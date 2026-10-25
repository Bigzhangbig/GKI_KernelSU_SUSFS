import os
import subprocess
import logging
import re
import hashlib
import json
import shlex
import sys
import zipfile
from pathlib import Path
from typing import Optional, Callable
from dataclasses import asdict, dataclass, field

from config import BuildConfig, SUSFS_REPO_CONFIG, SUKISU_PATCH_REPO_CONFIG, ANYKERNEL_CONFIG
from release_target import resolve_latest_release

RELEASE_PATCH = Path(__file__).resolve().parent.parent / "patches/sukisu-builtin-release.patch"
COMMON_PATCH = Path(__file__).resolve().parent.parent / "patches/sukisu-common-uapi6.patch"
RELEASE_CONTRACT = Path(__file__).resolve().parents[3] / "tests/release_contract.py"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class BuildResult:
    success: bool
    config: BuildConfig
    message: str = ""
    artifacts: list = field(default_factory=list)
    build_time: Optional[float] = None


class ShellCommand:
    def __init__(self, cwd: Optional[str] = None, env: Optional[dict] = None):
        self.cwd = cwd
        self.env = env or os.environ.copy()

    def run(self, cmd: str, check: bool = True, capture_output: bool = False,
            shell: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        logger.info(f"执行命令: {cmd}")
        try:
            return subprocess.run(cmd, shell=shell, cwd=self.cwd, env=self.env,
                                capture_output=capture_output, text=True, timeout=timeout, check=check)
        except subprocess.CalledProcessError as e:
            logger.error(f"命令执行失败: {e.stderr or str(e)}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"命令执行超时: {cmd}")
            raise

    def run_with_callback(self, cmd: str, callback: Optional[Callable] = None) -> str:
        logger.info(f"执行命令: {cmd}")
        process = subprocess.Popen(cmd, shell=True, cwd=self.cwd, env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        output_lines = []
        for line in process.stdout:
            line = line.rstrip()
            output_lines.append(line)
            if callback:
                callback(line)
        process.wait()
        if process.returncode != 0:
            raise RuntimeError(f"命令执行失败")
        return "\n".join(output_lines)


class KernelBuilder:
    KERNEL_CONFIG_TEMPLATE = """
# === KernelSU Config ===
CONFIG_KSU=y
CONFIG_KPM=y
CONFIG_KSU_SUSFS_SUS_SU=n

# === TMPFS Config ===
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_POSIX_ACL=y

# === Network Config ===
CONFIG_IP_NF_TARGET_TTL=y
CONFIG_IP6_NF_TARGET_HL=y
CONFIG_IP6_NF_MATCH_HL=y

# === BBR Config ===
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BBR=y
CONFIG_NET_SCH_FQ=y
CONFIG_TCP_CONG_BIC=n
CONFIG_TCP_CONG_WESTWOOD=n
CONFIG_TCP_CONG_HTCP=n

# === SUSFS Config ===
CONFIG_KSU_SUSFS=y
CONFIG_KSU_SUSFS_SUS_MAP=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_TRY_UMOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
"""


    def __init__(self, config: BuildConfig, workspace: str):
        self.config = config
        self.workspace = Path(workspace).resolve()
        self.shell = ShellCommand(cwd=str(self.workspace))
        self.env = os.environ.copy()
        self.work_dir = self.workspace / config.config_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.susfs_dir = self.workspace / "susfs4ksu"
        self.sukisu_patch_dir = self.workspace / "SukiSU_patch"
        self.anykernel_dir = self.workspace / "AnyKernel3"
        self._release_verified = False
        self._setup_env()


    def _setup_env(self):
        self.env["CONFIG"] = self.config.config_name
        self.env["CCACHE_COMPILERCHECK"] = "%compiler% -dumpmachine; %compiler% -dumpversion"
        self.env["CCACHE_NOHASHDIR"] = "true"
        self.env["CCACHE_HARDLINK"] = "true"
        self.shell.env = self.env


    def _run_cmd(self, cmd: str, **kwargs) -> subprocess.CompletedProcess:
        return self.shell.run(cmd, **kwargs)


    def _chdir(self, path: Path):
        os.chdir(path)
        self.shell.cwd = str(path)


    def _assert_git_head(self, repo_dir: Path, expected: str):
        result = self._run_cmd(f"git -C {shlex.quote(str(repo_dir))} rev-parse HEAD", capture_output=True)
        if result.stdout.strip() != expected:
            raise RuntimeError(f"Pinned repository HEAD mismatch: {repo_dir.name}")


    def _assert_git_clean(self, repo_dir: Path, include_ignored: bool = False):
        if not (repo_dir / ".git").exists():
            raise RuntimeError(f"Source input is not a Git checkout: {repo_dir}")
        ignored_flag = " --ignored" if include_ignored else ""
        result = self._run_cmd(
            f"git -C {shlex.quote(str(repo_dir))} status --porcelain --untracked-files=all{ignored_flag}",
            capture_output=True)
        if result.stdout.strip():
            raise RuntimeError(f"Source input must be clean; dirty, untracked or ignored files in {repo_dir}")

    def _verify_latest_release(self):
        if not self._release_verified:
            if resolve_latest_release() != self.config.target:
                raise ValueError("Latest Release does not match the audited build target")
            self._release_verified = True

    def clone_repositories(self):
        self._verify_latest_release()
        repositories = [
            ("SUSFS", self.susfs_dir, SUSFS_REPO_CONFIG["repo_url"], self.config.kernel_branch, self.config.target.susfs_commit),
            ("SukiSU Patch", self.sukisu_patch_dir, SUKISU_PATCH_REPO_CONFIG["repo_url"], None, self.config.target.patch_commit),
            ("AnyKernel3", self.anykernel_dir, ANYKERNEL_CONFIG["repo_url"], ANYKERNEL_CONFIG["branch"], self.config.target.anykernel_commit),
        ]
        # Check all reused inputs before changing any dependency checkout.
        for _, repo_dir, _, _, _ in repositories:
            if repo_dir.exists():
                self._assert_git_clean(repo_dir, include_ignored=True)
        for name, repo_dir, url, branch, commit in repositories:
            if not repo_dir.exists():
                branch_arg = "-b " + shlex.quote(branch) if branch else ""
                self._run_cmd(f"git clone {branch_arg} {shlex.quote(url)} {shlex.quote(str(repo_dir))}", check=True)
                if not repo_dir.is_dir():
                    raise RuntimeError(f"{name} clone did not create {repo_dir}")
                self._assert_git_clean(repo_dir, include_ignored=True)
            if not (repo_dir / ".git").exists():
                raise RuntimeError(f"{name} is not a Git checkout: {repo_dir}")
            self._chdir(repo_dir)
            self._run_cmd("git fetch origin")
            self._run_cmd(f"git checkout --detach {commit}")
            self._assert_git_head(repo_dir, commit)
            self._chdir(self.workspace)

    def setup_repo_tool(self):
        logger.info("=== 安装 repo 工具 ===")
        repo_dir = self.workspace / "git-repo"
        repo_dir.mkdir(exist_ok=True)
        repo_path = repo_dir / "repo"
        if not repo_path.exists():
            curl_flags = "-fLSs"
            self._run_cmd(f"curl {curl_flags} https://storage.googleapis.com/git-repo-downloads/repo > {repo_path}", check=True)
            self._run_cmd(f"chmod a+rx {repo_path}", check=True)
        if repo_path.stat().st_size == 0:
            raise RuntimeError("repo tool download is empty")
        self.env["REPO"] = str(repo_path)
        self.shell.env = self.env


    def init_and_sync_kernel(self):
        logger.info("=== 初始化和同步内核源代码 ===")
        for source in (self.work_dir / "common", self.work_dir / ".repo/manifests"):
            if source.exists():
                self._assert_git_clean(source)
        self._chdir(self.work_dir)
        if (self.work_dir / ".repo/project.list").is_file():
            self._run_cmd("$REPO forall -e -c 'repo_changes=$(git status --porcelain --untracked-files=all) && test -z \"$repo_changes\"'")
        formatted_branch = self.config.formatted_branch

        self._run_cmd(f"$REPO init --depth=1 -u https://android.googlesource.com/kernel/manifest "
                     f"-b common-{formatted_branch} --repo-rev=v2.16", check=True)

        remote_result = subprocess.run(
            ["git", "ls-remote", "https://android.googlesource.com/kernel/common", formatted_branch],
            capture_output=True, text=True, check=True)
        remote = remote_result.stdout.strip()
        if not remote:
            raise RuntimeError(f"GKI branch is missing: {formatted_branch}")
        if "deprecated" in remote:
            manifest_path = self.work_dir / ".repo/manifests/default.xml"
            with open(manifest_path, "r") as f:
                content = f.read()
            content = content.replace(f'"{formatted_branch}"', f'"deprecated/{formatted_branch}"')
            with open(manifest_path, "w") as f:
                f.write(content)

        self.env["REMOTE_BRANCH"] = remote
        logger.info("同步内核源代码...")
        self._run_cmd("$REPO --trace sync -c -j$(nproc --all) --no-tags --fail-fast", check=True)

        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            raise RuntimeError("repo sync 失败，common 目录不存在")
        self._assert_git_clean(common_dir)
        self._run_cmd(f"git -C {shlex.quote(str(common_dir))} checkout --detach {self.config.target.common_commit}")
        self._assert_git_head(common_dir, self.config.target.common_commit)
        resolved_manifest = self.work_dir / f"{self.config.target.name}-resolved-manifest.xml"
        self._run_cmd(f"$REPO manifest -r -o {shlex.quote(str(resolved_manifest))}")
        if not resolved_manifest.is_file() or resolved_manifest.stat().st_size == 0:
            raise RuntimeError("Resolved GKI manifest was not produced")
        logger.info("=== 内核源代码同步完成 ===")


    def add_kernelsu(self):
        ksu_dir = self.work_dir / "KernelSU"
        for source in (ksu_dir, self.work_dir / "common"):
            if source.exists():
                self._assert_git_clean(source)
        self._chdir(self.work_dir)
        commit = self.config.target.kernelsu_commit
        setup_url = f"https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/{commit}/kernel/setup.sh"
        setup_file = self.work_dir / "sukisu-setup.sh"
        self._run_cmd(f"curl -fLSs {shlex.quote(setup_url)} -o {shlex.quote(str(setup_file))}")
        self._run_cmd(f"bash {shlex.quote(str(setup_file))} {commit}")
        ksu_dir = self.work_dir / "KernelSU"
        if not ksu_dir.is_dir():
            raise RuntimeError("KernelSU setup did not create the pinned source tree")
        self._assert_git_clean(ksu_dir)
        self._chdir(ksu_dir)
        self._run_cmd(f"git checkout {commit}")
        self._assert_git_head(ksu_dir, commit)
        self._chdir(self.work_dir)

    @property
    def _pinned_patch(self):
        return RELEASE_PATCH

    @property
    def _pinned_contract(self):
        return RELEASE_CONTRACT

    def apply_pinned_patch(self):
        ksu_dir = self.work_dir / "KernelSU"
        header = ksu_dir / "kernel/include/uapi/supercall.h"
        if not self._pinned_patch.is_file():
            raise RuntimeError(f"Required builtin patch is missing: {self._pinned_patch}")
        if not header.is_file() or not re.search(rf'DECLARE\(__u32, KERNEL_SU_UAPI_VERSION, {self.config.target.uapi}\)', header.read_text()):
            raise RuntimeError("Pinned KernelSU source is not the expected native UAPI baseline")
        self._chdir(ksu_dir)
        patch = shlex.quote(str(self._pinned_patch))
        self._run_cmd(f"git apply --check {patch}")
        self._run_cmd(f"git apply {patch}")
        makefile = ksu_dir / "kernel/Makefile"
        old_line = "KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)"
        content = makefile.read_text()
        if content.count(old_line) != 1:
            raise RuntimeError("Pinned KernelSU Makefile version formula changed")
        content = content.replace(old_line, f"KSU_VERSION     := {self.config.target.version}")
        tag_line = "VERSION_TAG     := $(or $(KSU_GITHUB_VER),$(git_latest_tag),4.2.1)"
        full_line = "KSU_VERSION_FULL := $(if $(call git_short_sha),v$(VERSION_TAG)-$(call git_short_sha)@$(call git_branch),v$(VERSION_TAG)-$(REPO_NAME)-unknown@unknown)"
        if content.count(tag_line) != 1 or content.count(full_line) != 1:
            raise RuntimeError("Pinned release Makefile version tag formula changed")
        content = content.replace(tag_line, f"VERSION_TAG     := {self.config.target.backend_tag.removeprefix('v')}")
        content = content.replace(full_line, f"KSU_VERSION_FULL := {self.config.target.full_version}")
        # Disable the otherwise eagerly evaluated releases/latest request, too.
        content, count = re.subn(r"(?m)^KSU_GITHUB_VER\s*:= \$\(shell .*?/releases/latest.*$",
                                 f"KSU_GITHUB_VER   := {self.config.target.backend_tag.removeprefix('v')}", content)
        if count != 1:
            raise RuntimeError("Pinned release Makefile release lookup changed")
        makefile.write_text(content)
        self._chdir(self.work_dir)


    def test_pinned_contract(self):
        if not self._pinned_contract.is_file():
            raise RuntimeError(f"Required builtin contract test is missing: {self._pinned_contract}")
        self._run_cmd(f"{shlex.quote(sys.executable)} {shlex.quote(str(self._pinned_contract))} "
                      f"--source {shlex.quote(str(self.work_dir / 'KernelSU'))} --host-header")


    def apply_susfs_patches(self):
        logger.info("=== 应用 SUSFS 补丁 ===")
        self._chdir(self.work_dir)
        common_dir = self.work_dir / "common"
        susfs_patch = self.susfs_dir / "kernel_patches" / self.config.get_susfs_patch_filename()
        if not susfs_patch.is_file():
            raise RuntimeError(f"Required SUSFS patch is missing: {susfs_patch}")
        if susfs_patch.exists():
            self._run_cmd(f"cp {susfs_patch} {common_dir}/", check=True)
        for src, dst in [
            (self.susfs_dir / "kernel_patches/fs", common_dir / "fs/"),
            (self.susfs_dir / "kernel_patches/include/linux", common_dir / "include/linux/"),
        ]:
            if not src.is_dir():
                raise RuntimeError(f"Required SUSFS source is missing: {src}")
            if src.exists():
                self._run_cmd(f"cp -r {src}/* {dst}", check=True)
        if susfs_patch.exists():
            patch_file = common_dir / self.config.get_susfs_patch_filename()
            if patch_file.exists():
                self._chdir(common_dir)
                self._run_cmd(f"patch -p1 --fuzz=3 < {patch_file}", check=True)
                self._chdir(self.work_dir)


    def apply_sukisu_patches(self):
        logger.info("=== 应用 SukiSU 补丁 ===")
        self._chdir(self.work_dir / "common")
        hooks_patch = self.sukisu_patch_dir / "69_hide_stuff.patch"
        if not hooks_patch.is_file():
            raise RuntimeError(f"Required SukiSU hooks patch is missing: {hooks_patch}")
        if hooks_patch.exists():
            self._run_cmd(f"cp {hooks_patch} . && patch -p1 -F 3 < 69_hide_stuff.patch", check=True)
        self.apply_common_compatibility_patch()

    def apply_common_compatibility_patch(self):
        if not COMMON_PATCH.is_file():
            raise RuntimeError(f"Required common compatibility patch is missing: {COMMON_PATCH}")
        self._chdir(self.work_dir / "common")
        patch = shlex.quote(str(COMMON_PATCH))
        self._run_cmd(f"git apply --check {patch}")
        self._run_cmd(f"git apply {patch}")


    def apply_task_mmu_fixes(self):
        logger.info("=== 应用 task_mmu.c 修复 ===")
        self._chdir(self.work_dir / "common")
        task_mmu = Path("fs/proc/task_mmu.c")
        if not task_mmu.exists():
            return

        # 读取文件内容
        with open(task_mmu, "r") as f:
            content = f.read()

        # ===== 修复 VMA_PAD_START 未定义 =====
        if "VMA_PAD_START" in content and "#define VMA_PAD_START" not in content:
            logger.info("检测到 VMA_PAD_START 未定义，正在添加宏定义...")
            # 在 #include <linux/pkeys.h> 之后添加定义
            lines = content.split('\n')
            new_lines = []
            inserted = False
            for line in lines:
                new_lines.append(line)
                if not inserted and line.strip().startswith('#include <linux/pkeys.h>'):
                    new_lines.append('')
                    new_lines.append('// VMA_PAD_START fix for SUSFS')
                    new_lines.append('#ifndef VMA_PAD_START')
                    new_lines.append('#define VMA_PAD_START(vma) ((vma)->vm_end)')
                    new_lines.append('#endif')
                    inserted = True
            if inserted:
                content = '\n'.join(new_lines)
                logger.info("已添加 VMA_PAD_START 宏定义")

        # ===== 修复 dentry 未初始化（如果还存在） =====
        if "struct dentry *dentry;" in content:
            content = content.replace("struct dentry *dentry;", "struct dentry *dentry = NULL;")
            logger.info("已修复 dentry 未初始化问题")

        # ===== 写入修改 =====
        with open(task_mmu, "w") as f:
            f.write(content)

        # ===== 原有的修复逻辑 =====
        fb = f"{self.config.android_version}-{self.config.kernel_version}"
        
        if fb == "android15-6.6" and "unsigned int nr_subpages" not in content:
            self._fix_base_c_header()
        elif fb == "android14-6.1" and "if (!vma_pages(vma))" not in content:
            self._fix_base_c_header()
            # 重新读取内容，因为可能已被修改
            with open(task_mmu, "r") as f:
                content = f.read()
            if "goto show_pad;" in content:
                content = content.replace("goto show_pad;", "return 0;")
                with open(task_mmu, "w") as f:
                    f.write(content)
        elif fb in ["android12-5.10", "android13-5.10", "android13-5.15"] and "if (!vma_pages(vma))" not in content:
            with open(task_mmu, "r") as f:
                content = f.read()
            if "goto show_pad;" in content:
                content = content.replace("goto show_pad;", "return 0;")
                with open(task_mmu, "w") as f:
                    f.write(content)


    def _fix_base_c_header(self):
        base_c = self.work_dir / "common/fs/proc/base.c"
        if not base_c.exists():
            return
        with open(base_c, "r") as f:
            content = f.read()
        if "#include <linux/dma-buf.h>" not in content:
            content = content.replace("#include <linux/cpufreq_times.h>",
                                    "#include <linux/cpufreq_times.h>\n#include <linux/dma-buf.h>")
            with open(base_c, "w") as f:
                f.write(content)


    def configure_kernel(self):
        logger.info("=== 配置内核 ===")
        self._chdir(self.work_dir)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        if not config_file.exists():
            raise RuntimeError(f"Required kernel config is missing: {config_file}")

        with open(config_file, "a") as f:
            f.write(self.KERNEL_CONFIG_TEMPLATE)
            f.write("CONFIG_KPM=n\nCONFIG_KSU_DEBUG=n\n")
            f.write("CONFIG_KSU_SUSFS_SUS_PATH=y\n")

        build_config = self.work_dir / "common/build.config.gki"
        if build_config.exists():
            with open(build_config, "r") as f:
                content = f.read()
            content = content.replace("check_defconfig", "")
            with open(build_config, "w") as f:
                f.write(content)


    def verify_pinned_sources(self):
        if not self._pinned_contract.is_file():
            raise RuntimeError(f"Required release source contract is missing: {self._pinned_contract}")
        self._run_cmd(f"{shlex.quote(sys.executable)} {shlex.quote(str(self._pinned_contract))} "
                      f"--source {shlex.quote(str(self.work_dir / 'KernelSU'))} "
                      f"--common {shlex.quote(str(self.work_dir / 'common'))}")


    def write_pinned_manifest(self):
        self._assert_git_head(self.work_dir / "common", self.config.target.common_commit)
        self._assert_git_head(self.work_dir / "KernelSU", self.config.target.kernelsu_commit)
        self._assert_git_head(self.susfs_dir, self.config.target.susfs_commit)
        self._assert_git_head(self.sukisu_patch_dir, self.config.target.patch_commit)
        self._assert_git_head(self.anykernel_dir, self.config.target.anykernel_commit)
        def git_head(path: Path) -> str:
            return self._run_cmd(f"git -C {shlex.quote(str(path))} rev-parse HEAD", capture_output=True).stdout.strip()

        makefile = self.work_dir / "KernelSU/kernel/Makefile"
        setup_file = self.work_dir / "sukisu-setup.sh"
        resolved_manifest = self.work_dir / f"{self.config.target.name}-resolved-manifest.xml"
        manifest = {
            "target": (f"{self.config.target.archive_name.removesuffix('-AnyKernel3.zip')} / KernelSU {self.config.target.version} / "
                       f"UAPI {self.config.target.uapi} / SUSFS {self.config.target.susfs_version}"),
            "common_commit": self.config.target.common_commit,
            "kernelsu_commit": self.config.target.kernelsu_commit,
            "susfs_commit": self.config.target.susfs_commit,
            "patch_commit": self.config.target.patch_commit,
            "anykernel_commit": self.config.target.anykernel_commit,
            "avc_backport_commit": self.config.target.avc_backport_commit,
            "release_tag": self.config.target.tag,
            "release_commit": self.config.target.release_commit,
            "manager_version": self.config.target.manager_version,
            "backend_tag": self.config.target.backend_tag,
            "backend_version": self.config.target.version,
            "backend_source_commit": self.config.target.kernelsu_commit,
            "source_fingerprint": self.config.target.source_fingerprint,
            "builtin_compatibility_commit": self.config.target.kernelsu_commit,
            "full_version": self.config.target.full_version,
            "official_manager_apk_sha256": self.config.target.apk_sha256,
            "official_manager_certificate_sha256": self.config.target.manager_certificate_sha256,
            "manifest_commit": git_head(self.work_dir / ".repo/manifests"),
            "resolved_toolchain_manifest_sha256": hashlib.sha256(resolved_manifest.read_bytes()).hexdigest(),
            "source_patch_sha256": hashlib.sha256(self._pinned_patch.read_bytes()).hexdigest(),
            "common_compatibility_patch_sha256": hashlib.sha256(COMMON_PATCH.read_bytes()).hexdigest(),
            "source_contract_sha256": hashlib.sha256(self._pinned_contract.read_bytes()).hexdigest(),
            "setup_script_sha256": hashlib.sha256(setup_file.read_bytes()).hexdigest(),
            "kernel_makefile_sha256": hashlib.sha256(makefile.read_bytes()).hexdigest(),
            "kernel_makefile_version_change": f"replace upstream LOCAL_COUNT formula with KSU_VERSION := {self.config.target.version}",
            "build_config": self.config.to_dict(),
        }
        (self.work_dir / f"{self.config.target.name}-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (self.work_dir / "release-target.json").write_text(json.dumps(asdict(self.config.target), indent=2) + "\n")


    def verify_pinned_outputs(self) -> Path:
        dist = self.work_dir / "out/android12-5.10/dist"
        image = dist / "Image"
        for output in (image, dist / "vmlinux", dist / "System.map"):
            if not output.is_file() or output.stat().st_size == 0:
                raise RuntimeError(f"{self.config.target.name} build did not produce {output.name}")
        generated_config = self.work_dir / "out/android12-5.10/common/.config"
        if not generated_config.is_file():
            raise RuntimeError(f"{self.config.target.name} generated common/.config is missing")
        config_lines = generated_config.read_text().splitlines()
        if not all(f"{key}=y" in config_lines for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS")):
            raise RuntimeError(f"{self.config.target.name} generated .config does not enable KernelSU and SUSFS")
        if any(f"{key}=y" in config_lines for key in ("CONFIG_KSU_DEBUG", "CONFIG_KPM")):
            raise RuntimeError(f"{self.config.target.name} generated .config unexpectedly enables KSU_DEBUG or KPM")
        if self.config.target.avc_backport_commit and "CONFIG_KPROBES=y" not in config_lines:
            raise RuntimeError("CONFIG_KPROBES is required for the AVC backport")
        return image


    def configure_kernel_name(self):
        logger.info("=== 配置内核名称 ===")
        self._chdir(self.work_dir)
        setlocalversion = self.work_dir / "common/scripts/setlocalversion"
        if setlocalversion.exists():
            content = setlocalversion.read_text().replace("-dirty", "")
            setlocalversion.write_text(content)

        import datetime
        current_time = datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        mkcompile_h = self.work_dir / "common/scripts/mkcompile_h"
        if mkcompile_h.exists():
            with open(mkcompile_h, "r") as f:
                content = f.read()
            content = content.replace('UTS_VERSION="$(echo $UTS_VERSION $CONFIG_FLAGS $TIMESTAMP | cut -b -$UTS_LEN)"',
                                    f'UTS_VERSION="#1 SMP PREEMPT {current_time}"')
            with open(mkcompile_h, "w") as f:
                f.write(content)

    def show_kernel_config(self):
        logger.info("=== 显示内核配置列表 ===")
        self._chdir(self.work_dir)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        
        if not config_file.exists():
            logger.warning(f"配置文件不存在: {config_file}")
            return
        
        with open(config_file, "r") as f:
            lines = f.readlines()
        
        config_lines = [line.strip() for line in lines if line.strip().startswith("CONFIG_")]
        
        key_configs = {
            "CONFIG_KSU": "KernelSU",
            "CONFIG_KPM": "KPM",
            "CONFIG_KSU_SUSFS": "SUSFS",
            "CONFIG_BBG": "Baseband-guard",
            "CONFIG_BBR": "BBR",
            "CONFIG_ZRAM": "ZRAM",
        }
        
        logger.info("关键配置状态:")
        for prefix, name in key_configs.items():
            found = [c for c in config_lines if c.startswith(prefix)]
            if found:
                status = "已启用"
            else:
                status = "未配置"
            logger.info(f"  [{status}] {name}")
            if found:
                for f in sorted(found):
                    logger.info(f"      -> {f}")
        
        logger.info("-" * 60)

    def build_kernel(self) -> bool:
        logger.info("=== 开始编译内核 ===")
        self._chdir(self.work_dir)

        build_config = self.work_dir / "common/build.config.gki.aarch64"
        if build_config.exists():
            with open(build_config, "r") as f:
                content = f.read()
            content = content.replace("BUILD_SYSTEM_DLKM=1", "BUILD_SYSTEM_DLKM=0")
            lines = [l for l in content.split('\n') if 'MODULES_ORDER=android/gki_aarch64_modules' not in l and 'KMI_SYMBOL_LIST_STRICT_MODE' not in l]
            with open(build_config, "w") as f:
                f.write('\n'.join(lines))

        try:
            if (self.work_dir / "build/build.sh").exists():
                logger.info("使用旧版构建方式...")
                result = self._run_cmd("LTO=thin BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh CC=\"/usr/bin/ccache clang\"", check=True)
            else:
                raise RuntimeError("Verified GKI build/build.sh is missing")

            if result.returncode == 0:
                logger.info("=== 内核编译成功 ===")
                return True
            logger.error(f"内核编译失败: {result.stderr if result.stderr else 'Unknown error'}")
            return False
        except Exception as e:
            logger.error(f"编译过程出错: {e}")
            return False


    def create_anykernel_zips(self) -> list:
        image = self.work_dir / "Image"
        if not image.is_file() or not image.stat().st_size:
            raise RuntimeError("AnyKernel3 packaging requires the current nonempty Image")
        archive = self.work_dir / self.config.target.archive_name
        if archive.exists():
            raise RuntimeError("Release packaging requires a fresh ZIP path")
        self._run_cmd(f"cp {shlex.quote(str(image))} {shlex.quote(str(self.anykernel_dir / 'Image'))}")
        self._chdir(self.anykernel_dir)
        self._run_cmd(f"zip -r {shlex.quote(str(archive))} ./*")
        self._run_cmd(f"rm {shlex.quote(str(self.anykernel_dir / 'Image'))}")
        if not archive.is_file() or not archive.stat().st_size:
            raise RuntimeError("AnyKernel3 packaging did not produce a ZIP")
        with zipfile.ZipFile(archive) as package:
            if package.testzip() is not None or package.namelist().count("Image") != 1:
                raise RuntimeError("AnyKernel3 ZIP is corrupt or has no unique Image")
            if hashlib.sha256(package.read("Image")).digest() != hashlib.sha256(image.read_bytes()).digest():
                raise RuntimeError("AnyKernel3 ZIP Image differs from the current build")
        self._chdir(self.work_dir)
        return [str(archive)]

    def build(self) -> BuildResult:
        import time
        start_time = time.time()
        logger.info("=" * 50)
        logger.info(f"开始 GKI Kernel 构建 - {self.config.config_name}")
        logger.info("=" * 50)

        try:
            if (self.work_dir / "out").exists():
                raise RuntimeError(f"{self.config.target.name} target requires a fresh output directory")
            self._verify_latest_release()
            self.clone_repositories()
            self.setup_repo_tool()
            self.init_and_sync_kernel()
            self.add_kernelsu()
            self.apply_pinned_patch()
            self.test_pinned_contract()
            self.apply_susfs_patches()
            self.apply_sukisu_patches()
            self.apply_task_mmu_fixes()
            self.configure_kernel()
            self.verify_pinned_sources()
            self.configure_kernel_name()
            self.show_kernel_config()

            if not self.build_kernel():
                return BuildResult(success=False, config=self.config, message="内核编译失败", build_time=time.time() - start_time)

            artifacts = []
            image = self.verify_pinned_outputs()
            self._run_cmd(f"cp {shlex.quote(str(image))} {shlex.quote(str(self.work_dir / 'Image'))}")
            artifacts.extend(self.create_anykernel_zips())
            if not artifacts or any(not Path(artifact).is_file() for artifact in artifacts):
                raise RuntimeError(f"{self.config.target.name} AnyKernel3 artifact is missing")
            self.write_pinned_manifest()
            artifacts.append(str(self.work_dir / f"{self.config.target.name}-manifest.json"))
            artifacts.append(str(self.work_dir / "release-target.json"))

            build_time = time.time() - start_time
            logger.info(f"构建成功! 耗时: {build_time:.2f} 秒, 生成 {len(artifacts)} 个产物")
            return BuildResult(success=True, config=self.config, message="构建成功", artifacts=artifacts, build_time=build_time)
        except Exception as e:
            logger.error(f"构建过程出错: {e}")
            return BuildResult(success=False, config=self.config, message=str(e), build_time=time.time() - start_time)
