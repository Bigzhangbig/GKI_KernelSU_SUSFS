import os
import subprocess
import logging
import re
import hashlib
import json
import shlex
import sys
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field

from config import (BuildConfig, KSU_REPO_CONFIG, SUSFS_REPO_CONFIG, SUKISU_PATCH_REPO_CONFIG,
                   ANYKERNEL_CONFIG, KERNEL_PATCHES_CONFIG, BBG_CONFIG, TOOLCHAIN_CONFIG,
                   LEGACY_FIXES, OP8E_PATCH_URL, KPM_PATCH_URL,
                   OFFICIAL_40971_5_KSU_COMMIT, OFFICIAL_40971_5_SUSFS_COMMIT,
                   OFFICIAL_40971_5_SUKISU_PATCH_COMMIT, OFFICIAL_40971_5_COMMON_COMMIT)

OFFICIAL_40971_5_PATCH = Path(__file__).resolve().parent.parent / "patches/sukisu-builtin-6c284e95-uapi5.patch"
OFFICIAL_40971_5_CONTRACT = Path(__file__).resolve().parents[3] / "tests/test_uapi5_contract.py"

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

    ZRAM_CONFIG_5_10 = "CONFIG_ZSMALLOC=y\nCONFIG_ZRAM=y\nCONFIG_MODULE_SIG=n\nCONFIG_CRYPTO_LZO=y\nCONFIG_ZRAM_DEF_COMP_LZ4KD=y\n"
    ZRAM_CONFIG_COMMON = "CONFIG_CRYPTO_LZ4HC=y\nCONFIG_CRYPTO_LZ4K=y\nCONFIG_CRYPTO_LZ4KD=y\nCONFIG_CRYPTO_842=y\nCONFIG_CRYPTO_LZ4K_OPLUS=y\nCONFIG_ZRAM_WRITEBACK=y\n"

    def __init__(self, config: BuildConfig, workspace: str):
        self.config = config
        self.workspace = Path(workspace)
        self.shell = ShellCommand(cwd=workspace)
        self.env = os.environ.copy()
        self.work_dir = self.workspace / config.config_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.susfs_dir = self.workspace / "susfs4ksu"
        self.sukisu_patch_dir = self.workspace / "SukiSU_patch"
        self.anykernel_dir = self.workspace / "AnyKernel3"
        self.kernel_patches_dir = self.workspace / "kernel_patches"
        self.toolchain_dir = self.workspace / "toolchain"
        self.mkbootimg_dir = self.workspace / "mkbootimg"
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

    def _apply_susfs_commit(self):
        if not self.config.susfs_commit or not self.susfs_dir.exists():
            return
        self._chdir(self.susfs_dir)
        if self.config.susfs_commit.startswith("HEAD~"):
            self._run_cmd("git fetch origin", check=False)
            self._run_cmd(f"git reset --hard {self.config.susfs_commit}", check=False)
        else:
            self._run_cmd("git fetch origin", check=self.config.official_40971_5)
            self._run_cmd(f"git checkout {self.config.susfs_commit}", check=self.config.official_40971_5)
        if self.config.official_40971_5:
            self._assert_git_head(self.susfs_dir, OFFICIAL_40971_5_SUSFS_COMMIT)
        self._chdir(self.workspace)

    def _assert_git_head(self, repo_dir: Path, expected: str):
        result = self._run_cmd(f"git -C {shlex.quote(str(repo_dir))} rev-parse HEAD", capture_output=True)
        if result.stdout.strip() != expected:
            raise RuntimeError(f"Pinned repository HEAD mismatch: {repo_dir.name}")

    def clone_repositories(self):
        logger.info("=== 开始克隆仓库 ===")
        for name, repo_dir, url, branch in [
            ("SUSFS", self.susfs_dir, SUSFS_REPO_CONFIG['repo_url'], self.config.kernel_branch),
            ("SukiSU Patch", self.sukisu_patch_dir, SUKISU_PATCH_REPO_CONFIG['repo_url'], None),
            ("AnyKernel3", self.anykernel_dir, ANYKERNEL_CONFIG['repo_url'], ANYKERNEL_CONFIG['branch']),
            ("Kernel Patches", self.kernel_patches_dir, KERNEL_PATCHES_CONFIG['repo_url'], None),
        ]:
            if not repo_dir.exists():
                if self.config.official_40971_5:
                    cmd = f"git clone {'-b ' + branch if branch else ''} {shlex.quote(url)} {shlex.quote(str(repo_dir))}"
                else:
                    cmd = f"git clone {url}"
                    if branch:
                        cmd += f" -b {branch}"
                logger.info(f"克隆 {name}...")
                self._run_cmd(cmd, check=self.config.official_40971_5)
                if self.config.official_40971_5 and not repo_dir.is_dir():
                    raise RuntimeError(f"{name} clone did not create {repo_dir}")
            else:
                logger.info(f"{name} 已存在，跳过")
            if self.config.official_40971_5 and not (repo_dir / ".git").exists():
                raise RuntimeError(f"{name} is not a Git checkout: {repo_dir}")
        self._apply_susfs_commit()
        if self.config.official_40971_5:
            self._chdir(self.sukisu_patch_dir)
            self._run_cmd("git fetch origin")
            self._run_cmd(f"git checkout {OFFICIAL_40971_5_SUKISU_PATCH_COMMIT}")
            self._assert_git_head(self.sukisu_patch_dir, OFFICIAL_40971_5_SUKISU_PATCH_COMMIT)
            self._chdir(self.workspace)
        logger.info("=== 仓库克隆完成 ===")

    def clone_toolchain(self):
        logger.info("=== 克隆工具链 ===")
        if not self.toolchain_dir.exists():
            self._run_cmd(f"git clone {TOOLCHAIN_CONFIG['aosp_mirror']}/kernel/prebuilts/build-tools "
                         f"-b {TOOLCHAIN_CONFIG['build_tools_branch']} --depth 1 {self.toolchain_dir}", check=self.config.official_40971_5)
        if not self.mkbootimg_dir.exists():
            self._run_cmd(f"git clone {TOOLCHAIN_CONFIG['aosp_mirror']}/platform/system/tools/mkbootimg "
                         f"-b {TOOLCHAIN_CONFIG['mkbootimg_branch']} --depth 1 {self.mkbootimg_dir}", check=self.config.official_40971_5)
        self.env["AVBTOOL"] = str(self.toolchain_dir / "linux-x86/bin/avbtool")
        self.env["MKBOOTIMG"] = str(self.mkbootimg_dir / "mkbootimg.py")
        self.env["UNPACK_BOOTIMG"] = str(self.mkbootimg_dir / "unpack_bootimg.py")
        if "BOOT_SIGN_KEY_PATH" in os.environ:
            self.env["BOOT_SIGN_KEY_PATH"] = os.environ["BOOT_SIGN_KEY_PATH"]
        self.shell.env = self.env
        logger.info("=== 工具链准备完成 ===")

    def setup_repo_tool(self):
        logger.info("=== 安装 repo 工具 ===")
        repo_dir = self.workspace / "git-repo"
        repo_dir.mkdir(exist_ok=True)
        repo_path = repo_dir / "repo"
        if not repo_path.exists():
            curl_flags = "-fLSs" if self.config.official_40971_5 else ""
            self._run_cmd(f"curl {curl_flags} https://storage.googleapis.com/git-repo-downloads/repo > {repo_path}", check=self.config.official_40971_5)
            self._run_cmd(f"chmod a+rx {repo_path}", check=self.config.official_40971_5)
        if self.config.official_40971_5 and repo_path.stat().st_size == 0:
            raise RuntimeError("repo tool download is empty")
        self.env["REPO"] = str(repo_path)
        self.shell.env = self.env

    def init_and_sync_kernel(self):
        logger.info("=== 初始化和同步内核源代码 ===")
        self._chdir(self.work_dir)
        formatted_branch = self.config.formatted_branch

        self._run_cmd(f"$REPO init --depth=1 -u https://android.googlesource.com/kernel/manifest "
                     f"-b common-{formatted_branch} --repo-rev=v2.16", check=self.config.official_40971_5)

        remote_result = subprocess.run(
            ["git", "ls-remote", "https://android.googlesource.com/kernel/common", formatted_branch],
            capture_output=True, text=True, check=self.config.official_40971_5)
        remote = remote_result.stdout.strip()
        if self.config.official_40971_5 and not remote:
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
        self._run_cmd("$REPO --trace sync -c -j$(nproc --all) --no-tags --fail-fast", check=self.config.official_40971_5)

        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            raise RuntimeError("repo sync 失败，common 目录不存在")
        if self.config.official_40971_5:
            self._run_cmd(f"git -C {shlex.quote(str(common_dir))} checkout --detach {OFFICIAL_40971_5_COMMON_COMMIT}")
            self._assert_git_head(common_dir, OFFICIAL_40971_5_COMMON_COMMIT)
            resolved_manifest = self.work_dir / "40971-5-resolved-manifest.xml"
            self._run_cmd(f"$REPO manifest -r -o {shlex.quote(str(resolved_manifest))}")
            if not resolved_manifest.is_file() or resolved_manifest.stat().st_size == 0:
                raise RuntimeError("Resolved GKI manifest was not produced")
        self._apply_legacy_fixes(remote)
        logger.info("=== 内核源代码同步完成 ===")

    def _apply_legacy_fixes(self, remote_branch: str = ""):
        av, kv = self.config.android_version, self.config.kernel_version
        sub = self.config.get_sub_level_int()
        is_deprecated = "deprecated" in remote_branch

        if is_deprecated and av == "android13" and kv == "5.15" and sub and sub < 123:
            common_dir = self.work_dir / "common"
            self._chdir(common_dir)
            self._run_cmd(f"curl -LSs {LEGACY_FIXES['android13-5.15-below-123']['url']} -o fix.patch && patch -p1 < fix.patch", check=False)
            self._chdir(self.work_dir)

        if av == "android12" and kv == "5.10" and sub and sub < 136:
            common_dir = self.work_dir / "common"
            self._chdir(common_dir)
            self._run_cmd(f"curl -LSs {LEGACY_FIXES['android12-5.10-below-136']['url']} | patch -p1", check=False)
            self._chdir(self.work_dir)

    def add_kernel_supatch(self):
        if not self.config.support_op8e:
            return
        logger.info("=== 添加 OnePlus 8E 支持补丁 ===")
        drivers_dir = self.work_dir / "common/drivers"
        if not drivers_dir.exists():
            return
        self._chdir(drivers_dir)
        self._run_cmd(f"curl -LSs {OP8E_PATCH_URL} -o hmbird_patch.c", check=False)
        if (drivers_dir / "hmbird_patch.c").exists():
            with open(drivers_dir / "Makefile", "a") as f:
                f.write("obj-y += hmbird_patch.o\n")

    def add_kernelsu(self):
        logger.info("=== 添加 KernelSU ===")
        self._chdir(self.work_dir)
        setup_url = (f"https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/{self.config.kernelsu_commit}/kernel/setup.sh"
                    if self.config.kernelsu_commit else KSU_REPO_CONFIG["setup_script"])
        if self.config.official_40971_5:
            setup_file = self.work_dir / "sukisu-setup.sh"
            self._run_cmd(f"curl -fLSs {shlex.quote(setup_url)} -o {shlex.quote(str(setup_file))}")
            self._run_cmd(f"bash {shlex.quote(str(setup_file))} {OFFICIAL_40971_5_KSU_COMMIT}")
        else:
            self._run_cmd(f"curl -LSs {setup_url} | bash -s builtin", check=False)
        if self.config.kernelsu_commit:
            ksu_dir = self.work_dir / "KernelSU"
            if ksu_dir.exists():
                self._chdir(ksu_dir)
                self._run_cmd(f"git checkout {self.config.kernelsu_commit}", check=self.config.official_40971_5)
                if self.config.official_40971_5:
                    self._assert_git_head(ksu_dir, OFFICIAL_40971_5_KSU_COMMIT)
                self._chdir(self.work_dir)
            elif self.config.official_40971_5:
                raise RuntimeError("KernelSU setup did not create the pinned source tree")

    def apply_official_40971_5_patch(self):
        if not self.config.official_40971_5:
            return
        ksu_dir = self.work_dir / "KernelSU"
        header = ksu_dir / "kernel/include/uapi/supercall.h"
        if not OFFICIAL_40971_5_PATCH.is_file():
            raise RuntimeError(f"Required UAPI5 patch is missing: {OFFICIAL_40971_5_PATCH}")
        if not header.is_file() or not re.search(r'DECLARE\(__u32, KERNEL_SU_UAPI_VERSION, 2\)', header.read_text()):
            raise RuntimeError("Pinned KernelSU source is not the expected UAPI2 baseline")
        self._chdir(ksu_dir)
        patch = shlex.quote(str(OFFICIAL_40971_5_PATCH))
        self._run_cmd(f"git apply --check {patch}")
        self._run_cmd(f"git apply {patch}")
        makefile = ksu_dir / "kernel/Makefile"
        old_line = "KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)"
        content = makefile.read_text()
        if content.count(old_line) != 1:
            raise RuntimeError("Pinned KernelSU Makefile version formula changed")
        makefile.write_text(content.replace(old_line, "KSU_VERSION     := 40971"))
        self._chdir(self.work_dir)

    def test_official_40971_5_contract(self):
        if not self.config.official_40971_5:
            return
        if not OFFICIAL_40971_5_CONTRACT.is_file():
            raise RuntimeError(f"Required UAPI5 contract test is missing: {OFFICIAL_40971_5_CONTRACT}")
        self._run_cmd(f"{shlex.quote(sys.executable)} {shlex.quote(str(OFFICIAL_40971_5_CONTRACT))} "
                      f"--source {shlex.quote(str(self.work_dir / 'KernelSU'))} --host-header")

    def add_bbg(self):
        if not self.config.use_bbg:
            return
        logger.info("=== 添加 Baseband-guard ===")
        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            return
        self._chdir(common_dir)
        self._run_cmd(f"wget -O- {BBG_CONFIG['setup_script']} | bash", check=False)
        config_file = common_dir / "arch/arm64/configs/gki_defconfig"
        if config_file.exists():
            with open(config_file, "a") as f:
                f.write("CONFIG_BBG=y\n")
        kconfig_file = common_dir / "security/Kconfig"
        if kconfig_file.exists():
            with open(kconfig_file, "r") as f:
                content = f.read()
            content = re.sub(r'(config LSM.*?)(default .*)(\n.*?help)',
                           lambda m: m.group(1) + ('lockdown,baseband_guard' if 'lockdown' in m.group(2) and 'baseband_guard' not in m.group(2) else m.group(2)) + m.group(3),
                           content, flags=re.DOTALL)
            with open(kconfig_file, "w") as f:
                f.write(content)

    def apply_susfs_patches(self):
        logger.info("=== 应用 SUSFS 补丁 ===")
        self._chdir(self.work_dir)
        common_dir = self.work_dir / "common"
        susfs_patch = self.susfs_dir / "kernel_patches" / self.config.get_susfs_patch_filename()
        if self.config.official_40971_5 and not susfs_patch.is_file():
            raise RuntimeError(f"Required SUSFS patch is missing: {susfs_patch}")
        if susfs_patch.exists():
            self._run_cmd(f"cp {susfs_patch} {common_dir}/", check=self.config.official_40971_5)
        for src, dst in [
            (self.susfs_dir / "kernel_patches/fs", common_dir / "fs/"),
            (self.susfs_dir / "kernel_patches/include/linux", common_dir / "include/linux/"),
        ]:
            if self.config.official_40971_5 and not src.is_dir():
                raise RuntimeError(f"Required SUSFS source is missing: {src}")
            if src.exists():
                self._run_cmd(f"cp -r {src}/* {dst}", check=self.config.official_40971_5)
        if susfs_patch.exists():
            patch_file = common_dir / self.config.get_susfs_patch_filename()
            if patch_file.exists():
                self._chdir(common_dir)
                self._run_cmd(f"patch -p1 --fuzz=3 < {patch_file}", check=self.config.official_40971_5)
                self._chdir(self.work_dir)

    def apply_sukisu_patches(self):
        logger.info("=== 应用 SukiSU 补丁 ===")
        self._chdir(self.work_dir / "common")
        hooks_patch = self.sukisu_patch_dir / "69_hide_stuff.patch"
        if self.config.official_40971_5 and not hooks_patch.is_file():
            raise RuntimeError(f"Required SukiSU hooks patch is missing: {hooks_patch}")
        if hooks_patch.exists():
            self._run_cmd(f"cp {hooks_patch} . && patch -p1 -F 3 < 69_hide_stuff.patch", check=self.config.official_40971_5)

    def apply_zram_patches(self):
        if not self.config.use_zram:
            return
        logger.info("=== 应用 ZRAM (LZ4KD) 补丁 ===")
        self._chdir(self.work_dir / "common")
        for src in [
            (self.sukisu_patch_dir / "other/zram/lz4k/include/linux", "include/linux/"),
            (self.sukisu_patch_dir / "other/zram/lz4k/lib", "lib/"),
            (self.sukisu_patch_dir / "other/zram/lz4k/crypto", "crypto/"),
            (self.sukisu_patch_dir / "other/zram/lz4k_oplus", "lib/"),
        ]:
            if src[0].exists():
                self._run_cmd(f"cp -r {src[0]}/* {src[1]}", check=False)
        zram_patch_dir = self.sukisu_patch_dir / f"other/zram/zram_patch/{self.config.kernel_version}"
        for patch in ["lz4kd.patch", "lz4k_oplus.patch"]:
            p = zram_patch_dir / patch
            if p.exists():
                self._run_cmd(f"patch -p1 -F 3 < {p}", check=False)

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
            if self.config.official_40971_5:
                raise RuntimeError(f"Required kernel config is missing: {config_file}")
            logger.warning(f"配置文件不存在: {config_file}")
            return

        with open(config_file, "a") as f:
            f.write(self.KERNEL_CONFIG_TEMPLATE)
            if self.config.official_40971_5 and not self.config.use_kpm:
                f.write("CONFIG_KPM=n\n")
            if self.config.kernel_version != "6.6":
                f.write("CONFIG_KSU_SUSFS_SUS_PATH=y\n")
            else:
                f.write("CONFIG_KSU_SUSFS_SUS_PATH=n\n")

        if self.config.use_zram:
            self._configure_zram()
            self._configure_bazel()

        if self.config.set_default_bbr:
            with open(config_file, "a") as f:
                f.write("CONFIG_DEFAULT_BBR=y\n")

        build_config = self.work_dir / "common/build.config.gki"
        if build_config.exists():
            with open(build_config, "r") as f:
                content = f.read()
            content = content.replace("check_defconfig", "")
            with open(build_config, "w") as f:
                f.write(content)

    def verify_official_40971_5_sources(self):
        if not self.config.official_40971_5:
            return
        common = self.work_dir / "common"
        ksu = self.work_dir / "KernelSU/kernel"
        expected_text = {
            ksu / "include/uapi/supercall.h": [
                r"DECLARE\(__u32, KERNEL_SU_UAPI_VERSION, 5\)",
                r"DECLARE\(__u32, KSU_GET_INFO_FLAG_BUNDLED, \(1U << 4\)\)",
            ],
            ksu / "Makefile": [r"(?m)^KSU_VERSION\s*:= 40971$"],
            ksu / "supercall/dispatch.c": [
                r"case EVENT_SERVICES:\s*\{.*?services_started = true;.*?return 1;",
                r"\.cmd = KSU_IOCTL_GET_WRAPPER_FD,[^}]*\.allow_su_session = true",
                r"\.cmd = KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT,[^}]*\.allow_su_session = true",
                r"ksu_ioctl_handlers\[i\]\.allow_su_session && ksu_is_su_session_fd\(filp\)",
            ],
            ksu / "infra/file_wrapper.c": [
                r"old_cred = override_creds\(ksu_cred\);\s*wrapper_file = .*?;\s*revert_creds\(old_cred\);",
            ],
            ksu / "manager/apk_sign.c": [
                r'\{\s*0x35c,\s*"947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"\s*\}',
            ],
            ksu / "feature/sucompat.c": [
                r"int ksu_handle_execveat_sucompat\(.*?if \(!\(__ksu_is_allow_uid_for_current\(current_uid\(\)\.val\)\)\)\s*return -EINVAL;",
                r"if \(current_chrooted\(\)\).*?return -EINVAL;",
                r"if \(ret\) \{.*?return -EINVAL;.*?\}\s*return 0;",
                r"int ksu_handle_post_execveat_sucompat\(.*?if \(\*retval >= 0\) \{\s*\(void\)ksu_install_su_fd\(\);",
            ],
            common / "fs/exec.c": [
                r"bool is_su_session = false;",
                r"if \(likely\(susfs_is_current_proc_no_su\(\)\)\)\s*goto orig_flow;",
                r"if \(static_branch_likely\(&ksu_su_compat_enabled\)\)",
                r"is_su_session = !ksu_handle_execveat\(&fd, &filename, &argv, &envp, &flags\);",
                r"is_su_session = !ksu_handle_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags\);",
                r"retval = bprm_execve\(bprm, fd, filename, flags\);\s*#ifdef CONFIG_KSU_SUSFS\s*if \(unlikely\(is_su_session\)\)\s*\(void\)ksu_handle_post_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags, &retval\);",
            ],
            common / "include/linux/susfs.h": [r'#define\s+SUSFS_VERSION\s+"v2\.3\.0"'],
            common / "arch/arm64/configs/gki_defconfig": [r"(?m)^CONFIG_KSU=y$", r"(?m)^CONFIG_KSU_SUSFS=y$"],
            common / "Makefile": [r"(?m)^VERSION = 5$", r"(?m)^PATCHLEVEL = 10$", r"(?m)^SUBLEVEL = 209$"],
        }
        for path, patterns in expected_text.items():
            if not path.is_file():
                raise RuntimeError(f"Required target source is missing: {path}")
            content = path.read_text()
            for pattern in patterns:
                if not re.search(pattern, content, re.DOTALL):
                    raise RuntimeError(f"40971-5 source verification failed: {path.name}: {pattern}")
        # A later `CONFIG_FOO=n` in defconfig overrides an earlier enabled line.
        config_lines = (common / "arch/arm64/configs/gki_defconfig").read_text().splitlines()
        for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS"):
            values = [line for line in config_lines if line.startswith(key + "=")]
            if not values or values[-1] != key + "=y":
                raise RuntimeError(f"40971-5 requires effective {key}=y")

    def write_official_40971_5_manifest(self):
        if not self.config.official_40971_5:
            return
        self._assert_git_head(self.work_dir / "common", OFFICIAL_40971_5_COMMON_COMMIT)
        self._assert_git_head(self.work_dir / "KernelSU", OFFICIAL_40971_5_KSU_COMMIT)
        self._assert_git_head(self.susfs_dir, OFFICIAL_40971_5_SUSFS_COMMIT)
        self._assert_git_head(self.sukisu_patch_dir, OFFICIAL_40971_5_SUKISU_PATCH_COMMIT)
        def git_head(path: Path) -> str:
            return self._run_cmd(f"git -C {shlex.quote(str(path))} rev-parse HEAD", capture_output=True).stdout.strip()

        makefile = self.work_dir / "KernelSU/kernel/Makefile"
        setup_file = self.work_dir / "sukisu-setup.sh"
        resolved_manifest = self.work_dir / "40971-5-resolved-manifest.xml"
        manifest = {
            "target": "android12-5.10.209-2024-05 / KernelSU 40971 / UAPI 5 / SUSFS 2.3.0",
            "common_commit": OFFICIAL_40971_5_COMMON_COMMIT,
            "kernelsu_commit": OFFICIAL_40971_5_KSU_COMMIT,
            "susfs_commit": OFFICIAL_40971_5_SUSFS_COMMIT,
            "sukisu_patch_commit": OFFICIAL_40971_5_SUKISU_PATCH_COMMIT,
            "anykernel_commit": git_head(self.anykernel_dir),
            "manifest_commit": git_head(self.work_dir / ".repo/manifests"),
            "resolved_toolchain_manifest_sha256": hashlib.sha256(resolved_manifest.read_bytes()).hexdigest(),
            "uapi_patch_sha256": hashlib.sha256(OFFICIAL_40971_5_PATCH.read_bytes()).hexdigest(),
            "setup_script_sha256": hashlib.sha256(setup_file.read_bytes()).hexdigest(),
            "kernel_makefile_sha256": hashlib.sha256(makefile.read_bytes()).hexdigest(),
            "kernel_makefile_version_change": "replace upstream LOCAL_COUNT formula with KSU_VERSION := 40971",
            "build_config": self.config.to_dict(),
        }
        (self.work_dir / "40971-5-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def verify_official_40971_5_outputs(self) -> Path:
        dist = self.work_dir / "out/android12-5.10/dist"
        image = dist / "Image"
        for output in (image, dist / "vmlinux", dist / "System.map"):
            if not output.is_file() or output.stat().st_size == 0:
                raise RuntimeError(f"40971-5 build did not produce {output.name}")
        generated_config = self.work_dir / "out/android12-5.10/common/.config"
        if not generated_config.is_file():
            raise RuntimeError("40971-5 generated common/.config is missing")
        config_lines = generated_config.read_text().splitlines()
        if not all(f"{key}=y" in config_lines for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS")):
            raise RuntimeError("40971-5 generated .config does not enable KernelSU and SUSFS")
        if any(f"{key}=y" in config_lines for key in ("CONFIG_KSU_DEBUG", "CONFIG_KPM")):
            raise RuntimeError("40971-5 generated .config unexpectedly enables KSU_DEBUG or KPM")
        return image

    def _configure_zram(self):
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        with open(config_file, "r") as f:
            content = f.read()
        kv = self.config.kernel_version
        if kv == "5.10":
            with open(config_file, "a") as f:
                f.write(self.ZRAM_CONFIG_5_10)
        else:
            content = content.replace("CONFIG_ZRAM=m", "CONFIG_ZRAM=y")
            with open(config_file, "w") as f:
                f.write(content)
            with open(config_file, "a") as f:
                f.write("CONFIG_ZSMALLOC=y\n")
        with open(config_file, "a") as f:
            f.write(self.ZRAM_CONFIG_COMMON)

    def _configure_bazel(self):
        modules_bzl = self.work_dir / "common/modules.bzl"
        if modules_bzl.exists():
            with open(modules_bzl, "r") as f:
                content = f.read()
            modified = False
            for old in ['"drivers/block/zram/zram.ko",\n', '"drivers/block/zram/zram.ko",',
                       '"mm/zsmalloc.ko",\n', '"mm/zsmalloc.ko",']:
                if old in content:
                    content = content.replace(old, '')
                    modified = True
            if modified:
                with open(modules_bzl, "w") as f:
                    f.write(content)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        with open(config_file, "a") as f:
            f.write("CONFIG_MODULE_SIG_FORCE=n\n")

    def configure_kernel_name(self):
        logger.info("=== 配置内核名称 ===")
        self._chdir(self.work_dir)
        MAX_CUSTOM_LEN = 48
        safe_custom_version = ""
        if self.config.custom_version:
            safe_custom_version = self.config.custom_version.rstrip('-')[:MAX_CUSTOM_LEN]

        setlocalversion = self.work_dir / "common/scripts/setlocalversion"
        if setlocalversion.exists():
            with open(setlocalversion, "r") as f:
                content = f.read()
            if safe_custom_version:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'echo "$res"' in line and not line.strip().startswith('#'):
                        lines[i] = f'\techo "{safe_custom_version}$res"'
                        break
                with open(setlocalversion, "w") as f:
                    f.write('\n'.join(lines))
            if "-dirty" in content:
                content = content.replace("-dirty", "")
                with open(setlocalversion, "w") as f:
                    f.write(content)

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

        if self.config.kernel_version in ["6.1", "6.6"]:
            init_makefile = self.work_dir / "common/init/Makefile"
            if init_makefile.exists():
                with open(init_makefile, "r") as f:
                    content = f.read()
                content = content.replace('$(preempt-flag-y) "$(build-timestamp)"', f'$(preempt-flag-y) "{current_time}"')
                with open(init_makefile, "w") as f:
                    f.write(content)

        if not (self.work_dir / "build/build.sh").exists():
            bazel_build = self.work_dir / "common/BUILD.bazel"
            if bazel_build.exists():
                with open(bazel_build, "r") as f:
                    content = f.read()
                lines = [l for l in content.split('\n') if '"protected_exports_list"' not in l or 'android/abi_gki_protected_exports_aarch64' not in l]
                with open(bazel_build, "w") as f:
                    f.write('\n'.join(lines))

            abi_path = self.work_dir / "common/android/abi_gki_protected_exports_aarch64"
            if abi_path.exists():
                import shutil
                try:
                    if abi_path.is_dir():
                        shutil.rmtree(abi_path)
                    else:
                        abi_path.unlink()
                except Exception:
                    pass

            stamp_bzl = self.work_dir / "build/kernel/kleaf/impl/stamp.bzl"
            if stamp_bzl.exists():
                with open(stamp_bzl, "r") as f:
                    content = f.read()
                content = content.replace("-maybe-dirty", "")
                with open(stamp_bzl, "w") as f:
                    f.write(content)

            if self.config.custom_version:
                config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
                if config_file.exists():
                    with open(config_file, "r") as f:
                        content = f.read()
                    content = re.sub(r'^CONFIG_LOCALVERSION=".*"$', f'CONFIG_LOCALVERSION="{self.config.custom_version}"', content, flags=re.MULTILINE)
                    with open(config_file, "w") as f:
                        f.write(content)
                else:
                    logger.warning(f"配置文件不存在，跳过 custom_version 设置: {config_file}")

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
        
        # 显示 ZRAM 相关配置
        if self.config.use_zram:
            zram_configs = [c for c in config_lines if any(x in c for x in ["ZRAM", "ZSMALLOC", "LZ4", "LZ4KD", "CRYPTO_LZ4", "MODULE_SIG"])]
            if zram_configs:
                logger.info("ZRAM 相关配置:")
                for zc in sorted(zram_configs):
                    logger.info(f"  -> {zc}")
        
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
                result = self._run_cmd("LTO=thin BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh CC=\"/usr/bin/ccache clang\"", check=False)
            else:
                logger.info("使用 Bazel 构建方式...")
                result = self._run_cmd("tools/bazel build --disk_cache=/home/runner/.cache/bazel --config=fast --lto=thin //common:kernel_aarch64_dist", check=False)

            if result.returncode == 0:
                logger.info("=== 内核编译成功 ===")
                return True
            logger.error(f"内核编译失败: {result.stderr if result.stderr else 'Unknown error'}")
            return False
        except Exception as e:
            logger.error(f"编译过程出错: {e}")
            return False

    def patch_kpm_image(self):
        if not self.config.use_kpm or self.config.kernel_version == "6.6":
            return
        logger.info("=== 修补 Image 文件 (KPM) ===")
        self._chdir(self.work_dir)

        if self.config.android_version in ["android12", "android13"]:
            image_dir = self.work_dir / f"out/{self.config.android_version}-{self.config.kernel_version}/dist"
        else:
            image_dir = self.work_dir / "bazel-bin/common/kernel_aarch64"

        if not image_dir.exists():
            return
        self._chdir(image_dir)
        self._run_cmd(f"curl -LSs {KPM_PATCH_URL} -o patch && chmod 777 patch && ./patch", check=False)
        if (image_dir / "oImage").exists():
            self._run_cmd("mv oImage Image", check=False)

    def prepare_boot_images(self) -> list:
        logger.info("=== 准备启动镜像 ===")
        self._chdir(self.work_dir)
        bootimgs_dir = self.work_dir / "bootimgs"
        bootimgs_dir.mkdir(exist_ok=True)
        artifacts = []

        if self.config.android_version in ["android12", "android13"]:
            image_source = self.work_dir / f"out/{self.config.android_version}-{self.config.kernel_version}/dist"
        else:
            image_source = self.work_dir / "bazel-bin/common/kernel_aarch64"

        for image_name in ["Image", "Image.lz4"]:
            src = image_source / image_name
            if src.exists():
                self._run_cmd(f"cp {src} {bootimgs_dir}/ && cp {src} {self.work_dir}/", check=False)

        if (self.work_dir / "Image").exists():
            self._run_cmd("gzip -n -k -f -9 Image", check=False)

        if self.config.android_version == "android12":
            self._prepare_android12_boot_images(bootimgs_dir, artifacts)
        else:
            self._prepare_boot_images_generic(bootimgs_dir, artifacts)
        return artifacts

    def _prepare_android12_boot_images(self, bootimgs_dir: Path, artifacts: list):
        self._chdir(bootimgs_dir)
        gki_url = f"https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-{self.config.os_patch_level}_{self.config.revision}.zip"
        fallback_url = "https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-2023-01_r1.zip"
        result = subprocess.run(f"curl -sL -w '%{{http_code}}' {gki_url} -o /dev/null", shell=True, capture_output=True, text=True)
        url = gki_url if "200" in result.stdout else fallback_url
        self._run_cmd(f"curl -Lo gki-kernel.zip {url} && unzip -o gki-kernel.zip && rm gki-kernel.zip", check=False)
        boot_img_path = bootimgs_dir / "boot-5.10.img"
        if boot_img_path.exists():
            self._run_cmd(f"$UNPACK_BOOTIMG --boot_img={boot_img_path}", check=False)
        self._create_boot_image_variants(bootimgs_dir, artifacts, has_ramdisk=True)

    def _prepare_boot_images_generic(self, bootimgs_dir: Path, artifacts: list):
        self._chdir(bootimgs_dir)
        self._create_boot_image_variants(bootimgs_dir, artifacts, has_ramdisk=False)

    def _create_boot_image_variants(self, bootimgs_dir: Path, artifacts: list, has_ramdisk: bool = False):
        self._chdir(bootimgs_dir)
        if (bootimgs_dir / "Image").exists():
            self._run_cmd("gzip -n -k -f -9 Image", check=False)

        for kernel_file, output_file in [("Image", "boot.img"), ("Image.gz", "boot-gz.img"), ("Image.lz4", "boot-lz4.img")]:
            kernel_path = bootimgs_dir / kernel_file
            if not kernel_path.exists():
                continue
            cmd = f"$MKBOOTIMG --header_version 4 --kernel {kernel_file} --output {output_file}"
            if has_ramdisk:
                cmd += f" --ramdisk out/ramdisk --os_version 12.0.0 --os_patch_level {self.config.os_patch_level}"
            self._run_cmd(cmd, check=False)
            self._run_cmd(f"$AVBTOOL add_hash_footer --partition_name boot --partition_size $((64 * 1024 * 1024)) --image {output_file} --algorithm SHA256_RSA2048 --key $BOOT_SIGN_KEY_PATH", check=False)
            dest = self.work_dir / f"{self.config.android_version}-{self.config.kernel_version}.{self.config.sub_level}-{self.config.os_patch_level}-{output_file}"
            self._run_cmd(f"cp {output_file} {dest}", check=False)
            artifacts.append(str(dest))

    def create_anykernel_zips(self) -> list:
        logger.info("=== 创建 AnyKernel3 ZIP 文件 ===")
        self._chdir(self.work_dir)
        artifacts = []
        ak3_dir = self.anykernel_dir

        for suffix in ["", "-lz4", "-gz"]:
            image_file = f"Image{suffix}"
            image_path = self.work_dir / image_file
            if not image_path.exists():
                continue
            zip_name = f"{self.config.android_version}-{self.config.kernel_version}.{self.config.sub_level}-{self.config.os_patch_level}-AnyKernel3{suffix}.zip"
            self._run_cmd(f"cp {image_path} {ak3_dir}/", check=self.config.official_40971_5)
            self._chdir(ak3_dir)
            zip_path = self.work_dir / zip_name if self.config.official_40971_5 else Path("..") / zip_name
            self._run_cmd(f"zip -r {shlex.quote(str(zip_path))} ./*", check=self.config.official_40971_5)
            self._run_cmd(f"rm {ak3_dir}/{image_file}", check=self.config.official_40971_5)
            if self.config.official_40971_5 and not (self.work_dir / zip_name).is_file():
                raise RuntimeError("AnyKernel3 packaging did not produce a ZIP")
            artifacts.append(str(self.work_dir / zip_name))
            self._chdir(self.work_dir)
        return artifacts

    def build(self) -> BuildResult:
        import time
        start_time = time.time()
        logger.info("=" * 50)
        logger.info(f"开始 GKI Kernel 构建 - {self.config.config_name}")
        logger.info("=" * 50)

        try:
            if self.config.official_40971_5 and (self.work_dir / "out").exists():
                raise RuntimeError("40971-5 target requires a fresh output directory")
            self.clone_repositories()
            if not self.config.official_40971_5:
                self.clone_toolchain()
            self.setup_repo_tool()
            self.init_and_sync_kernel()
            self.add_kernel_supatch()
            self.add_kernelsu()
            self.apply_official_40971_5_patch()
            self.test_official_40971_5_contract()
            self.add_bbg()
            self.apply_susfs_patches()
            self.apply_sukisu_patches()
            self.apply_zram_patches()
            self.apply_task_mmu_fixes()
            self.configure_kernel()
            self.verify_official_40971_5_sources()
            self.configure_kernel_name()
            self.show_kernel_config()

            if not self.build_kernel():
                return BuildResult(success=False, config=self.config, message="内核编译失败", build_time=time.time() - start_time)

            self.patch_kpm_image()
            artifacts = []
            if not self.config.official_40971_5:
                artifacts.extend(self.prepare_boot_images())
            else:
                image = self.verify_official_40971_5_outputs()
                self._run_cmd(f"cp {shlex.quote(str(image))} {shlex.quote(str(self.work_dir / 'Image'))}")
            artifacts.extend(self.create_anykernel_zips())
            if self.config.official_40971_5:
                if not artifacts or any(not Path(artifact).is_file() for artifact in artifacts):
                    raise RuntimeError("40971-5 AnyKernel3 artifact is missing")
                self.write_official_40971_5_manifest()
                artifacts.append(str(self.work_dir / "40971-5-manifest.json"))

            build_time = time.time() - start_time
            logger.info(f"构建成功! 耗时: {build_time:.2f} 秒, 生成 {len(artifacts)} 个产物")
            return BuildResult(success=True, config=self.config, message="构建成功", artifacts=artifacts, build_time=build_time)
        except Exception as e:
            logger.error(f"构建过程出错: {e}")
            return BuildResult(success=False, config=self.config, message=str(e), build_time=time.time() - start_time)
