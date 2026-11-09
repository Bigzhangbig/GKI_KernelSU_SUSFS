# GKI SukiSU-Ultra + SUSFS

`main` 只维护正式 Release 构建。每次校验或构建都会查询 SukiSU-Ultra 最新的正式 Release，核对源码接口、官方 APK 签名和 native UAPI，再决定能否继续。

构建目标是 **Android 12 / Linux 5.10.209 / 2024-05 / r13**，使用 SUSFS **2.4.0**（含 priority UID filter），关闭 KPM 和 KSU_DEBUG。当前配方对应 **v4.3.0-r2 / 41150 / UAPI6**，用于 Redmi K50 rubens；不声明支持其他 GKI 组合。

本分支 `codex/k50-upstream-inode-20261109` 在该配方上加入 KSTAT inode 生命周期修复。规则持有目标 inode 引用，并在替换规则或文件系统退出时释放。真实 SUSFS 2.4.0 源码合同、补丁摘要和打包 Image 的 `KSTAT published path=` 标记均参与构建门禁。用户已选定官方 builtin 当前最新基线 `1cfa5734`，手机重启与长期使用效果待刷入后验收。

## 分支与更新规则

| 分支 | 用途 |
| --- | --- |
| `main` | 自动选择最新兼容的正式 Release |
| `pinned/40971-uapi5` | 固定 40971 / UAPI5 的历史构建 |
| `pinned/40994-ee35e654` | 固定 40994 / ee35e654 的历史构建 |
| `dev` | 保留的开发分支 |

新版只有在内核源码、UAPI、管理器与内核交互的源码指纹保持一致，且官方 APK 签名和 native UAPI 校验通过时，才会自动接受。只有管理器更新时，可以使用新版管理器继续构建已验证的内核后端。

当前是针对 5.10 builtin 的 r2 适配构建，完整身份为 **v4.3.0-r2-1cfa5734@builtin / 41150 / UAPI6 / features 17**。官方 `kernel/`、`uapi/`、`userspace/` 源码**原样使用，不做 fork 修改**；保留的只有两处构建胶水（见下节）。管理器后续更新不会自动改写该后端身份。若内核或接口发生变化，构建会停止，等待审查、适配与验证。

已审查的后端配方位于 [.github/release-target.json](.github/release-target.json)。构建产物中的 `release-target.json` 则记录该次实际选中的正式 Release 和官方 APK 身份，供后续复验使用。

## 为什么钉死版本 —— "fork 最新提交" ≠ 固定

一个常见疑问："fork 上游源码到最新那个提交，不就已经固定了吗？" —— 在很窄的意义上成立（那个提交是确定坐标），但不足以支撑本管线的目标，有三道裂缝：

**1. fork 的"最新"是随时间移动的标签，不是坐标。**
fork 的 `main` / `HEAD` / "最新提交" 是会被前进、甚至被 force-push 改写的**标签**；SHA 才是不会变的**坐标**。不 pull 上游它停在旧位置（叫"最新"其实是"旧"），定期 pull 则同一个 `main HEAD` 今天明天是两个东西。

**2. 构建依赖 5 个仓库，fork 只覆盖 1 个。**
真正进内核的东西是 SukiSU builtin、`ShirkNeko/susfs4ksu`、GKI common 源、AnyKernel3 模板、官方 APK 这一整套，各家都在独立漂移。"每家都用最新"是最危险组合，不是"各取最新就能编"。

**3. 各家"最新"之间有隐式符号依赖。**
例：susfs 某 commit 的 `exec.c` 引用 `susfs_set_priority_uid_filter`，该符号要求 kernelsu 树也到对应位置，两边配错直接编译挂（41100 就踩过，见 reports/14）。显式钉成一组已验证的组合，才能审计与复现。

**真正的固定点在 `release-target.json`，不在 fork。**
fork 只是放补丁/胶水/workflow 的载体，它"最新推到哪个 commit"与构建身份无关。身份锚在配方的这些字段上：

```
kernelsu_commit / susfs_commit / patch_commit / common_commit /
anykernel_commit / release_commit / apk_sha256 / source_fingerprint
```

其中 `source_fingerprint` 按 **kernel/ uapi/ userspace/ 的文件内容哈希**（不是分支名或"最新提交"）计算。所以即使 fork 的 main 被推来推去，只要这些字段没变，`verify_delivery.py` 就能逐字节证明"这次 CI 编出的 Image = 钉死那份源码编出的"。上游一变更（哪怕只动一行内核），指纹就变、门禁就故意拦住，逼人工审后再放行——这就是"r2 适配"要走一遍的原因。

一句话：**你要的是跨时间、跨机器、多仓库、可审计的确定性；固定的是坐标(SHA) + 内容指纹，fork 只是打补丁和跑流水线的工具，不承担"固定"的职责。**

## 构建与检查

在 GitHub **Actions → Kernel Build → Run workflow** 手动启动完整构建，没有版本、SHA、Dev 或矩阵输入。成功后下载 `kernel-release` 中的 AnyKernel3 ZIP；`evidence-release` 保存配置、源码清单和链接后二进制验证证据。

`Release checks` 在 `main` 的推送、拉取请求或手动运行时执行单元回归、最新 Release/APK 检查，以及从精确提交取得的真实 builtin C 源码契约。它不编译完整 GKI 内核，也不证明设备启动或 root 验收通过。

本地使用 Linux、Python 3.12、Git、GitHub CLI（`gh`）、C 编译器和 `apksigner`，在仓库根目录运行：

```bash
# 校验最新正式 Release、源码接口和官方 APK；不克隆、编译内核
python .github/workflows/scripts/build.py --dry-run --output-json release-check.json

# 完整构建；使用没有旧 out 目录和旧 ZIP 的工作目录
python .github/workflows/scripts/build.py \
  --workspace /tmp/gki-release --output-json /tmp/gki-release/build-result.json

# 回归检查
python -m unittest discover -s tests -v
```

可设置 `GH_TOKEN` 访问 GitHub API。完整构建还需要工作流中列出的内核编译依赖和足够磁盘空间。

构建会验证精确源码提交、补丁与真实 C 行为，检查生成配置、Image/vmlinux/System.map、ZIP 中的 Image，以及 ELF 与打包后二进制的一致性。任何必需检查失败时均不导出“已验证”内核包。Actions 产物验证与实际设备启动、root、休眠唤醒等验收分别进行。

## r1/r2 源码与补丁清理

v4.3.0-r2 适配（2026-11-08）：官方变更仅在 manager 侧 —— `build.gradle.kts` 增加 core library desugaring（java.time/java.nio.file 的 Android 7 兼容）、`Natives.kt` 删除一行注释；`kernel/`、`uapi/`、`userspace/` 与 r1 字节一致。

官方 release 为 `645ef9860b9b7f900bb5d1b27e224f2c311d39c0`，builtin 基线为 `1cfa57340590971cba7521ed536da8ebbedc5f0a`。保留原生 UAPI6、扩展中心、version-spoof 和符号查询。内核 release banner 沿用已核对的 rubens 原厂值；实际构建来源以清单和摘要为准。

### main 配方原则（2026-11-09 起）：官方内核源码零修改

`main` 的 `sukisu-builtin-release.patch` 只保留两处**构建胶水**，不含任何行为/功能修改：

1. **Kconfig 胶水**：`KSU_SUSFS_PRIORITY_UID_FILTER` 符号。上游 susfs patch 的 `default y` 依赖此符号存在于 builtin 树的 Kconfig（官方 builtin 不自带），缺了编译不过。纯构建依赖，无运行时行为。
2. **Makefile 胶水**：无条件 `-DKSU_NO_PREINIT`（pinned susfs 2.4.0 的 preinit 钩子未接通，见下节）+ 离线化 `GITHUB_COMMITS :=` 禁用（CI 不依赖运行时 release 查询）。

已移除的内核修改（历史配方 `codex/sukisu-v4.3.0-r2` 分支仍可查到）：

- **AVC backport**（`ff7dfe2d`）：kprobe 替换 `slow_avc_audit` 审计 tcontext 的移植 —— 属"功能"级修改，按 main 零修改原则移除。本机 susfs 模块的 `avc_log_spoofing` 是 SUSFS 自带 hook（`10_enable_susfs_for_ksu.patch` 内），与这个独立；移除后 `ksu_susfs enable_avc_log_spoofing` 仍可用，SukiSU 侧的 avc_spoof feature 不再存在。
- **release backports**（`8f6d140`/`45fab659`/`85d05cf2`）：原子输入回调、高频路径日志清理、SELinux generation 修复 —— 全部是行为修改，移除。`85d05cf2` 的 generation 修复对应 dmesg 里策略重载行为，移除后策略发布路径回到官方 builtin 原样。
- **pr_info 删除**（sucompat/lsm_hook/ksud）：日志噪音清理，行为无差别，移除（恢复官方原样即保留这些 log，属"官方源码原样"）。

features 从 `10004` 回到官方 builtin 的 `KSU_FEATURE_MAX`（17，即 MOUNT_HIDE=16 之后），GET_INFO 上报值随之变化；合约测试同步改为校验 17。`CONFIG_KPROBES` 不再由本管线强制（defconfig 本身含）。

保留项（非内核修改配方）：

- **banner 对齐**（`stock_kernel_release_suffix` / `stock_kernel_build_stamp`）：rubens 原厂 release 串与 UTS_VERSION 硬编码，11-02 小黑盒事故的修复，用户明确要求保留。
- `CONFIG_KPM=n` / `CONFIG_KSU_DEBUG=n` 与 SUSFS feature 组 defconfig 追加：构建配置选择，非源码修改。

## 保留的兼容改动与限制

SuSFS 2.4.0 的现有 exec hooks 尚未接通新版 builtin 的 preinit runner，因此显式定义 `KSU_NO_PREINIT`，不回报 PREINIT 支持，管理器继续使用常规模块启动流程。此构建不宣称支持 preinit。

保留 common 侧 `ksu_su_compat_enabled` 的 bool 类型和三参数 read hook 适配。SUSFS 自己拥有三个 SELinux 隐藏入口的本地实现；合同检查 UID、运行开关、原始回退及参数，不重新添加已删除的 builtin 委托补丁。

（AVC audit 日志 target SID 替换功能：官方 builtin 无此功能，main 配方不再移植；历史移植与验证记录见 `codex/sukisu-v4.3.0-r2` 分支及 reports/14。）
