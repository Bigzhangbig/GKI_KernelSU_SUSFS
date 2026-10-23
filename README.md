# GKI SukiSU-Ultra + SUSFS

`main` 只维护正式 Release 构建。每次校验或构建都会查询 SukiSU-Ultra 最新的正式 Release，核对源码接口、官方 APK 签名和 native UAPI，再决定能否继续。

当前已验证的构建目标是 **Android 12 / Linux 5.10.209 / 2024-05 / r13**，使用 SUSFS **2.3.0**，关闭 KPM 和 KSU_DEBUG。当前审查配方对应 **v4.2.1-r1 / 41049 / UAPI6**。其他 GKI 组合没有在 `main` 提供构建入口。

## 分支与更新规则

| 分支 | 用途 |
| --- | --- |
| `main` | 自动选择最新兼容的正式 Release |
| `pinned/40971-uapi5` | 固定 40971 / UAPI5 的历史构建 |
| `pinned/40994-ee35e654` | 固定 40994 / ee35e654 的历史构建 |
| `dev` | 保留的开发分支 |

新版只有在内核源码、UAPI、管理器与内核交互的源码指纹保持一致，且官方 APK 签名和 native UAPI 校验通过时，才会自动接受。只有管理器更新时，可以使用新版管理器继续构建已验证的内核后端。

内核后端仍如实报告 **41049 / v4.2.1-r1-ce75122b@builtin / UAPI6**。管理器的新版标签、提交和版本号单独记录，不会用管理器版本覆盖内核版本。若内核或接口发生变化，构建会停止，等待审查、适配与验证；不会静默退回旧版或切到 Dev。

已审查的后端配方位于 [.github/release-target.json](.github/release-target.json)。构建产物中的 `release-target.json` 则记录该次实际选中的正式 Release 和官方 APK 身份，供后续复验使用。

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

## v4.2.1-r1 配方的明确限制

使用官方 builtin 提交 `ce75122bec7423e0f1fa06e3e9a174085c5231ab`，保留其原生 UAPI6、扩展中心 ioctl 和符号查询；不再应用旧版 UAPI2→5 声明补丁。

SuSFS 2.3.0 的现有 exec hooks 尚未接通新版 builtin 的 preinit runner，因此显式定义 `KSU_NO_PREINIT`，不回报 PREINIT 支持，管理器继续使用常规模块启动流程。此构建不宣称支持 preinit。

本地源码补丁另将 mount_hide 文件筛选限定为 procfs，避免普通 ext4/f2fs 文件仅因命名为 `mountinfo`、`mounts` 或 `mountstats` 而被拦截；已用未修复的真实 helper 验证该反例。源码补丁与真实 C 合同的哈希随构建保存。
