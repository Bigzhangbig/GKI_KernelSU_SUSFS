# GKI SukiSU-Ultra + SUSFS

`main` 只维护正式 Release 构建。每次校验或构建都会查询 SukiSU-Ultra 最新的正式 Release，核对源码接口、官方 APK 签名和 native UAPI，再决定能否继续。

构建目标是 **Android 12 / Linux 5.10.209 / 2024-05 / r13**，使用 SUSFS **2.3.0**（含 priority UID filter），关闭 KPM 和 KSU_DEBUG。当前配方对应 **v4.3.0-r2 / 41150 / UAPI6**，用于 Redmi K50 rubens；不声明支持其他 GKI 组合。

## 分支与更新规则

| 分支 | 用途 |
| --- | --- |
| `main` | 自动选择最新兼容的正式 Release |
| `pinned/40971-uapi5` | 固定 40971 / UAPI5 的历史构建 |
| `pinned/40994-ee35e654` | 固定 40994 / ee35e654 的历史构建 |
| `dev` | 保留的开发分支 |

新版只有在内核源码、UAPI、管理器与内核交互的源码指纹保持一致，且官方 APK 签名和 native UAPI 校验通过时，才会自动接受。只有管理器更新时，可以使用新版管理器继续构建已验证的内核后端。

当前是针对 5.10 builtin 的 r2 适配构建，完整身份为 **v4.3.0-r2-1cfa5734+avc-ff7dfe2d+release-85d05cf2@builtin / 41150 / UAPI6**。官方 release 树与 builtin 长期分支不同；实际 builtin SHA、官方增量移植来源和补丁摘要均单独保存。管理器后续更新不会自动改写该后端身份。若内核或接口发生变化，构建会停止，等待审查、适配与验证。

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

## r1/r2 源码与补丁清理

v4.3.0-r2 适配（2026-11-08）：官方变更仅在 manager 侧 —— `build.gradle.kts` 增加 core library desugaring（java.time/java.nio.file 的 Android 7 兼容）、`Natives.kt` 删除一行注释；`kernel/`、`uapi/`、`userspace/` 与 r1 字节一致，builtin 长期分支无漂移，susfs、补丁、AVC backport 与 release backports 全部沿用原 pin。r2 APK（`6fe64e7b…`）签名证书与 pin 一致。

官方 release 为 `645ef9860b9b7f900bb5d1b27e224f2c311d39c0`，builtin 基线为 `1cfa57340590971cba7521ed536da8ebbedc5f0a`。保留原生 UAPI6、扩展中心、version-spoof 和符号查询。内核 release banner 沿用已核对的 rubens 原厂值；实际构建来源以清单和摘要为准。

- 删除旧的 mount-hide procfs 保护补丁：新版 builtin 已原生检查 procfs，并在首次读取时安装记录过滤器，避免旧版拒绝打开挂载文件造成的崩溃。默认启用状态遵循官方新版（关闭）；测试检查三类 proc 文件、普通 ext4/f2fs、过滤、回退和错误保留。
- `708f083` 文件引用修复已有 builtin 等效实现，不重复移植。
- 补齐 `8f6d140`、`45fab659` 在 builtin 中遗漏的原子输入回调及高频路径日志清理，保留控制流。
- 从 `85d05cf22bb0bcc7d41d555221d7eedc850b709f` 移植 SELinux generation 修复：两个策略发布点递增 generation，缓存刷新和通知使用同一个新值。真实 C 合同检查顺序和通知参数，并用定向反例验证断言能检出缺陷。
- `e03a37d` 针对模块/BTF 的 ABI 改动不适用于本次 5.10 builtin 路径，不引入相关依赖。

`release_backport_commits` 与 AVC 来源均为不可替换的完整 SHA，逐项写入产物清单；补丁 SHA256 与源码合同 SHA256 随构建保存。保留历史 Git 提交作为回退记录，删除的是当前构建中重复的补丁内容。

## 保留的兼容改动与限制

SuSFS 2.3.0 的现有 exec hooks 尚未接通新版 builtin 的 preinit runner，因此显式定义 `KSU_NO_PREINIT`，不回报 PREINIT 支持，管理器继续使用常规模块启动流程。此构建不宣称支持 preinit。

保留 common 侧 `ksu_su_compat_enabled` 的 bool 类型和三参数 read hook 适配。SUSFS 自己拥有三个 SELinux 隐藏入口的本地实现；合同检查 UID、运行开关、原始回退及参数，不重新添加已删除的 builtin 委托补丁。

官方 builtin 仍没有 AVC audit 日志 target SID 替换功能，因此保留来自 `ff7dfe2dbc39f78a08ee6fcff23bc615b0f54ea2` 的移植。版本字符串的 `+avc-ff7dfe2d` 与构建清单明确记录来源。

移植仅适配 builtin 的统一编译单元、初始化与启动完成入口、头文件位置和局部静态符号名称。feature 与 extension 的同名强制状态位图分别命名，使统一编译仍保持两组状态隔离。UAPI仍为6，新增 feature ID10003，GET_INFO的features字段上限为10004；该上限不代表有10004项功能。

功能依赖 `CONFIG_KPROBES=y`，官方实现仅修改 slow_avc_audit 的日志渲染 SID，不改变已完成的权限决策。首次启用时SID解析或探针注册失败不会激活探针；官方GET返回的是配置开关，并不证明探针在手机上已激活。实际SID、探针注册及与SuSFS日志处理的组合效果须刷入后另验；关闭此开关不会关闭SuSFS自己的日志处理。
