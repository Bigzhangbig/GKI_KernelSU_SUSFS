# GKI 内核编译环境镜像（android12-5.10 管线）
# 构建与推送：.github/workflows/container-publish.yml → ghcr.io/bigzhangbig/gki-kernel-build
# 引用方式：jobs.<job_id>.container.image: ghcr.io/bigzhangbig/gki-kernel-build:latest
#
# 依赖集 = kernel-build.yml 既有 apt 列表（本管线在 ubuntu-latest 上验证过的组合）：
#   build-essential linux-libc-dev bc bison flex libssl-dev libelf-dev
#   ccache git gh curl wget zip unzip xz-utils openssl pixz
#   binutils-aarch64-linux-gnu apksigner
# 追加：
#   python3 + python-is-python3 —— ubuntu 24.04 系统即 3.12，替代 actions/setup-python
#   zstd —— actions/cache 压缩所需
#   openssh-client gnupg rsync —— 宿主 runner 预装但基础镜像没有：
#   repo sync 需 ssh；headers_install 需 rsync（GKI 构建末段复制 UAPI 头）
#   sudo —— 供复用本镜像的其他仓库在调试步骤里兜底
# 不进镜像（由 kernel_builder.py 运行时获取）：repo 启动器、clang 工具链（随 GKI manifest 同步）
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential linux-libc-dev bc bison flex libssl-dev libelf-dev \
      ccache git gh curl wget zip unzip xz-utils openssl pixz \
      binutils-aarch64-linux-gnu apksigner \
      python3 python-is-python3 zstd sudo ca-certificates \
      openssh-client gnupg rsync \
    && rm -rf /var/lib/apt/lists/*

# GitHub Actions 容器作业里 run 步骤默认 shell 是 sh，不支持 set -o pipefail；
# workflow 层统一指定 shell: bash（本镜像自带 bash），SHELL 指令仅保证构建期行为一致。
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 构建期自检：管线必需命令全部就位（clang/repo 不在此列，属运行期下载）
RUN set -euo pipefail; \
    for cmd in gcc make python python3 ccache git curl wget gh apksigner \
               aarch64-linux-gnu-objcopy zip unzip xz pixz zstd sha256sum; do \
      command -v "$cmd" >/dev/null || { echo "missing: $cmd" >&2; exit 1; }; \
    done; \
    python3 --version && ccache --version | head -1 && apksigner --version
