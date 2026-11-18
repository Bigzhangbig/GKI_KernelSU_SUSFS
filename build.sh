#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && $1 == /* ]] || { echo "Usage: bash build.sh /absolute/empty-work-directory" >&2; exit 2; }
work=$1
mkdir -p "$work"
[[ -z $(ls -A "$work") ]] || { echo "Build workspace must be empty" >&2; exit 2; }

common_rev=f0826289c51653ee116c20c1dda9c87ad8a30636
patch_rev=547ae94bcaec53d030398f857950c64662043a5d
clang_rev=6e3223f76384455acde43affde3df0ea9df66c0d
clang_repo=https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86
common=$work/common
out=$work/out
patch_repo=$work/codec-source

checkout() {
    local dst=$1 url=$2 rev=$3
    shift 3
    git init -q "$dst"
    git -C "$dst" remote add origin "$url"
    if (( $# )); then
        git -C "$dst" sparse-checkout init --cone
        git -C "$dst" sparse-checkout set "$@"
        git -C "$dst" fetch --no-tags --depth=1 --filter=blob:none origin "$rev"
    else
        git -C "$dst" fetch --no-tags --depth=1 origin "$rev"
    fi
    git -C "$dst" checkout -q --detach FETCH_HEAD
    [[ $(git -C "$dst" rev-parse HEAD) == "$rev" ]]
}

checkout "$common" https://github.com/aosp-mirror/kernel_common.git "$common_rev"
checkout "$patch_repo" https://github.com/SukiSU-Nova/SukiSU_patch.git "$patch_rev" other/zram
zram=$patch_repo/other/zram
for file in crypto/lz4k.c crypto/lz4kd.c include/linux/lz4k.h include/linux/lz4kd.h; do
    install -m 644 "$zram/lz4k/$file" "$common/$file"
done
cp -R "$zram/lz4k/lib/lz4k" "$zram/lz4k/lib/lz4kd" "$common/lib/"
patch_paths=(
    lib/Kconfig lib/Makefile crypto/Kconfig crypto/Makefile
    drivers/block/zram/zram_drv.c drivers/block/zram/Kconfig drivers/block/zram/zcomp.c
)
includes=(--exclude=kernel/module.c)
for path in "${patch_paths[@]}"; do
    includes+=("--include=$path")
done
git -C "$common" apply --check "${includes[@]}" "$zram/zram_patch/5.10/lz4kd.patch"
git -C "$common" apply "${includes[@]}" "$zram/zram_patch/5.10/lz4kd.patch"
diff -u <(printf '%s\n' "${patch_paths[@]}" | LC_ALL=C sort) <(git -C "$common" diff --name-only | LC_ALL=C sort)
git -C "$common" diff --exit-code -- kernel/module.c

clang_dir=$work/toolchain
mkdir "$clang_dir"
if ! curl --fail --location --show-error --silent --max-time 420 \
    "$clang_repo/+archive/$clang_rev/clang-r416183b.tar.gz" | tar -xz -C "$clang_dir"; then
    checkout "$work/clang-git" "$clang_repo" "$clang_rev" clang-r416183b
    clang_dir=$work/clang-git/clang-r416183b
fi
export PATH="$clang_dir/bin:$PATH"
"$clang_dir/bin/clang" --version
"$clang_dir/bin/ld.lld" --version
export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_COMPAT=arm-linux-gnueabi-
export KCFLAGS=-D__ANDROID_COMMON_KERNEL__
kmake=(make -C "$common" O="$out")
"${kmake[@]}" gki_defconfig
"$common/scripts/config" --file "$out/.config" \
    -d LTO_CLANG_FULL -e LTO_CLANG_THIN \
    -e ZSMALLOC -e ZRAM -e CRYPTO_LZ4KD -e ZRAM_DEF_COMP_LZ4KD -e ZRAM_WRITEBACK -e IKCONFIG
"${kmake[@]}" olddefconfig
for flag in ZSMALLOC ZRAM CRYPTO_LZ4KD ZRAM_DEF_COMP_LZ4KD ZRAM_WRITEBACK IKCONFIG LTO_CLANG_THIN; do
    grep -Fx "CONFIG_$flag=y" "$out/.config"
done
grep -Fx 'CONFIG_ZRAM_DEF_COMP="lz4kd"' "$out/.config"
jobs=$(nproc)
(( jobs <= 4 )) || jobs=4
"${kmake[@]}" -j"$jobs" Image
for product in arch/arm64/boot/Image System.map vmlinux .config; do
    test -s "$out/$product"
done
