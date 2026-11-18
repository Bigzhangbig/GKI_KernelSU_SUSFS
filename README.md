# Android 12 GKI 5.10.209 with zram and lz4kd

This standalone branch builds an ARM64 kernel Image from the Android common kernel.
It uses the Android GKI configuration, adds the lz4kd compression codec, and enables
zram with lz4kd as the default compressor and writeback support. It has no dependency
on the other branches of this repository.

The GitHub Actions workflow runs `build.sh` on Ubuntu 22.04 and passes the resulting
Image, kernel configuration, ELF and symbol map to `verify.py`. The downloadable
artifact contains the kernel Image, configuration, verification evidence and checksums.

The checks cover the compiled binary. They do not establish phone boot compatibility,
vendor module compatibility or on-device compression performance. This artifact is a
raw kernel Image, not a device-specific boot image or recovery installer.
