"""Immutable configuration for the single verified official Release recipe."""
from dataclasses import asdict, dataclass, field

from release_target import ReleaseTarget, load_release_target, validate_target

SUSFS_REPO_CONFIG = {"repo_url": "https://github.com/ShirkNeko/susfs4ksu.git"}
SUKISU_PATCH_REPO_CONFIG = {"repo_url": "https://github.com/ShirkNeko/SukiSU_patch.git"}
ANYKERNEL_CONFIG = {"repo_url": "https://github.com/WildPlusKernel/AnyKernel3.git", "branch": "gki-2.0"}


@dataclass(frozen=True)
class BuildConfig:
    target: ReleaseTarget = field(default_factory=load_release_target)

    def __post_init__(self):
        validate_target(self.target)
        if self.target.kernel_tuple != ("android12", "5.10", "209", "2024-05") or self.target.revision != "r13":
            raise ValueError("Only the verified android12/5.10.209/2024-05/r13 GKI target is supported")

    @property
    def android_version(self):
        return self.target.kernel_tuple[0]

    @property
    def kernel_version(self):
        return self.target.kernel_tuple[1]

    @property
    def sub_level(self):
        return self.target.kernel_tuple[2]

    @property
    def os_patch_level(self):
        return self.target.kernel_tuple[3]

    @property
    def revision(self):
        return self.target.revision

    @property
    def kernelsu_commit(self):
        return self.target.kernelsu_commit

    @property
    def susfs_commit(self):
        return self.target.susfs_commit

    @property
    def use_kpm(self):
        return False

    @property
    def config_name(self):
        return f"{self.android_version}-{self.kernel_version}-{self.sub_level}"

    @property
    def formatted_branch(self):
        return f"{self.android_version}-{self.kernel_version}-{self.os_patch_level}"

    @property
    def kernel_branch(self):
        return f"gki-{self.android_version}-{self.kernel_version}"

    def get_susfs_patch_filename(self):
        return f"50_add_susfs_in_gki-{self.android_version}-{self.kernel_version}.patch"

    def to_dict(self):
        data = asdict(self.target)
        data["release_tag"] = data.pop("tag")
        data.update(android_version=self.android_version, kernel_version=self.kernel_version,
                    sub_level=self.sub_level, os_patch_level=self.os_patch_level,
                    full_version=self.target.full_version, release=True, use_kpm=False, make_release=False, ksu_debug=False)
        return data
