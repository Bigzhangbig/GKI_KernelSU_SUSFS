"""Resolve signed stable managers against an audited, immutable builtin backend.

A new tag is allowed when its kernel/API/interaction implementation is unchanged.
The manager's version never replaces the actual backend's version or source SHA.
"""
import base64
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from release_apk import inspect_release_apk

RECIPE = Path(__file__).resolve().parents[2] / "release-target.json"
OFFICIAL_REPOSITORY = "SukiSU-Ultra/SukiSU-Ultra"
INTERACTION_PATHS = frozenset((
    "userspace/ksud/build.rs", "manager/app/build.gradle.kts",
    "userspace/ksud/src/ksucalls.rs", "userspace/ksud/src/dynamic_manager.rs",
    "userspace/ksud/src/ksu_uapi.h", "manager/app/src/main/cpp/ksu.cc",
    "manager/app/src/main/cpp/ksu.h", "manager/app/src/main/cpp/jni.cc",
    "manager/app/src/main/java/com/sukisu/ultra/Natives.kt"))
LABEL_FILES = frozenset(("kernel/Makefile", "kernel/Kbuild"))
LABEL_ASSIGNMENT = re.compile(r"^(?:VERSION_BASE|VERSION_OFFSET|KSU_GITHUB_VER|GITHUB_COMMITS|LOCAL_COUNT|KSU_VERSION|VERSION_TAG|KSU_VERSION_FULL)\s*:?=")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-r[1-9][0-9]*)?")
FRONTEND_FIELDS = frozenset(("tag", "release_commit", "manager_version", "apk_name", "apk_sha256"))

@dataclass(frozen=True)
class ReleaseTarget:
    tag: str
    release_commit: str
    manager_version: int
    backend_tag: str
    source_fingerprint: str
    version: int
    uapi: int
    features: int
    kernelsu_commit: str
    susfs_commit: str
    susfs_version: str
    patch_commit: str
    common_commit: str
    anykernel_commit: str
    kernel_tuple: tuple
    revision: str
    apk_name: str
    apk_sha256: str
    manager_certificate_sha256: str

    @property
    def name(self):
        return "release"

    @property
    def full_version(self):
        return f"{self.backend_tag}-{self.kernelsu_commit[:8]}@builtin"

    @property
    def archive_name(self):
        android, kernel, sublevel, patch = self.kernel_tuple
        return f"{android}-{kernel}.{sublevel}-{patch}-AnyKernel3.zip"

    @property
    def pins(self):
        return {key: getattr(self, key) for key in
                ("common_commit", "kernelsu_commit", "susfs_commit", "patch_commit", "anykernel_commit")}


def _shape(target):
    for key in ("release_commit", "common_commit", "kernelsu_commit", "susfs_commit", "patch_commit", "anykernel_commit"):
        if not isinstance(getattr(target, key), str) or SHA.fullmatch(getattr(target, key)) is None:
            raise ValueError("Release requires a complete source SHA: " + key)
    for key in ("apk_sha256", "manager_certificate_sha256", "source_fingerprint"):
        if not isinstance(getattr(target, key), str) or DIGEST.fullmatch(getattr(target, key)) is None:
            raise ValueError("Release requires a SHA256 digest: " + key)
    if not TAG.fullmatch(target.tag) or not TAG.fullmatch(target.backend_tag):
        raise ValueError("Only stable semantic Release tags are supported")
    if any(type(getattr(target, key)) is not int or getattr(target, key) <= 0
           for key in ("version", "manager_version", "uapi", "features")):
        raise ValueError("Release identity fields must be positive integers")
    if target.apk_name != f"SukiSU_{target.tag}_{target.manager_version}-release.apk":
        raise ValueError("Manager APK filename and Release identity differ")
    return target


def load_release_target():
    data = json.loads(RECIPE.read_text())
    data["kernel_tuple"] = tuple(data["kernel_tuple"])
    return _shape(ReleaseTarget(**data))


def validate_target(target):
    _shape(target)
    baseline = asdict(load_release_target())
    if any(value != baseline[key] for key, value in asdict(target).items() if key not in FRONTEND_FIELDS):
        raise ValueError("Backend recipe differs from the audited source/ABI/configuration")
    return target


def load_target_file(path):
    data = json.loads(Path(path).read_text())
    data["kernel_tuple"] = tuple(data["kernel_tuple"])
    return validate_target(ReleaseTarget(**data))


def github_api(endpoint):
    result = subprocess.run(["gh", "api", f"repos/{OFFICIAL_REPOSITORY}/{endpoint}"],
                            capture_output=True, text=True, timeout=60, check=True)
    return json.loads(result.stdout)


def source_fingerprint(tree, read_blob):
    """Hash exact kernel/UAPI/interaction files; ignore only version label assignments."""
    if tree.get("truncated") is not False:
        raise ValueError("Official source tree is incomplete")
    entries = tree.get("tree", [])
    paths = {item.get("path") for item in entries if item.get("type") == "blob"}
    if not INTERACTION_PATHS.issubset(paths) or not {"kernel/Kbuild", "kernel/Makefile"}.issubset(paths):
        raise ValueError("Official source layout changed; adaptation is required")
    records = []
    seen = set()
    for item in entries:
        path = item.get("path", "")
        if not (path.startswith(("kernel/", "uapi/", "userspace/", "manager/app/src/main/cpp/")) or path in INTERACTION_PATHS):
            continue
        if item.get("type") == "tree":
            continue
        if item.get("type") != "blob" or item.get("mode") not in ("100644", "100755", "120000"):
            raise ValueError("Unsupported source entry: " + path)
        if path in seen or SHA.fullmatch(item.get("sha", "")) is None:
            raise ValueError("Invalid or duplicate source entry: " + path)
        seen.add(path)
        digest = item["sha"]
        if path in LABEL_FILES:
            contents = read_blob(item["sha"]).decode("utf-8")
            normalized = "\n".join(line for line in contents.splitlines() if not LABEL_ASSIGNMENT.match(line))
            digest = hashlib.sha256(normalized.encode()).hexdigest()
        records.append((path, item["mode"], digest))
    return hashlib.sha256(json.dumps(sorted(records), separators=(",", ":")).encode()).hexdigest()


def _read_blob(sha):
    blob = github_api("git/blobs/" + sha)
    if blob.get("encoding") != "base64":
        raise ValueError("Unsupported official source blob encoding")
    contents = base64.b64decode(blob["content"], validate=False)
    actual = hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
    if actual != sha:
        raise ValueError("Official source blob identity differs")
    return contents


def release_asset(release):
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("Only official stable Releases are supported on main")
    tag = release.get("tag_name", "")
    if not isinstance(tag, str) or TAG.fullmatch(tag) is None:
        raise ValueError("Unsupported official stable tag format")
    pattern = re.compile(r"SukiSU_" + re.escape(tag) + r"_([0-9]+)-release\.apk")
    assets = [(asset, pattern.fullmatch(asset.get("name") or "")) for asset in release.get("assets", [])]
    assets = [(asset, match) for asset, match in assets if match]
    if len(assets) != 1:
        raise ValueError("Expected exactly one official signed manager APK")
    asset, match = assets[0]
    digest = asset.get("digest", "")
    url = f"https://github.com/{OFFICIAL_REPOSITORY}/releases/download/{tag}/{asset['name']}"
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or asset.get("browser_download_url") != url:
        raise ValueError("Official manager APK digest or download origin is invalid")
    if type(asset.get("size")) is not int or not 0 < asset["size"] <= 256 * 1024 * 1024:
        raise ValueError("Official manager APK size is invalid")
    return tag, int(match[1]), asset


def validate_manager(target, metadata):
    expected = {"package": "com.sukisu.ultra", "version_name": target.tag,
                "version_code": target.manager_version, "uapi": target.uapi,
                "certificate_sha256": target.manager_certificate_sha256, "sha256": target.apk_sha256}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("Official APK signature, actual manager identity or native UAPI changed; adaptation is required")


def _resolve(release):
    baseline = load_release_target()
    tag, manager_version, asset = release_asset(release)
    commit = github_api("commits/" + tag).get("sha", "")
    if SHA.fullmatch(commit) is None:
        raise ValueError("Official Release tag does not resolve to a commit")
    tree = github_api(f"git/trees/{commit}?recursive=1")
    fingerprint = source_fingerprint(tree, _read_blob)
    if fingerprint != baseline.source_fingerprint:
        raise ValueError(f"Official Release {tag} changed kernel/API/interaction implementation; adaptation and review are required before building")
    target = validate_target(replace(baseline, tag=tag, release_commit=commit, manager_version=manager_version,
                                    apk_name=asset["name"], apk_sha256=asset["digest"][7:]))
    with tempfile.TemporaryDirectory(prefix="official-manager-") as directory:
        subprocess.run(["gh", "release", "download", tag, "--repo", OFFICIAL_REPOSITORY,
                        "--pattern", target.apk_name, "--dir", directory],
                       capture_output=True, text=True, check=True, timeout=180)
        apk = Path(directory) / target.apk_name
        if apk.stat().st_size != asset["size"]:
            raise ValueError("Downloaded official APK size differs from Release metadata")
        validate_manager(target, inspect_release_apk(apk))
    return target


def resolve_latest_release():
    return _resolve(github_api("releases/latest"))


def verify_release_snapshot(target):
    validate_target(target)
    resolved = _resolve(github_api("releases/tags/" + target.tag))
    if resolved != target:
        raise ValueError("Release snapshot differs from its immutable official tag/APK")
    return target
