#!/usr/bin/env python3
"""Build an audited official Release, using latest or an explicit pinned snapshot."""
import argparse
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from config import BuildConfig
from kernel_builder import BuildResult, KernelBuilder
from release_target import load_release_target, resolve_latest_release, verify_release_snapshot

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Build the audited latest SukiSU official Release (android12/5.10.209/2024-05/r13)")
    parser.add_argument("--workspace", "-w", default=os.environ.get("GKI_WORKSPACE", "/tmp/gki-build"))
    parser.add_argument("--output-json")
    parser.add_argument("--dry-run", action="store_true", help="Validate the recipe against the latest official Release without cloning")
    parser.add_argument("--pinned-release", action="store_true",
                        help="Validate and build only the repository's immutable audited Release snapshot")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


def create_build_config(args):
    return BuildConfig(target=load_release_target() if getattr(args, "pinned_release", False) else resolve_latest_release())


def build_single(config, workspace, dry_run=False, pinned_release=False):
    if dry_run:
        if pinned_release:
            verify_release_snapshot(config.target)
        elif resolve_latest_release() != config.target:
            raise ValueError("Latest Release does not match the audited build target")
        selection = "Pinned official Release snapshot" if pinned_release else "Latest official Release"
        return BuildResult(success=True, config=config, message=f"{selection} and audited recipe validated; no build performed")
    return KernelBuilder(config, workspace, pinned_release=pinned_release).build()


def print_summary(results, output_json=None):
    if len(results) != 1:
        raise ValueError("Release builds require exactly one result")
    result = results[0]
    logger.info("%s %s: %s", result.config.target.tag, result.config.config_name, result.message)
    if output_json:
        data = {"timestamp": datetime.now().isoformat(), "total": 1,
                "success": int(result.success), "failed": int(not result.success),
                "results": [{"config": result.config.to_dict(), "success": result.success,
                             "message": result.message, "artifacts": result.artifacts,
                             "build_time": result.build_time}]}
        Path(output_json).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def main():
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        config = create_build_config(args)
        result = build_single(config, args.workspace, args.dry_run, pinned_release=args.pinned_release)
        print_summary([result], args.output_json)
        return 0 if result.success else 1
    except Exception as exc:
        logger.error("Release validation/build failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
