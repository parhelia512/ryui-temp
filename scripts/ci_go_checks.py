#!/usr/bin/env python3
"""Run CI-only dependency resolution, gofmt diagnostics, pure-package tests/vet.

Android c-shared compilation lives in build_android.py. Never call go test ./...
for the entire app: RyUI/mobile and app/mobile are Android/iOS-only packages.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from build_android import canonical_tags, ensure_dependencies, run

# These packages are explicitly testable on Linux. They do not import the app UI
# or mobile JNI package. Core/runtime also use the canonical core feature tags.
PURE_PACKAGES = (
    "./assets",
    "./internal/model",
    "./internal/parser",
    "./internal/storage",
    "./internal/builder",
    "./internal/automation",
    "./internal/debugapi",
    "./internal/diagnostics",
    "./internal/ruleset",
    "./internal/transfer",
    "./internal/warp",
    "./internal/core",
    "./internal/runtime",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--app-root", type=Path, default=None)
    parser.add_argument("--core-root", type=Path, default=None)
    parser.add_argument("--artifacts", type=Path, default=None)
    args = parser.parse_args()
    root = args.root.resolve()
    app = (args.app_root or (root / "app")).resolve()
    core = (args.core_root or (root / "core")).resolve()
    artifacts = (args.artifacts or (root / "artifacts")).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOFLAGS": "-buildvcs=false", "GOWORK": "off"})
    ensure_dependencies(root, app, core)

    # The app checkout is an isolated CI workspace. Format it before type checks
    # so pre-existing review-style formatting cannot prevent the real build.
    go_files = [str(path) for path in sorted(app.rglob("*.go"))
                if not any(p in {"third_party", "testdata", "vendor"} for p in path.relative_to(app).parts)]
    if go_files:
        run(["gofmt", "-w", *go_files], cwd=app, env=env, log_path=artifacts / "gofmt.log")
        run(["gofmt", "-d", *go_files], cwd=app, env=env, log_path=artifacts / "gofmt.diff")
    run(["go", "mod", "tidy"], cwd=app, env=env, log_path=artifacts / "go-mod-tidy.log")
    run(["go", "mod", "graph"], cwd=app, env=env, log_path=artifacts / "go-dependency-graph.txt")
    run(["go", "list", "-m", "-json", "all"], cwd=app, env=env, log_path=artifacts / "go-modules.json")
    for name in ("go.mod", "go.sum"):
        path = app / name
        if path.is_file():
            (artifacts / ("resolved-" + name)).write_bytes(path.read_bytes())
    packages = [package for package in PURE_PACKAGES if (app / package[2:]).is_dir()]
    if not packages:
        raise RuntimeError("no pure Go packages were found; refusing an empty test/vet pass")
    tags = canonical_tags(core)
    graph = {
        "pure_go_test_vet_packages": packages,
        "android_only_packages": ["./cmd/lxbox", "./mobile", "./internal/ui"],
        "android_validation": "go build -buildmode=c-shared with full canonical core tags for all three ABIs",
        "canonical_core_tags": tags,
    }
    (artifacts / "go-check-scope.json").write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
    # core includes the Android cronet backend when with_naive_outbound is set.
    # Linux validates that same feature graph through its supported purego path.
    test_env = dict(env)
    test_env["CGO_ENABLED"] = "0"
    linux_tags = tags + ["with_purego"]
    run(["go", "test", "-count=1", "-tags", ",".join(linux_tags), "-ldflags", "-checklinkname=0", *packages], cwd=app, env=test_env, log_path=artifacts / "go-pure-tests.log")
    run(["go", "vet", "-tags", ",".join(linux_tags), *packages], cwd=app, env=test_env, log_path=artifacts / "go-pure-vet.log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
