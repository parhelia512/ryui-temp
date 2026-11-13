#!/usr/bin/env python3
"""Keep Gradle manifests and reports even when the build fails."""

from pathlib import Path
import os
import shutil
import sys

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
host = cache / "ryui/android-host"
marker = out / "host-path.txt"
if marker.exists():
    host = Path(marker.read_text(encoding="utf-8").strip())
collected = []
if host.exists():
    for path in host.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(host)
        if "build" not in rel.parts:
            continue
        if (path.name == "AndroidManifest.xml"
                or path.name.startswith("lint-results-")
                or path.name == "manifest-merger-debug-report.txt"):
            dest = out / "gradle" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            collected.append(rel.as_posix())
(out / "collected-reports.txt").write_text("\n".join(collected) + "\n", encoding="utf-8")
print(f"Collected {len(collected)} manifest/Lint report files from {host}")
