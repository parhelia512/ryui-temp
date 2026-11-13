#!/usr/bin/env python3
"""Verify package metadata and the embedded Go libraries without running them."""

import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

out = Path(sys.argv[1])
apk = out / "ryui-gallery-api24-debug.apk"
badging = (out / "apk-badging.txt").read_text(encoding="utf-8")
if not re.search(r"^sdkVersion:'24'$", badging, re.M):
    raise SystemExit("APK minSdk is not 24")
if not re.search(r"^targetSdkVersion:'36'$", badging, re.M):
    raise SystemExit("APK targetSdk is not 36")
abis = ["arm64-v8a", "armeabi-v7a", "x86_64"]
with zipfile.ZipFile(apk) as archive:
    if "AndroidManifest.xml" not in archive.namelist():
        raise SystemExit("APK contains no AndroidManifest.xml")
    libraries = {}
    machines = {"arm64-v8a": 183, "armeabi-v7a": 40, "x86_64": 62}
    for abi in abis:
        name = f"lib/{abi}/libryui.so"
        data = archive.read(name)
        if data[:4] != b"\x7fELF":
            raise SystemExit(f"{name} is not ELF")
        machine = int.from_bytes(data[18:20], "little")
        if machine != machines[abi]:
            raise SystemExit(f"{name} has unexpected ELF architecture {machine}")
        libraries[abi] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if not any(n.startswith("assets/") for n in archive.namelist()):
        raise SystemExit("Gallery assets were not embedded")
report = {
    "min_sdk": 24,
    "target_sdk": 36,
    "package": re.search(r"package: name='([^']+)'", badging).group(1),
    "embedded_libraries": libraries,
    "runtime_verified": False,
}
(out / "apk-verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
