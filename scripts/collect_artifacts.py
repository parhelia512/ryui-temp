#!/usr/bin/env python3
"""Collect manifests, lint results, versions, dependency graphs and verify APK ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

MACHINES = {"arm64-v8a": 183, "armeabi-v7a": 40, "x86_64": 62}


def elf_load_alignments(data: bytes) -> list[int]:
    if len(data) < 64 or data[5] != 1:
        raise ValueError("unsupported or truncated ELF header")
    if data[4] == 2:
        offset = struct.unpack_from("<Q", data, 32)[0]
        entry_size, count = struct.unpack_from("<HH", data, 54)
        alignment_offset, alignment_format = 48, "<Q"
    elif data[4] == 1:
        offset = struct.unpack_from("<I", data, 28)[0]
        entry_size, count = struct.unpack_from("<HH", data, 42)
        alignment_offset, alignment_format = 28, "<I"
    else:
        raise ValueError("unexpected ELF class")
    alignments = []
    for index in range(count):
        entry = offset + index * entry_size
        if struct.unpack_from("<I", data, entry)[0] == 1:
            alignments.append(struct.unpack_from(alignment_format, data, entry + alignment_offset)[0])
    return alignments


def apk_report(apk: Path) -> dict[str, object]:
    errors = []
    libraries = {}
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        if "AndroidManifest.xml" not in names:
            errors.append("APK has no AndroidManifest.xml")
        if any("libflutter.so" in name or name.endswith("/libapp.so") for name in names):
            errors.append("APK unexpectedly contains a Flutter/Dart runtime")
        if any(name.endswith("/libryui.so") or name.endswith("/libbox.so") for name in names):
            errors.append("APK contains a second standalone Go runtime library")
        for abi, machine in MACHINES.items():
            name = f"lib/{abi}/liblxbox.so"
            if name not in names:
                errors.append(f"missing {name}")
                continue
            data = archive.read(name)
            if data[:4] != b"\x7fELF":
                errors.append(f"{name} is not ELF")
                continue
            found = int.from_bytes(data[18:20], "little")
            if found != machine:
                errors.append(f"{name} has ELF machine {found}, expected {machine}")
            alignments = elf_load_alignments(data)
            if not alignments or any(alignment < 16384 for alignment in alignments):
                errors.append(f"{name} has LOAD alignments below 16 KiB: {alignments}")
            libraries[abi] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "elf_machine": found, "load_alignments": alignments}
    return {"status": "error" if errors else "ok", "errors": errors, "libraries": libraries, "runtime_verified": False}


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
    host = app / "android"
    copied = []
    for path in sorted(host.rglob("*")) if host.is_dir() else []:
        if not path.is_file():
            continue
        rel = path.relative_to(host)
        if "build" not in rel.parts:
            continue
        if path.name == "AndroidManifest.xml" or path.name.startswith("lint-results-") or path.name == "manifest-merger-debug-report.txt" or path.name == "output-metadata.json":
            dest = artifacts / "gradle" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            copied.append(dest.relative_to(artifacts).as_posix())
    for path in sorted((host / "app" / "build" / "outputs").glob("**/*.apk")):
        dest = artifacts / path.name
        if not dest.exists():
            shutil.copy2(path, dest)
    # Build-native logs are written beside jniLibs; preserve them even when Go
    # or Gradle fails before producing an APK.
    native_parent = host / "app" / "src" / "main"
    for path in native_parent.glob("*.log"):
        shutil.copy2(path, artifacts / path.name)
    for pattern in ("go-deps-*.txt", "elf-*.txt", "symbols-*.txt"):
        for path in native_parent.glob(pattern):
            shutil.copy2(path, artifacts / path.name)
    for name in ("go.version", "upstream.version"):
        if (core / name).is_file():
            shutil.copy2(core / name, artifacts / name)
    if (root / "core-commit.txt").is_file():
        shutil.copy2(root / "core-commit.txt", artifacts / "core-commit.txt")
    ndk = os.environ.get("ANDROID_NDK_HOME")
    if ndk and (Path(ndk) / "source.properties").is_file():
        shutil.copy2(Path(ndk) / "source.properties", artifacts / "ndk-source.properties")
    sdk = os.environ.get("ANDROID_HOME")
    verification = None
    errors = []
    apk = artifacts / "lxbox-debug.apk"
    if not apk.is_file():
        candidates = sorted(artifacts.glob("*.apk"))
        if candidates:
            shutil.copy2(candidates[0], apk)
    if apk.is_file():
        verification = apk_report(apk)
        for abi in MACHINES:
            symbols_path = artifacts / f"symbols-{abi}.txt"
            if not symbols_path.is_file():
                verification["errors"].append(f"missing native symbol report for {abi}")
                continue
            symbols = symbols_path.read_text(encoding="utf-8")
            if len(re.findall(r"\bJNI_OnLoad$", symbols, re.MULTILINE)) != 1:
                verification["errors"].append(f"{abi} does not have exactly one defined JNI_OnLoad")
            if not re.search(r"\bbox_jni_onload$", symbols, re.MULTILINE):
                verification["errors"].append(f"{abi} lacks core box_jni_onload initializer")
        if sdk:
            build_tools = Path(sdk) / "build-tools" / "36.0.0"
            for tool, options, output_name in (("aapt", ["dump", "badging"], "manifest.txt"), ("apksigner", ["verify", "--verbose"], "signature.txt")):
                executable = build_tools / tool
                if executable.is_file():
                    result = subprocess.run([str(executable), *options, str(apk)], capture_output=True, text=True, check=False)
                    (artifacts / output_name).write_text(result.stdout + result.stderr, encoding="utf-8")
                    if result.returncode:
                        errors.append(f"{tool} exited {result.returncode}")
                else:
                    errors.append(f"required APK verification tool missing: {executable}")
            manifest = artifacts / "manifest.txt"
            if manifest.is_file():
                text = manifest.read_text(encoding="utf-8")
                if "sdkVersion:'24'" not in text:
                    verification["errors"].append("APK minSdk is not 24")
                if "targetSdkVersion:'36'" not in text:
                    verification["errors"].append("APK targetSdk is not 36")
        else:
            errors.append("ANDROID_HOME is missing; APK manifest and signature were not verified")
        verification["errors"].extend(errors)
        verification["status"] = "error" if verification["errors"] else "ok"
        (artifacts / "apk-verification.json").write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")
        checksum = hashlib.sha256(apk.read_bytes()).hexdigest()
        (artifacts / "SHA256SUMS").write_text(f"{checksum}  {apk.name}\n", encoding="utf-8")
        errors.extend(verification["errors"])
    report = {
        "status": "error" if errors else ("ok" if verification else "no_apk"),
        "copied_gradle_reports": copied,
        "apk_present": verification is not None,
        "errors": errors,
        "runtime_verified": False,
        "dart_feature_parity_verified": False,
    }
    (artifacts / "artifact-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
