#!/usr/bin/env python3
"""Report migration and native-host wiring completeness without building anything."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXPECTED_REPLACES = {
    "github.com/egoist/ryui": "./third_party/ryui",
    "github.com/sagernet/sing-box": "../core",
    "github.com/sagernet/wireguard-go": "../core/submodules/wireguard-go",
    "github.com/sagernet/sing-tun": "../core/submodules/sing-tun",
    "github.com/sagernet/gvisor": "../core/submodules/gvisor",
    "github.com/metacubex/utls": "../core/submodules/utls",
}
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")


def replace_map(go_mod: str) -> dict[str, str]:
    return dict(re.findall(r"^replace\s+(\S+)\s*=>\s*(\S+)\s*$", go_mod, re.MULTILINE))


def files_containing(root: Path, suffixes: tuple[str, ...], needle: str) -> list[str]:
    hits = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in suffixes:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if needle in text:
                hits.append(path.relative_to(root).as_posix())
    return hits


def source_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    excluded = {"third_party", "testdata", "vendor", "build", ".gradle"}
    return [
        path for path in sorted(root.rglob("*"))
        if path.is_file()
        and any(path.name.endswith(suffix) for suffix in suffixes)
        and not any(part in excluded for part in path.relative_to(root).parts)
    ]


def has_android_library_load(android: Path) -> bool:
    for path in source_files(android, (".kt", ".java")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"loadLibrary\s*\(\s*[\"']lxbox[\"']\s*\)", text):
            return True
        constants = re.findall(r'\b(?:const\s+)?val\s+(\w+)\s*=\s*"lxbox"', text)
        if any(re.search(r"loadLibrary\s*\(\s*" + re.escape(name) + r"\s*\)", text) for name in constants):
            return True
    return False


def functionality_matrix(app: Path) -> list[dict[str, str]]:
    """List only evidence-backed migrated surfaces; absence is not a feature claim."""
    matrix = []
    checks = (
        ("Go application entrypoint", app / "cmd" / "lxbox"),
        ("Go runtime implementation", app / "internal" / "runtime"),
        ("Android host", app / "android"),
        ("Embedded resources", app / "assets"),
    )
    for surface, path in checks:
        exists = path.is_dir() and any(p.is_file() for p in path.rglob("*"))
        matrix.append({"surface": surface, "status": "present" if exists else "missing", "evidence": path.relative_to(app).as_posix()})
    matrix.append({
        "surface": "Flutter/Dart feature parity",
        "status": "not_assessed",
        "evidence": "No feature-by-feature mapping is supplied; absence of Dart dependencies does not establish parity.",
    })
    return matrix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="staging workspace root containing core/ and app/")
    parser.add_argument("--app-root", type=Path, default=None)
    parser.add_argument("--core-root", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--source-only", action="store_true", help="allow missing external checkouts when reviewing an archive; never builds")
    args = parser.parse_args()
    root = args.root.resolve()
    app = (args.app_root or (root / "app")).resolve()
    core = (args.core_root or (root / "core")).resolve()
    report_path = (args.report or (app / "artifacts" / "migration-report.json")).resolve()
    errors: list[str] = []
    warnings: list[str] = []

    app_mod_path = app / "go.mod"
    app_mod = app_mod_path.read_text(encoding="utf-8") if app_mod_path.is_file() else ""
    if not app_mod_path.is_file():
        errors.append("missing app/go.mod")
    elif not re.search(r"^module github\.com/Leadaxe/lxbox/app$", app_mod, re.MULTILINE):
        errors.append("app/go.mod must declare module github.com/Leadaxe/lxbox/app")
    replaces = replace_map(app_mod)
    for module, target in EXPECTED_REPLACES.items():
        if replaces.get(module) != target:
            errors.append(f"app/go.mod replace mismatch: {module} => {replaces.get(module)!r}, expected {target!r}")
        if module == "github.com/egoist/ryui":
            checkout = app / target
        elif module == "github.com/sagernet/sing-box":
            checkout = core
        elif target.startswith("../core/"):
            checkout = core / target.removeprefix("../core/")
        else:
            checkout = (app / target).resolve()
        if not checkout.joinpath("go.mod").is_file():
            message = f"external checkout missing: {module} at {target}"
            (warnings if args.source_only else errors).append(message)
    for rel in ("cmd/lxbox", "assets/embed.go"):
        if not (app / rel).exists():
            errors.append(f"missing required migration path app/{rel}")

    embed_path = app / "assets" / "embed.go"
    embed_text = embed_path.read_text(encoding="utf-8") if embed_path.is_file() else ""
    for token in ("package assets", "FS", "func Read"):
        if token not in embed_text:
            errors.append(f"app/assets/embed.go does not expose {token}")
    asset_files = [p for p in app.glob("assets/**/*") if p.is_file() and p.name != "embed.go"]
    if not asset_files:
        errors.append("app/assets contains no embedded non-Go resources")

    go_sources = source_files(app, (".go",))
    main_sources = []
    main_count = 0
    mobile_main_count = 0
    for path in go_sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        code = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.DOTALL)
        count = len(re.findall(r"\bfunc\s+main\s*\(", code))
        if count:
            main_sources.append(path.relative_to(app).as_posix())
            main_count += count
        mobile_main_count += len(re.findall(r"\bmobile\.Main\s*=", code))
    if main_count == 0:
        errors.append("app/cmd/lxbox has no func main; unified c-shared entrypoint is missing")
    elif main_count > 1:
        errors.append(f"duplicate func main definitions in app module: {main_count}")
    if mobile_main_count > 1:
        errors.append(f"duplicate mobile.Main assignments in app module: {mobile_main_count}")
    if mobile_main_count == 0:
        warnings.append("mobile.Main assignment is not in source; CI overlay must inject exactly one writeOverlay-equivalent init")

    android = app / "android"
    gradle_files = sorted(list(android.glob("*.gradle")) + list(android.glob("*.gradle.kts")) + list(android.rglob("*.gradle")) + list(android.rglob("*.gradle.kts"))) if android.is_dir() else []
    gradle_files = sorted(set(gradle_files))
    gradle_text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in gradle_files)
    if not android.is_dir():
        errors.append("missing app/android host project")
    else:
        if not gradle_files:
            errors.append("app/android has no Gradle build file")
        for expr, label in ((r"compileSdk(?:Version)?\s*[=: ]\s*37\b", "compileSdk 37"), (r"targetSdk(?:Version)?\s*[=: ]\s*36\b", "targetSdk 36"), (r"minSdk(?:Version)?\s*[=: ]\s*24\b", "minSdk 24")):
            if not re.search(expr, gradle_text):
                errors.append(f"Android Gradle host does not declare {label}")
        if not all(abi in gradle_text for abi in ABIS):
            errors.append("Android Gradle host must configure arm64-v8a, armeabi-v7a, and x86_64")
        if not has_android_library_load(android):
            errors.append("Android host must load unified native library with loadLibrary(\"lxbox\")")

    native_bootstrap_hits = []
    initialize_hits = []
    for path in source_files(app, (".go", ".kt", ".java", ".c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"\b(?:nativeBootstrap|NativeBootstrap)\s*\(", text):
            native_bootstrap_hits.append(path.relative_to(app).as_posix())
        if re.search(r"\bruntime\.Initialize\s*\(", text):
            initialize_hits.append(path.relative_to(app).as_posix())
    if not native_bootstrap_hits:
        errors.append("nativeBootstrap JNI bridge is missing from app/mobile or Android host")
    if not initialize_hits:
        errors.append("runtime.Initialize call is missing from native bootstrap wiring")

    dart_files = [p.relative_to(app).as_posix() for p in source_files(app, (".dart",))]
    flutter_pattern = re.compile(r"(?:io\.flutter|dev\.flutter|libflutter|libapp|flutterEmbedding|flutter\.plugin)", re.IGNORECASE)
    flutter_refs = []
    for path in source_files(app, (".go", ".kt", ".java", ".gradle", ".gradle.kts", ".xml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if flutter_pattern.search(text):
            flutter_refs.append(path.relative_to(app).as_posix())
    if dart_files or flutter_refs:
        errors.append("unmigrated Flutter/Dart references found; this workflow does not claim Dart migration")
    else:
        warnings.append("Dart/Flutter sources and runtime dependencies are absent; feature parity remains unassessed")
    matrix = functionality_matrix(app)
    unmigrated = []
    gap_pattern = re.compile(r"\b(?:unmigrated|not migrated|not ported|not implemented|unsupported)\b", re.IGNORECASE)
    for path in source_files(app, (".go", ".kt", ".java")):
        if path.name.endswith("_test.go"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if gap_pattern.search(line):
                unmigrated.append({"file": path.relative_to(app).as_posix(), "line": number, "detail": line.strip()})
    if unmigrated:
        warnings.append(f"{len(unmigrated)} source statements explicitly identify missing/unmigrated behavior; review functionality_gaps")

    report = {
        "module": "github.com/Leadaxe/lxbox/app",
        "status": "error" if errors else "ok",
        "errors": errors,
        "warnings": warnings,
        "main_sources": main_sources,
        "mobile_main_assignments": mobile_main_count,
        "embedded_asset_count": len(asset_files),
        "dart_files": dart_files,
        "flutter_references": flutter_refs,
        "android_gradle_files": [p.relative_to(root).as_posix() for p in gradle_files],
        "native_bootstrap_files": native_bootstrap_hits,
        "runtime_initialize_files": initialize_hits,
        "functionality_matrix": matrix,
        "functionality_gaps": unmigrated,
        "source_only": args.source_only,
        "api24_scope": {
            "min_sdk": 24,
            "compile_sdk": 37,
            "target_sdk": 36,
            "runtime_verified": False,
        },
        "migration_statement": "Dart/Flutter UI is not declared fully migrated; only listed Go, native host, and embedded assets are checked.",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
