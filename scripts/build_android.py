#!/usr/bin/env python3
"""Build the migrated app's unified Go c-shared libraries and Android debug APK.

The script invokes Go and Gradle when explicitly executed in CI. It never starts
an emulator or device and never invokes Git. Local review in this workspace is
restricted to Python AST/YAML parsing; do not execute this build entrypoint locally.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ABIS = {
    "arm64-v8a": ("arm64", "aarch64-linux-android24-clang", None),
    "armeabi-v7a": ("arm", "armv7a-linux-androideabi24-clang", "7"),
    "x86_64": ("amd64", "x86_64-linux-android24-clang", None),
}
EXPECTED_SUBMODULES = {
    "github.com/sagernet/wireguard-go": "../core/submodules/wireguard-go",
    "github.com/sagernet/sing-tun": "../core/submodules/sing-tun",
    "github.com/sagernet/gvisor": "../core/submodules/gvisor",
    "github.com/metacubex/utls": "../core/submodules/utls",
}


def run(command: list[str], *, cwd: Path, env: dict[str, str], log_path: Path | None = None, check: bool = True) -> int:
    print("+", " ".join(command), flush=True)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    output = []
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        output.append(line)
    rc = process.wait()
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("".join(output), encoding="utf-8")
    if check and rc:
        raise RuntimeError(f"command failed ({rc}): {' '.join(command)}")
    return rc


def parse_replaces(go_mod: str) -> dict[str, str]:
    return dict(re.findall(r"^replace\s+(\S+)\s*=>\s*(\S+)\s*$", go_mod, re.MULTILINE))


def go_code(text: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.DOTALL)


def canonical_tags(root: Path) -> list[str]:
    source = root / "cmd" / "internal" / "build_libbox" / "main.go"
    text = go_code(source.read_text(encoding="utf-8"))
    tags: list[str] = []
    for match in re.finditer(r"sharedTags\s*=\s*append\(sharedTags,([^\n]+)\)", text):
        tags.extend(re.findall(r'"([^"]+)"', match.group(1)))
    if not tags:
        raise RuntimeError(f"could not extract sharedTags from {source}")
    required = {"with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_naive_outbound", "badlinkname", "tfogo_checklinkname0"}
    missing = sorted(required - set(tags))
    if missing:
        raise RuntimeError(f"canonical build_libbox tags missing: {', '.join(missing)}")
    return list(dict.fromkeys(tags))


def canonical_ldflags(root: Path, version: str) -> str:
    source = root / "cmd" / "internal" / "build_shared" / "flags.go"
    text = source.read_text(encoding="utf-8")
    for token in ("constant.Version", "runtime.godebugDefault", "-checklinkname=0"):
        if token not in text:
            raise RuntimeError(f"canonical linker flags source lacks {token}: {source}")
    initializer = re.search(r"flags\s*:=\s*\[\]string\s*\{(.*?)\n\s*\}", text, re.DOTALL)
    release = re.search(r"if !debug\s*\{\s*flags = append\(flags,(.*?)\)\s*\}", text, re.DOTALL)
    if initializer is None or release is None:
        raise RuntimeError(f"unrecognized canonical LinkerFlags implementation: {source}")
    flags = []
    for line in initializer.group(1).splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        match = re.fullmatch(r'"([^"\\]*)"(?:\s*\+\s*(version))?', line)
        if match is None:
            raise RuntimeError(f"unsupported canonical linker flag expression: {line}")
        flags.append(match.group(1) + (version if match.group(2) else ""))
    flags.extend(re.findall(r'"([^"\\]*)"', release.group(1)))
    return " ".join(flags)


def ensure_dependencies(root: Path, app: Path, core: Path) -> None:
    mod_path = app / "go.mod"
    if not mod_path.is_file():
        raise RuntimeError("app/go.mod is missing")
    replaces = parse_replaces(mod_path.read_text(encoding="utf-8"))
    if replaces.get("github.com/sagernet/sing-box") != "../core":
        raise RuntimeError("app/go.mod must replace github.com/sagernet/sing-box => ../core")
    if not (core / "go.mod").is_file():
        raise RuntimeError(f"pinned core checkout is missing: {core}")
    for module, target in EXPECTED_SUBMODULES.items():
        if replaces.get(module) != target:
            raise RuntimeError(f"{module} must replace to {target}, got {replaces.get(module)!r}")
        path = (app / target).resolve()
        if not (path / "go.mod").is_file():
            raise RuntimeError(f"core submodule checkout is missing or has no go.mod: {path}")
    ryui = app / "third_party" / "ryui" / "go.mod"
    if not ryui.is_file():
        raise RuntimeError(f"RyUI checkout is missing: {ryui}")
    if "module github.com/egoist/ryui" not in ryui.read_text(encoding="utf-8"):
        raise RuntimeError("unexpected RyUI module")
    # Root go.sum is the initial cache input. tidy is intentionally performed only
    # by this CI script, never by local review commands.
    app_sum = app / "go.sum"
    root_sum = core / "go.sum"
    if not app_sum.exists() and root_sum.is_file():
        shutil.copy2(root_sum, app_sum)


def generated_mobile_init(app: Path, source_dir: Path) -> Path | None:
    go_files = sorted(source_dir.glob("*.go"))
    if not go_files:
        raise RuntimeError(f"no Go files in {source_dir}")
    all_text = go_code("\n".join(p.read_text(encoding="utf-8", errors="replace") for p in go_files))
    main_count = len(re.findall(r"\bfunc\s+main\s*\(", all_text))
    if main_count != 1:
        raise RuntimeError(f"expected exactly one app main function, found {main_count}")
    assignments = len(re.findall(r"\bmobile\.Main\s*=", all_text))
    if assignments > 1:
        raise RuntimeError(f"duplicate mobile.Main assignments in {source_dir}")
    if assignments == 1:
        if not re.search(r"\bmobile\.Main\s*=\s*main\b", all_text):
            raise RuntimeError("mobile.Main exists but is not assigned to the app main function")
        return None
    generated = source_dir / "zz_ci_ryui_main.go"
    if generated.exists():
        raise RuntimeError(f"refusing to overwrite existing generated init: {generated}")
    # Same main assignment as cmd/ryui/ios.go writeOverlay, with an Android
    # constraint so no Linux check can accidentally pick up this CI-only file.
    generated.write_text(
        "//go:build android\n\n"
        "// Code generated by app/scripts/build_android.py; DO NOT EDIT.\n"
        "package main\n\n"
        'import "github.com/egoist/ryui/mobile"\n\n'
        "func init() { mobile.Main = main }\n",
        encoding="utf-8",
        newline="\n",
    )
    return generated


def ndk_compiler(ndk: Path, compiler: str) -> Path:
    host = "linux-x86_64"
    path = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin" / compiler
    if not path.is_file():
        raise RuntimeError(f"missing pinned NDK compiler: {path}")
    return path


def build_native(root: Path, app: Path, output: Path, env: dict[str, str], version: str, tags: list[str], ldflags: str) -> dict[str, dict[str, object]]:
    ndk = Path(env.get("ANDROID_NDK_HOME", ""))
    if not (ndk / "source.properties").is_file():
        raise RuntimeError("ANDROID_NDK_HOME must point to pinned NDK 28.2.13676358")
    if not re.search(r"Pkg.Revision\s*=\s*28\.2\.13676358", (ndk / "source.properties").read_text(encoding="utf-8")):
        raise RuntimeError("ANDROID_NDK_HOME source.properties does not match NDK 28.2.13676358")
    source_dir = app / "cmd" / "lxbox"
    generated = generated_mobile_init(app, source_dir)
    results: dict[str, dict[str, object]] = {}
    try:
        for abi, (goarch, compiler, goarm) in ABIS.items():
            out = output / abi / "liblxbox.so"
            out.parent.mkdir(parents=True, exist_ok=True)
            build_env = dict(env)
            build_env.update({"GOOS": "android", "GOARCH": goarch, "CGO_ENABLED": "1", "CC": str(ndk_compiler(ndk, compiler)), "CGO_CFLAGS": "-D__ANDROID_API__=24", "CGO_LDFLAGS": "-Wl,-z,max-page-size=16384"})
            if goarm:
                build_env["GOARM"] = goarm
            graph_path = output.parent / f"go-deps-{abi}.txt"
            run(["go", "list", "-deps", "-tags", ",".join(tags), "./cmd/lxbox"], cwd=app, env=build_env, log_path=graph_path)
            graph = set(graph_path.read_text(encoding="utf-8").splitlines())
            required = {
                "github.com/Leadaxe/lxbox/app/internal/ui",
                "github.com/Leadaxe/lxbox/app/internal/runtime",
                "github.com/Leadaxe/lxbox/app/internal/core",
                "github.com/Leadaxe/lxbox/app/mobile",
                "github.com/egoist/ryui/mobile",
                "github.com/sagernet/sing-box/common/jni",
            }
            if required - graph:
                raise RuntimeError(f"unified Android dependency graph misses: {sorted(required - graph)}")
            command = [
                "go", "build", "-buildmode=c-shared", "-trimpath", "-buildvcs=false",
                "-tags", ",".join(tags), "-ldflags", ldflags, "-o", str(out), "./cmd/lxbox",
            ]
            log = output.parent / f"go-build-{abi}.log"
            run(command, cwd=app, env=build_env, log_path=log)
            data = out.read_bytes()
            if data[:4] != b"\x7fELF":
                raise RuntimeError(f"native output is not ELF: {out}")
            results[abi] = {"path": str(out), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            # Headers are diagnostics, not JNI payloads.
            out.with_suffix(".h").unlink(missing_ok=True)
            readelf = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
            nm = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"
            run([str(readelf), "-lW", str(out)], cwd=app, env=build_env, log_path=output.parent / f"elf-{abi}.txt")
            symbols_path = output.parent / f"symbols-{abi}.txt"
            run([str(nm), "-D", "--defined-only", str(out)], cwd=app, env=build_env, log_path=symbols_path)
            symbols = symbols_path.read_text(encoding="utf-8")
            if len(re.findall(r"\bJNI_OnLoad$", symbols, re.MULTILINE)) != 1 or not re.search(r"\bbox_jni_onload$", symbols, re.MULTILINE):
                raise RuntimeError(f"{abi} must define exactly one JNI_OnLoad and the core box_jni_onload")
    finally:
        if generated is not None:
            generated.unlink(missing_ok=True)
    return results


def gradle_command(host: Path) -> list[str]:
    wrapper = host / "gradlew"
    if wrapper.is_file() and os.access(wrapper, os.X_OK):
        return [str(wrapper)]
    if shutil.which("gradle"):
        return ["gradle"]
    raise RuntimeError("app/android/gradlew is absent and Gradle setup did not provide gradle")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2], help="staging workspace root containing core/ and app/")
    parser.add_argument("--app-root", type=Path, default=None)
    parser.add_argument("--core-root", type=Path, default=None)
    parser.add_argument("--artifacts", type=Path, default=None)
    args = parser.parse_args()
    root = args.root.resolve()
    app = (args.app_root or (root / "app")).resolve()
    core = (args.core_root or (root / "core")).resolve()
    host = app / "android"
    artifacts = (args.artifacts or (root / "artifacts")).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("GOTOOLCHAIN", "local")
    env.setdefault("GOFLAGS", "-buildvcs=false")
    ensure_dependencies(root, app, core)
    pins = json.loads((app / "scripts" / "dependencies.json").read_text(encoding="utf-8"))
    version = pins["core"]["version"]
    core_source = core / "cmd/internal/build_libbox/main.go"
    source_build = core_source.read_text(encoding="utf-8")
    shared_flags = set()
    for match in re.finditer(r"sharedFlags\s*=\s*append\(sharedFlags,\s*\"([^\"]+)\"\s*\)", go_code(source_build)):
        shared_flags.add(match.group(1))
    if not {"-trimpath", "-buildvcs=false"}.issubset(shared_flags):
        raise RuntimeError("canonical build_libbox shared flags changed; review c-shared build arguments")
    tags = canonical_tags(core)
    ldflags = canonical_ldflags(core, version)
    native_dir = host / "app" / "src" / "main" / "jniLibs"
    results = build_native(core, app, native_dir, env, version, tags, ldflags)
    gradle = gradle_command(host)
    gradle_env = dict(env)
    gradle_env.update({"ANDROID_COMPILE_SDK": "37", "ANDROID_TARGET_SDK": "36", "ANDROID_MIN_SDK": "24", "ANDROID_NDK_VERSION": "28.2.13676358"})
    gradle_args = [":app:assembleDebug", "--stacktrace", "--console=plain", "--no-daemon"]
    run(gradle + gradle_args, cwd=host, env=gradle_env, log_path=artifacts / "gradle-build.log")
    lint_rc = run(gradle + [":app:lintDebug", "--stacktrace", "--console=plain", "--no-daemon"], cwd=host, env=gradle_env, log_path=artifacts / "lint.log", check=False)
    dep_rc = run(gradle + [":app:dependencies", "--configuration", "debugRuntimeClasspath", "--console=plain", "--no-daemon"], cwd=host, env=gradle_env, log_path=artifacts / "gradle-dependency-graph.txt", check=False)
    apk_candidates = sorted((host / "app" / "build" / "outputs" / "apk").glob("**/*.apk"))
    if not apk_candidates:
        raise RuntimeError("assembleDebug produced no APK")
    apk = apk_candidates[0]
    shutil.copy2(apk, artifacts / "lxbox-debug.apk")
    aapt = Path(env.get("ANDROID_HOME", "")) / "build-tools" / "36.0.0" / "aapt"
    if aapt.is_file():
        run([str(aapt), "dump", "badging", str(apk)], cwd=root, env=env, log_path=artifacts / "manifest.txt", check=False)
    manifest = {
        "version": version,
        "min_sdk": 24,
        "compile_sdk": 37,
        "target_sdk": 36,
        "ndk": "28.2.13676358",
        "go": "1.26.10",
        "java": "17",
        "abis": list(ABIS),
        "tags": tags,
        "ldflags": ldflags,
        "native": results,
        "lint_exit_code": lint_rc,
        "gradle_dependency_exit_code": dep_rc,
        "runtime_verified": False,
        "dart_migration_claim": False,
    }
    (artifacts / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (artifacts / "lint-status.json").write_text(json.dumps({"status": "passed" if lint_rc == 0 else "failed", "exit_code": lint_rc, "runtime_compatibility_verified": False}, indent=2) + "\n", encoding="utf-8")
    (artifacts / "version.txt").write_text(version + "\n", encoding="utf-8")
    return 1 if lint_rc or dep_rc else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"build_android.py: {exc}", file=sys.stderr)
        raise SystemExit(1)
