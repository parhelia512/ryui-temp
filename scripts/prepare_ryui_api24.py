#!/usr/bin/env python3
"""Apply generic RyUI API 24 build backports without gallery-specific code.

This script never invokes Go, Gradle, Git, an emulator, or a device. It edits only
an isolated checkout supplied by CI and writes an auditable patch report.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path


ANDROID_MIN_RE = re.compile(r"(androidMinAPI\s*=\s*\")33(\")")
MIN_SDK_RE = re.compile(r"(minSdk(?:Version)?\s*[=: ]\s*)33(\b)")


def collect_android_diagnostics(source: Path) -> tuple[list[str], list[dict[str, str]]]:
    android = source / "platform/android"
    if not android.is_dir():
        raise RuntimeError(f"missing Android host source: {android}")
    min_sdk_hits = []
    api_hits = []
    for path in sorted(android.rglob("*.kt")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\b(?:LocaleManager|LocaleList|NotificationChannel|RuntimeShader)\b", text):
            api_hits.append({"file": path.relative_to(source).as_posix(), "token": match.group(0)})
    for path in sorted(android.rglob("*.gradle*")):
        if path.is_dir():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"minSdk(?:Version)?\s*[=: ]\s*33\b", text):
            min_sdk_hits.append(path.relative_to(source).as_posix())
    return min_sdk_hits, api_hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--core-root", type=Path, default=None)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    core = (args.core_root or (source.parents[2] / "core")).resolve()
    if not (source / "go.mod").is_file():
        raise SystemExit(f"RyUI checkout has no go.mod: {source}")
    go_mod = (source / "go.mod").read_text(encoding="utf-8")
    if not re.search(r"^module github.com/egoist/ryui$", go_mod, re.MULTILINE):
        raise SystemExit("unexpected RyUI module; refusing to patch another project")

    before: dict[Path, str] = {}
    changed: dict[Path, str] = {}

    def current(path: Path) -> str:
        return changed[path] if path in changed else path.read_text(encoding="utf-8")

    def edit(path: Path, transform) -> None:
        old = current(path)
        new = transform(old)
        if new != old:
            before.setdefault(path, old)
            changed[path] = new

    def exact(path: Path, old: str, new: str) -> None:
        text = current(path)
        if text.count(old) != 1:
            raise RuntimeError(f"{path}: expected exactly one patch context: {old!r}")
        edit(path, lambda value: value.replace(old, new, 1))

    # Only the upstream host library modules are backported. No example app or
    # gallery source is selected, copied, or patched.
    gradles = sorted((source / "platform/android").glob("*/build.gradle.kts"))
    if len(gradles) != 10:
        raise RuntimeError(f"expected 10 pinned RyUI Android module Gradle files, found {len(gradles)}")
    for path in gradles:
        exact(path, "minSdk = 33", "minSdk = 24")
        exact(path, '    id("org.jetbrains.kotlin.android")\n', "")

    native_kotlin = source / "platform/android/ryui/src/main/java/dev/ryui/RyUINative.kt"
    if not native_kotlin.is_file():
        candidates = list((source / "platform/android").rglob("RyUINative.kt"))
        if len(candidates) != 1:
            raise RuntimeError(f"expected one RyUINative.kt, found {len(candidates)}")
        native_kotlin = candidates[0]
    exact(native_kotlin, 'System.loadLibrary("ryui")', 'System.loadLibrary("lxbox")')
    # Production loading must not accidentally select a stale development player.
    # The filename is kept consistent even though the workflow never deploys it.
    native_text = current(native_kotlin)
    if "libryui.so" in native_text:
        edit(native_kotlin, lambda text: text.replace("libryui.so", "liblxbox.so"))

    # The core JNI rename is owned by patches/sing-box-lx-core.patch and is verified here only.
    kernel = core / "common/jni/jni_android.c"
    if not kernel.is_file():
        raise RuntimeError(f"missing core JNI source: {kernel}")
    kernel_text = kernel.read_text(encoding="utf-8")
    if "box_jni_onload" not in kernel_text or "JNI_OnLoad" in kernel_text:
        raise RuntimeError("core JNI patch is not applied: expected box_jni_onload without JNI_OnLoad")

    # RyUI remains responsible for the single exported JNI_OnLoad and calls the core initializer.
    ryui_jni = source / "mobile/jni_android.c"
    exact(ryui_jni,
          "JNIEXPORT jint JNI_OnLoad(JavaVM *v, void *reserved) {\n\tvm = v;\n\treturn JNI_VERSION_1_6;\n}",
          "extern jint box_jni_onload(JavaVM *vm, void *reserved);\n\n"
          "JNIEXPORT jint JNI_OnLoad(JavaVM *v, void *reserved) {\n"
          "\tif (box_jni_onload(v, reserved) < 0) return JNI_ERR;\n"
          "\tvm = v;\n\treturn JNI_VERSION_1_6;\n}")

    android_go = source / "cmd" / "ryui" / "android.go"
    exact(android_go, 'const androidMinAPI = "33"', 'const androidMinAPI = "24"')

    # API 24 compatibility shims shared by the upstream Android host. Each edit is
    # context-checked and is deliberately independent because source layouts can move.
    replacements = {
        "Locale.kt": (
            "app.getSystemService(android.app.LocaleManager::class.java)?.systemLocales",
            "if (android.os.Build.VERSION.SDK_INT >= 33) {\n"
            "            app.getSystemService(android.app.LocaleManager::class.java)?.systemLocales\n"
            "        } else null",
        ),
        "applicationLocales =": (
            "app.getSystemService(android.app.LocaleManager::class.java)?.applicationLocales =\n"
            "            if (tag.isEmpty()) android.os.LocaleList.getEmptyLocaleList() else android.os.LocaleList.forLanguageTags(tag)",
            "if (android.os.Build.VERSION.SDK_INT >= 33) {\n"
            "            app.getSystemService(android.app.LocaleManager::class.java)?.applicationLocales =\n"
            "                if (tag.isEmpty()) android.os.LocaleList.getEmptyLocaleList() else android.os.LocaleList.forLanguageTags(tag)\n"
            "        } else {\n"
            "            androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(\n"
            "                androidx.core.os.LocaleListCompat.forLanguageTags(tag))\n"
            "        }",
        ),
    }
    kotlin_root = source / "platform/android/ryui/src/main/java/dev/ryui"
    locale_old, locale_new = replacements["Locale.kt"]
    exact(kotlin_root / "Locale.kt", locale_old, locale_new)
    app_locale_old, app_locale_new = replacements["applicationLocales ="]
    exact(kotlin_root / "RyUIRuntime.kt", app_locale_old, app_locale_new)
    for name in ("RyUIActivity.kt", "Navigation.kt"):
        owner = "runtime.app" if name == "RyUIActivity.kt" else "app"
        exact(
            kotlin_root / name,
            "reduceMotion = !android.animation.ValueAnimator.areAnimatorsEnabled()",
            "reduceMotion = if (android.os.Build.VERSION.SDK_INT >= 26) {\n"
            "            !android.animation.ValueAnimator.areAnimatorsEnabled()\n"
            "        } else {\n"
            "            android.provider.Settings.Global.getFloat(\n"
            f"                {owner}.contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f\n"
            "        }",
        )
    exact(
        kotlin_root / "Automation.kt",
        "        app.registerReceiver(r, f, Context.RECEIVER_EXPORTED)",
        "        androidx.core.content.ContextCompat.registerReceiver(\n"
        "            app, r, f, androidx.core.content.ContextCompat.RECEIVER_EXPORTED)",
    )

    output.mkdir(parents=True, exist_ok=True)
    patch_lines: list[str] = []
    for path, old in before.items():
        new = changed[path]
        rel = path.relative_to(source).as_posix()
        patch_lines.extend(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile="a/" + rel,
                tofile="b/" + rel,
            )
        )
    (output / "api24.patch").write_text("".join(patch_lines), encoding="utf-8")
    # All contexts have matched before any source file is changed.
    for path, text in changed.items():
        path.write_text(text, encoding="utf-8", newline="\n")

    min_sdk_hits, api33_hits = collect_android_diagnostics(source)

    report = {
        "source": "github.com/egoist/ryui",
        "api24": {"min_sdk": 24, "runtime_verified": False},
        "modified_files": [path.relative_to(source).as_posix() for path in changed],
        "native_library": "liblxbox.so",
        "jni_entrypoint": "RyUI JNI_OnLoad calls box_jni_onload; core JNI_OnLoad renamed with exact context",
        "modified_file_count": len(changed),
        "remaining_min_sdk_33": min_sdk_hits,
        "new_api_tokens_for_lint_review": api33_hits,
        "gallery_specific_code": "not selected or copied",
        "known_runtime_limits": [
            "Packaging at minSdk 24 is not proof of runtime compatibility.",
            "RuntimeShader and any remaining NewApi findings require lint review and device testing.",
            "No gallery example or gallery asset is used by this app workflow.",
        ],
    }
    (output / "api24.patch-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
