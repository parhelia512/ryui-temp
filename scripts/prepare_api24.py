#!/usr/bin/env python3
"""Apply context-checked build changes to an isolated RyUI source tree."""

import argparse
import difflib
import json
from pathlib import Path


def patch_tree(root: Path, output: Path) -> None:
    edits = {}

    def replace(relative: str, old: str, new: str, count: int = 1) -> None:
        path = root / relative
        original, current = edits.get(path, (path.read_text(encoding="utf-8"), None))
        if current is None:
            current = original
        actual = current.count(old)
        if actual != count:
            raise RuntimeError(f"{relative}: expected {count} matching context(s), got {actual}")
        edits[path] = (original, current.replace(old, new))

    gradles = sorted((root / "platform/android").glob("*/build.gradle.kts"))
    if len(gradles) != 10:
        raise RuntimeError(f"Expected 10 Android module Gradle files, found {len(gradles)}")
    for path in gradles:
        relative = path.relative_to(root).as_posix()
        replace(relative, "minSdk = 33", "minSdk = 24")
    replace(
        "platform/android/app/build.gradle.kts",
        '        getByName("debug") {\n',
        '        getByName("debug") {\n'
        '            prop("ryuiJniLibs")?.let { jniLibs.srcDir(it) }\n'
        '            prop("ryuiAssets")?.let { assets.srcDir(it) }\n',
    )
    replace("cmd/ryui/android.go", 'const androidMinAPI = "33"', 'const androidMinAPI = "24"')

    kotlin = "platform/android/ryui/src/main/java/dev/ryui/"
    replace(
        kotlin + "Locale.kt",
        "    val list = app.getSystemService(android.app.LocaleManager::class.java)?.systemLocales",
        "    val list = if (android.os.Build.VERSION.SDK_INT >= 33) {\n"
        "        app.getSystemService(android.app.LocaleManager::class.java)?.systemLocales\n"
        "    } else null",
    )
    replace(
        kotlin + "RyUIRuntime.kt",
        "        app.getSystemService(android.app.LocaleManager::class.java)?.applicationLocales =\n"
        "            if (tag.isEmpty()) android.os.LocaleList.getEmptyLocaleList() else android.os.LocaleList.forLanguageTags(tag)",
        "        if (android.os.Build.VERSION.SDK_INT >= 33) {\n"
        "            app.getSystemService(android.app.LocaleManager::class.java)?.applicationLocales =\n"
        "                if (tag.isEmpty()) android.os.LocaleList.getEmptyLocaleList() else android.os.LocaleList.forLanguageTags(tag)\n"
        "        } else {\n"
        "            androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(\n"
        "                androidx.core.os.LocaleListCompat.forLanguageTags(tag))\n"
        "        }",
    )
    for name in ("RyUIActivity.kt", "Navigation.kt"):
        replace(
            kotlin + name,
            "!android.animation.ValueAnimator.areAnimatorsEnabled()",
            "        reduceMotion = if (android.os.Build.VERSION.SDK_INT >= 26) {\n"
            "            !android.animation.ValueAnimator.areAnimatorsEnabled()\n"
            "        } else {\n"
            "            android.provider.Settings.Global.getFloat(\n"
            "                runtime.app.contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f\n"
            "        }," if name == "RyUIActivity.kt" else
            "        reduceMotion = if (android.os.Build.VERSION.SDK_INT >= 26) {\n"
            "            !android.animation.ValueAnimator.areAnimatorsEnabled()\n"
            "        } else {\n"
            "            android.provider.Settings.Global.getFloat(\n"
            "                app.contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f\n"
            "        },",
        )
    replace(
        kotlin + "Automation.kt",
        "        app.registerReceiver(r, f, Context.RECEIVER_EXPORTED)",
        "        androidx.core.content.ContextCompat.registerReceiver(\n"
        "            app, r, f, androidx.core.content.ContextCompat.RECEIVER_EXPORTED)",
    )

    helper = root / "cmd/ryui/ci_api24.go"
    if helper.exists():
        raise RuntimeError("Refusing to overwrite an existing cmd/ryui/ci_api24.go")
    helper_text = Path(__file__).with_name("ci_api24.go").read_text(encoding="utf-8")
    edits[helper] = ("", helper_text)
    patches = []
    for path, (before, after) in edits.items():
        relative = path.relative_to(root).as_posix()
        patches.extend(difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True),
            fromfile="a/" + relative, tofile="b/" + relative,
        ))
    output.mkdir(parents=True, exist_ok=True)
    (output / "api24.patch").write_text("".join(patches), encoding="utf-8")
    for path, (_, after) in edits.items():
        path.write_text(after, encoding="utf-8", newline="\n")
    report = {
        "min_sdk": 24,
        "ndk_api": 24,
        "example": "examples/gallery",
        "modified_files": [p.relative_to(root).as_posix() for p in edits],
        "runtime_verified": False,
        "known_runtime_limits": [
            "RuntimeShader is API 33+. The gallery shader demo is retained unchanged and is not backported.",
            "NotificationChannel calls and other NewApi findings need device testing and further backports.",
            "This experiment builds the complete gallery; successful packaging is not full API 24 support.",
        ],
    }
    (output / "patch-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Applied {len(edits)} context-checked edits; gallery Go source unchanged")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patch_tree(args.source.resolve(), args.output.resolve())
