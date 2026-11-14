import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_ryui_api24 import collect_android_diagnostics


class AndroidDiagnosticsTests(unittest.TestCase):
    def test_benchmark_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            host = source / "platform/android/ryui"
            host.mkdir(parents=True)
            (host / "Runtime.kt").write_text("val shader: RuntimeShader", encoding="utf-8")
            (host / "build.gradle.kts").write_text("minSdk = 33", encoding="utf-8")
            (host / "cache.gradle").mkdir()
            benchmark = source / "bench/compose/Meter.kt"
            benchmark.parent.mkdir(parents=True)
            benchmark.write_text("benchmark symlink placeholder", encoding="utf-8")
            read_text = Path.read_text

            def guarded_read(path, *args, **kwargs):
                if path == benchmark:
                    raise FileNotFoundError("broken benchmark symlink")
                return read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", guarded_read):
                min_sdk, api = collect_android_diagnostics(source)
            self.assertEqual(min_sdk, ["platform/android/ryui/build.gradle.kts"])
            self.assertEqual(api, [{"file": "platform/android/ryui/Runtime.kt", "token": "RuntimeShader"}])

    def test_missing_host_input_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            host = source / "platform/android/ryui"
            host.mkdir(parents=True)
            missing = host / "Runtime.kt"
            missing.write_text("placeholder", encoding="utf-8")
            read_text = Path.read_text

            def broken_read(path, *args, **kwargs):
                if path == missing:
                    raise FileNotFoundError("broken Android host input")
                return read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", broken_read):
                with self.assertRaises(FileNotFoundError):
                    collect_android_diagnostics(source)


if __name__ == "__main__":
    unittest.main()
