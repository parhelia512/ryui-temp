package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The upstream development command installs and launches on a device.
func init() {
	if os.Getenv("RYUI_CI_API24") != "1" {
		return
	}
	if err := buildCIAPI24(); err != nil {
		fmt.Fprintln(os.Stderr, "API 24 build:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func buildCIAPI24() error {
	app, err := loadApp("examples/gallery")
	if err != nil {
		return err
	}
	tc, err := newAndroidToolchain(true)
	if err != nil {
		return err
	}
	ndk := os.Getenv("ANDROID_NDK_HOME")
	if ndk == "" {
		return fmt.Errorf("ANDROID_NDK_HOME must name the pinned NDK")
	}
	tc.ndk = ndk
	tc.ndkBin = filepath.Join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
	if !exists(filepath.Join(tc.ndkBin, "aarch64-linux-android24-clang")) {
		return fmt.Errorf("missing API 24 NDK compiler in %s", tc.ndkBin)
	}
	work, err := workDir(app, "android-ci-api24")
	if err != nil {
		return err
	}
	jni, err := buildAndroidLibs(app, tc, work)
	if err != nil {
		return err
	}
	res := filepath.Join(work, "res")
	os.RemoveAll(res)
	iconDir := filepath.Join(res, "drawable")
	if err := os.MkdirAll(iconDir, 0o755); err != nil {
		return err
	}
	iconXML := `<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="48dp" android:height="48dp" android:viewportWidth="48" android:viewportHeight="48">
    <path android:fillColor="#6750A4" android:pathData="M0,0h48v48h-48z" />
    <path android:fillColor="#FFFFFF" android:pathData="M13,12h22v4h-22zM13,22h22v4h-22zM13,32h16v4h-16z" />
</vector>
`
	if err := os.WriteFile(filepath.Join(iconDir, "ci_launcher.xml"), []byte(iconXML), 0o644); err != nil {
		return err
	}
	if _, err := androidRes(app.cfg, res); err != nil {
		return err
	}
	manifest := filepath.Join(work, "AndroidManifest.xml")
	manifestContent := strings.ReplaceAll(app.cfg.androidManifest(true), "${ryuiIcon}", "@drawable/ci_launcher")
	if err := os.WriteFile(manifest, []byte(manifestContent), 0o644); err != nil {
		return err
	}
	unlock, err := lockShared(androidHostDir(work))
	if err != nil {
		return err
	}
	defer unlock()
	src, _, err := prepareAndroidHost(app, work)
	if err != nil {
		return err
	}
	args := []string{":app:assembleDebug", "--stacktrace", "--console=plain",
		"-PryuiApplicationId=" + androidPackage(app.cfg.ID),
		"-PryuiAppName=" + app.cfg.androidLabel(),
		"-PryuiVersionCode=" + strconv.Itoa(app.cfg.Build),
		"-PryuiVersionName=" + app.cfg.Version,
		"-PryuiJniLibs=" + jni,
		"-PryuiManifest=" + manifest,
		"-PryuiRes=" + res,
		"-PryuiNdkVersion=" + filepath.Base(ndk), app.cfg.gradleModules()}
	if assets := filepath.Join(app.dir, "assets"); exists(assets) {
		args = append(args, "-PryuiAssets="+assets)
	}
	out := os.Getenv("RYUI_CI_OUTPUT")
	if out == "" {
		return fmt.Errorf("RYUI_CI_OUTPUT must be set")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "host-path.txt"), []byte(src+"\n"), 0o644); err != nil {
		return err
	}
	if err := tc.gradle(src, args...); err != nil {
		return err
	}
	apk, err := os.ReadFile(filepath.Join(src, "app", "build", "outputs", "apk", "debug", "app-debug.apk"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "ryui-gallery-api24-debug.apk"), apk, 0o644); err != nil {
		return err
	}
	// NewApi findings remain a separate diagnostic, not evidence of runtime support.
	lintArgs := append([]string(nil), args...)
	lintArgs[0] = ":app:lintDebug"
	lintErr := tc.gradle(src, lintArgs...)
	lintStatus := "passed\n"
	if lintErr != nil {
		lintStatus = lintErr.Error() + "\n"
		fmt.Fprintln(os.Stderr, "Compatibility lint:", lintErr)
	}
	return os.WriteFile(filepath.Join(out, "lint-status.txt"), []byte(lintStatus), 0o644)
}
