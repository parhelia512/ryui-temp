# 独立仓库抽取交付说明

独立应用目录：

```text
D:\sing-box-app\lxbox-ryui-app
```

原内核目录 `D:\sing-box-app\sing-box-lx-1.14.4-lx.33\app` 已移除。应用源码不再作为 sing-box-lx 工作树中的子目录维护。

## 新的仓库关系

独立 app 仓库自身包含：

- `go.mod`
- `cmd/`
- `internal/`
- `mobile/`
- `android/`
- `assets/`
- `testdata/contract/`
- `scripts/`
- `.github/workflows/lxbox-ryui-android.yml`
- `patches/sing-box-lx-core.patch`
- `README.zh-CN.md`

它不包含：

- sing-box-lx 内核源码
- 四个 fork 子模块源码
- RyUI vendor 源码
- native build output、APK、AAB 或 JNI library

`app/go.mod` 的 replace 指向 Actions staging workspace 中的 `../core` 和 `../core/submodules/*`。RyUI 仍由 workflow checkout 到 `app/third_party/ryui`。

## Actions staging 流程

工作流运行时布局为：

```text
$GITHUB_WORKSPACE/
  app/        # 当前独立 app checkout
  core/       # 固定 sing-box-lx commit clone
  artifacts/
```

流程顺序：

1. checkout 独立 app 到 `app/`。
2. clone `core_repository` 到 `core/`。
3. detached checkout 固定 `core_commit`。
4. `git -C core apply --check ../app/patches/sing-box-lx-core.patch`。
5. 应用 patch。
6. 在 `core/submodules/` checkout 四个固定 fork SHA。
7. 在 `app/third_party/ryui` checkout 固定 RyUI SHA。
8. 运行 app scripts，脚本显式接收 `--app-root app --core-root core`。
9. 产出统一 `liblxbox.so` 和 APK 诊断 artifacts。

默认 core commit 为解析后的 tag commit：

```text
2d9a0a52df7881f55484d48f9daecb21d135f3e9
```

不要将 workflow 输入改为移动分支。

## Patch 内容

`patches/sing-box-lx-core.patch` 只改：

```text
common/jni/jni_android.c: JNI_OnLoad -> box_jni_onload
```

它与 RyUI 的唯一 JNI_OnLoad 配合，避免最终统一 native library 中出现两个 JNI 入口。RyUI API 24 backport 仍由 `prepare_ryui_api24.py` 对干净 RyUI checkout 执行，不混进 core patch。

## 本地验证限制

本次只执行 Python AST、tree-sitter、YAML/JSON/XML 和 source-only 静态检查；未运行：

- Go、gofmt、staticcheck
- Gradle、NDK、Android SDK build
- Git 提交/推送
- GitHub Actions
- Android 设备或模拟器

source-only 检查、Python 脚本语法检查和独立布局检查通过。缺少外部 checkout 的提示是预期结果，实际 checkout 只在 Actions 中执行。

## 运行 Actions

在独立 app 仓库中打开：

```text
Actions → LxBox RyUI Android manual build → Run workflow
```

保持默认 `core_repository` 与固定 `core_commit`，下载 artifact 后查看：

- `migration-report.json`
- `go-checks.log`
- `go-pure-tests.log`
- `go-pure-vet.log`
- `api24.patch-report.json`
- `apk-verification.json`
- `lint-status.json`
- `elf-*.txt`
- `symbols-*.txt`
- `core-commit.txt`
- `dependencies.json`

只有 Actions 构建成功后才能报告 APK 编译通过；只有 API 24 与较新 Android 实机完成运行验证后，才能报告 API 24 兼容。