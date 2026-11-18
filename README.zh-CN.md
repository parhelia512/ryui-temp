# LxBox RyUI 独立 Android 应用

本目录是从 `sing-box-lx` 工作树抽取出的独立应用仓库。它包含 RyUI Go UI、LxBox Go 应用层、Android Host、JNI bridge、资源、测试语料和 GitHub Actions；不包含 sing-box-lx 内核、四个 fork 子模块或 RyUI vendor 源码。

## 构建布局

GitHub Actions 构建时创建临时 staging workspace：

```text
workspace/
  core/       # 固定提交的 sing-box-lx clone
  app/        # 本仓库 checkout
  artifacts/
```

`app/go.mod` 通过 `../core` 和 `../core/submodules/*` 引用内核与 fork。RyUI 由 Actions 固定 checkout 到 `app/third_party/ryui`。

## Core patch

`patches/sing-box-lx-core.patch` 是唯一由应用仓库提供的内核 patch。它把内核 Android JNI 初始化函数从 `JNI_OnLoad` 改名为 `box_jni_onload`；RyUI 的唯一 `JNI_OnLoad` 显式调用该函数，避免最终 `liblxbox.so` 中出现两个 JNI 入口。

Actions 会先执行：

```text
git -C core apply --check ../app/patches/sing-box-lx-core.patch
git -C core apply ../app/patches/sing-box-lx-core.patch
```

上下文不匹配时构建立即失败，不会静默跳过。应用 patch 之外的 sing-box-lx 下游代码由固定 core 提交本身提供；四个 fork 也按 `scripts/dependencies.json` 的 SHA checkout。

## Actions

工作流：`.github/workflows/lxbox-ryui-android.yml`

手动运行时可输入：

- `core_repository`：默认 `Leadaxe/sing-box-lx`。
- `core_commit`：默认固定 SHA `f8e9156a1714d20f09889cc406e9f766dc4d5c47`，对应 `1.14.4-lx.33`。不要改成移动分支。

工作流使用 Go 1.26.10、JDK 17、NDK 28.2.13676358、compile SDK 37.0、target SDK 36、min API 24，并构建 arm64-v8a、armeabi-v7a、x86_64 三个 ABI。它不会启动设备或模拟器。

## 本地约束

本项目交付前只做 Python AST、YAML、JSON、XML、Go/Kotlin tree-sitter 静态检查；没有在本机运行 Go、gofmt、Gradle、NDK、Git 或 GitHub Actions。只有 Actions 成功后才能称为 APK 编译通过；只有 API 24 设备和较新 Android 设备完成测试后，才能称为运行兼容。

## 功能状态

迁移实现和差异详见：

- `reports/final-migration-review.zh-CN.md`
- `reports/functionality-review.json`
- `artifacts/static-delivery.json`

新 app 已清除 Dart/Flutter 运行依赖，但原 LxBox Dart 工程仍作为行为基线保留在外部目录。复杂 portable backup 语义、部分 DNS/rule/preset 语义、完整旧系统入口、部分统计/测速/高级编辑流程仍在最终报告中明确列出，不能因为 APK 能打包就宣称完全等价。
