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
6. 使用 core commit 自带的 gitlinks 初始化四个 submodules；不由 app workflow 独立指定或覆盖 fork SHA。
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

本次在独立 app 仓库上执行了 Python-only 静态检查：

- 初始抽取阶段 `D:\\go\\bin\\gofmt.exe -w` 格式化 102 个 app Go 文件，随后 `gofmt -d` 退出码为 0；本轮修复涉及的 Go 文件也已重新格式化并确认无差异。
- Python 脚本单元测试（2 tests）与 `compileall` 通过。
- 独立布局 source-only migration 检查通过；外部 RyUI 和 core submodule checkout 在本机未完成，属于预期 warning。
- `ci_go_checks.py` 因本地 staging workspace 缺失 Actions checkout 的外部依赖，在 Go 检查前置依赖验证处停止；本机未执行 Go 编译/测试/vet。

## 本轮 Actions 编译错误跟进

已修复 app 侧 parser registry 重名、mapper helper 与变量作用域、storage `loaded` 字段、workspace `model` 导入、automation 未使用变量、ruleset 测试返回值，以及 transfer plaintext base64/原文兼容问题。

wireguard-go、sing-tun、gvisor、utls 子模块由固定 core commit 的 gitlinks 决定，workflow 使用递归 submodule 初始化，不由 app 独立 pin 或覆盖。实际 submodule SHA 以 `core-submodules.txt` 为准。

最新 Actions 已通过 parser 编译；Go 纯测试仍在 contract URI golden 阶段失败。本轮定位到两处根因并修复：

- 语料 `entry` 按契约不含 `tag`（标签在 `label` 字段），测试此前直接比较带 `tag` 的 `Emit`，造成大面积假失败；测试现先移除 `tag`/`detour` 再比较，与 Dart 侧 `_canonEntryMap` 一致。
- mapper 执行器补齐了注册表声明的通用能力：`forms` 形态解码（v2rayN/base64 legacy/SIP002/wrapped）、选择器优先的两遍求值、`defaults`/`scheme_sets`（含 `*` 与 `$default_port`）、`materialize_default`、`on_invalid` 全部动作、`extract`/`split_into`、`merge`、`list`、`value_map.$ref` 前缀表、`normalize` 取值归一化，以及 `body.fields` 的 required/enum/format/pattern/item_pattern/min/max/requires/conflicts/absent_when/forbidden_for/advisory/coerce_when 清洗与降级。布尔 `false` 不再被误判为空值。

最新 Actions 已通过 parser 编译，golden 阶段暴露出 mapper 计划跳过 `params` 节点的回归，导致 server、端口、userinfo、TLS、transport 和协议参数全部丢失；现已恢复 `params` 递归收集，并同步修复 `applyMapperExtract` 签名与 parser 辅助函数段。

最新 Actions 又暴露了两个确定性错误：`dns_records.go` 默认 preset 分支的 `record` 作用域错误，以及 HTTP/AnyTLS userinfo 单段密码读取 `parts[1]` 造成 runtime panic；两处均已修复。

本地重新执行 gofmt、Python 单测、`compileall` 与 `check_migration.py --source-only` 均通过，未运行 Go 编译/测试、Gradle、NDK 或 Actions。

仍未运行：

- Go 编译、Go 测试、Go vet
- Gradle、NDK、Android SDK build
- Git 提交/推送
- GitHub Actions
- Android 设备或模拟器

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