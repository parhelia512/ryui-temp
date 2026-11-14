# RyUI + sing-box-lx 迁移实施报告

日期：2026-11-14

## 交付范围

本次在 `sing-box-lx-1.14.4-lx.33/app` 建立了独立 Go 应用模块 `github.com/Leadaxe/lxbox/app`，目标结构为：

- RyUI Go UI：`internal/ui`、`cmd/lxbox`。
- LxBox Go 应用层：`internal/runtime`、`internal/storage`、`internal/parser`、`internal/builder`、`internal/backup`、`internal/automation`、`internal/debugapi`、`internal/ruleset`、`internal/transfer`、`internal/diagnostics`、`internal/warp`。
- sing-box-lx Go 内核：`internal/core` 直接调用 `experimental/libbox`，不依赖 `libbox.aar`。
- Android Host：`android/app/src/main/kotlin/com/leadaxe/lxbox/android`，负责 VpnService/TUN、物理网络、DNS、通知、权限、SAF、文件流、OpenConnect 回调、应用信息和原生偏好。
- JNI：`mobile`，统一 `NativeBridge` 与 Go runtime，目标 native 库为 `liblxbox.so`。
- 非 Dart 资源：`assets`，包括模板、语言包、契约 registry、WARP endpoint 数据和图标；契约语料复制到 `testdata/contract`。

批准的计划已保存于：

- `LxBox-2.25.21/docs/migration/ryui-sing-box-lx-full-migration-plan.zh-CN.md`
- `sing-box-lx-1.14.4-lx.33/app/docs/migration-plan.zh-CN.md`

## 已实现并通过静态检查的部分

### 应用模块和资源

- `app/go.mod` 使用 Go 1.26，保留 sing-box-lx、RyUI 和四个 fork 的本地 replace。
- 复制了 2,110 个契约语料文件和 57 个非 Dart 资源文件。
- `assets/embed.go` 提供 `assets.FS` 与 `assets.Read`。
- `lxbox_settings.json`、workspace manifest、缓存、备份、未来版本只读保护、显式 legacy migration、未知字段保留和原子写入均有 Go 实现。
- 订阅缓存写入受 workspace generation 和 revision 保护；构建不联网，只读本地缓存。

### 解析、配置和节点工作流

- `parser.Parse/ParseString/ParseBytes`、`parser.Emit`、`Node.SingBox` 已建立。
- 支持 JSON、YAML、URI、base64、Clash/Sing-box/Xray 基础文档、SS、VMess、VLESS、Trojan、Hysteria/Hysteria2、TUIC、SOCKS、HTTP、AnyTLS、WireGuard、AmneziaWG 基础形态。
- 解析器保留原始节点和 source 元数据，`UseNumber` 保留大整数，WireGuard endpoint 使用 `endpoints`。
- 已加入 contract mapper 基础执行、URI/Xray mapper、shared blocks、条件/defaults/coercion、Clash YAML 和 corpus harness。
- builder 仅展开 `wizard_template.json` 的 `config`，使用真实模板生成默认 TUN、DNS、route、outbounds 和方向；不把模板元数据直接写入 sing-box config。
- builder 支持离线节点、source tag、detour、folder/chain/auto 的基础处理、规则集缓存和严格诊断；未知或无法保真的语义显式 fatal，避免静默丢数据。
- `ProbeCandidate` 使用独立、不监听 command socket 的 libbox CommandServer 和候选配置，不读取当前运行服务 tag；候选配置会拒绝 listeners、services、persistent cache 等不安全字段。
- Taildrop 使用 libbox chunk API 和 Android file handle/chunk API，默认块大小不超过 64 KiB；取消时关闭 session 和文件句柄。

### RyUI 和应用调度

- 主导航包含 VPN、Servers、Config、Routing、DNS、Connections、Logs、Statistics、Diagnostics、Tailscale、Taildrop、OpenConnect、WARP、Settings、Automation、Workspaces、Backup、Advanced 等页面。
- UI 请求通过 `runtime.Dispatch`，后台工作在 goroutine 执行，结果通过 `ui.Post` 回到主线程。
- 每个页面 scope 使用 `client_id/session_id`，退出时调用 `ccDisposeClient`。
- 订阅 CRUD、离线刷新、URL 去重、重试/退避、自动更新、导入向导、QR 相机、SAF、应用选择器、备份预览、报告读取/脱敏分享、pprof/memory、WARP 注册、诊断和 LAN transfer 已建立入口。
- 语言包保留中文/俄语值，英文 source key 作为 fallback；主题和原生偏好通过 Go storage 与 Android Host 同步。

### 核心、Android 和 JNI

- `core.Controller` 提供 Start/Reload/Stop/Close/Status/Call。
- CommandClient status/logs/groups/outbounds/connections/DNS 流有 scope snapshot 和事件投递；事件进入 Go event log，UI 通过 `events.poll` 重同步。
- WG/Tailscale/OpenConnect 状态中的私有迭代器已显式展开为 JSON。
- Local DNS 使用 Android underlying physical network，支持 lookup/raw exchange、rcode/errno、取消和超时；不会用全局 `InetAddress` 造成 TUN DNS recursion。
- TUN fd 所有权明确：Host 保留原始 descriptor，内核使用自身 dup/关闭路径。
- JNI 类名固定为 `com.leadaxe.lxbox.android.NativeBridge`，方法为 `nativeBootstrap(String, Host)` 和 `nativeAppCall(String, String)`；结果使用 `{ok,data,error}` envelope，失败保留 data。
- RyUI 保留唯一 `JNI_OnLoad`，CI 在干净 checkout 中将内核 `JNI_OnLoad` 改为显式 `box_jni_onload` 并由 RyUI 入口调用。

### GitHub Actions

工作流：`.github/workflows/lxbox-ryui-android.yml`

- 仅 `workflow_dispatch`。
- 固定 RyUI：`5cb5e808f220e8c903f2c7cb64ad6d52281c9349`。
- core 的四个 fork submodule 不再由 app workflow 独立 pin 或覆盖；Actions 使用固定 core commit 的 gitlinks，通过 `git clone --recurse-submodules` 和 `git submodule update --init --recursive` 获取，实际子模块 SHA 由该 core commit 决定。
- Go 1.26.10、JDK 17、NDK 28.2.13676358、compile SDK 37.0、target SDK 36、min SDK/NDK 编译目标 24。
- 三 ABI：arm64-v8a、armeabi-v7a、x86_64。
- 统一 native 库：`liblxbox.so`；构建参数包含 16 KiB page alignment。
- CI 会执行纯 Go 包测试/vet、依赖图、gofmt 差异检查、RyUI API 24 source patch、APK manifest/ABI/ELF/JNI/sig/lint 检查，并上传 APK、日志、manifest、lint、版本和依赖报告。
- 构建后不会启动设备或模拟器，也不会发布 Release。

## 静态验证结果

本机只执行了 Python 静态检查和指定 Go 文件的 gofmt 格式验证，未执行 Go 编译/测试、Gradle、NDK、Git 或 GitHub Actions：

- Python 脚本单元测试通过（2 tests）；`compileall` 通过。
- `D:\\go\\bin\\gofmt.exe -w` 已格式化本次修复涉及的 Go 文件，随后 `gofmt -d` 无差异。
- `check_migration.py --source-only`：`status=ok`、`errors=0`；外部 RyUI 和 core submodule checkout 缺失是预期 warning，等待 Actions checkout。
- 本轮已修复 app 自身的 parser registry 函数重名、mapper helper/变量作用域、storage `loaded` 字段、workspace `model` 导入、automation 未使用变量、ruleset 测试返回值，以及 transfer plaintext 的 base64/原文兼容。
- `ci_go_checks.py` 未执行到 Go 阶段，因为本地 staging workspace 缺少 Actions 才会 checkout 的 RyUI 和四个 fork；该前置失败不代表源码编译失败。
- `app` 内 Dart 文件：0。
- 新 app 的 Flutter runtime 引用：0。
- 契约语料：2,110 个文件。
- 非 Dart 资源：57 个文件。
- 迁移源码静态清单：`app/artifacts/static-delivery.json`。
- 功能差异快照：`app/reports/functionality-review.json`。

“静态检查通过”只说明源文件可以被静态 parser 读取，不代表 Go 类型检查、链接、APK 构建或 Android 运行已经通过。

## 本轮 Actions 错误修复记录

- core 的四个 fork submodule 由锁定的 sing-box-lx commit 中的 gitlinks 决定；Actions 递归初始化，不再从 app workflow 另行覆盖版本。submodule revisions 会记录到 `core-submodules.txt` 和构建 artifact。

- 新一轮 Actions 日志未出现 Go 编译器错误；失败集中在 parser contract URI golden。日志中的 AnyTLS/VLESS 大量差异暴露了通用 mapper 元数据未完整执行：协议 mapper 的 `userinfo`、`defaults`、`scheme_sets` 与 shared URI blocks 需要统一合并，不能只依赖协议顶层 `uri`。本轮已补上 mappers URI 的 userinfo/params/defaults/scheme_sets 读取、普通 URI 的 scheme defaults，以及字面量 query 解码；已用 gofmt 和 Python-only 检查验证，尚未运行 Go 测试。

以下内容仍不能宣称与旧 Flutter 应用完全等价：

1. **未执行编译和设备验证。** Go/Gradle/NDK/Actions 都未运行；API 24 安装、VPN 授权、TUN fd、Doze、服务重启、通知和 SAF 仍需 Actions/设备验证。
2. **复杂契约 mapper 尚未完整覆盖。** TLS/REALITY 全字段、XHTTP/transport/ECH/uTLS/multiplex/dialer 复杂组合、完整 Xray/Clash body mapper、完整 sanitizer/warning verdict/duplicate contract semantics 仍有差异。
3. **builder 仍有明确 fatal 缺口。** 部分 auto group/node-link、复杂 chain/direction refs、mixins、TUN apps、完整 DNS/rule preset references 和部分 source metadata/disabled overlays 遇到未保真语义会报错，避免生成错误配置。
4. **portable backup 不是旧 Dart 全语义副本。** 0.x folder/chain canonical conversion、source ID/NodeLink remap、订阅 full-settings merge、所有 DNS preset/default/reference、required-rule pinning、WARP typed storage conversion 仍有差异；报告会保留 warning/read-only guard。
5. **核心平台行为有边界。** 候选探测的 libbox constructor 仍可能触发 OOM recorder、power report、logger 和 FreeOSMemory 等进程级副作用；这是 libbox 内部构造器行为，当前 app 层未改核心源码绕过。
6. **部分旧系统功能仍是显式错误或 best effort。** 复杂 OpenConnect/Tasker/AppFunctions/Boot/watchdog/Deep Link 行为、按应用 trace、实时统计/测速图、完整日志 clear、部分 Taildrop 服务文件工作流、Tailscale state directory 和所有 native Android 细节仍需设备验证或继续迁移。
7. **原项目 Dart 代码保留作行为基线。** 新 `app/` 已没有 Dart/Flutter 依赖；旧 `LxBox-2.25.21` 目录和测试语料没有删除，以便对照和回归，不将“删除 Dart”与“功能等价”混为一谈。

## 用户后续操作

1. 将 `sing-box-lx-1.14.4-lx.33` 作为 GitHub 仓库根目录。
2. 手动运行 Actions → **LxBox RyUI Android manual build**。
3. 下载 artifact，优先查看：
   - `migration-report.json`
   - `go-checks.log`、`go-pure-tests.log`、`go-pure-vet.log`
   - `gofmt.diff`
   - `api24.patch-report.json`
   - `apk-verification.json`
   - `lint-status.json`
   - `elf-*.txt`、`symbols-*.txt`
4. 只有 Actions 通过后，才可报告 APK 编译通过；只有在 API 24 和较新 Android 设备完成安装、VPN、TUN、通知、SAF、扫码、自动化和生命周期测试后，才可报告运行兼容。

本报告没有运行远程工作流，也没有执行本地编译。