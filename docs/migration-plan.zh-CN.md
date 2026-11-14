# LxBox → RyUI + sing-box-lx 完整迁移计划

## 目标与约束

将 LxBox Android 应用迁移为 RyUI Go 界面、Go 应用层和 sing-box-lx Go 内核构成的单 Go runtime 应用。最终不保留任何 Dart/Flutter 源码、运行依赖、构建插件或 Flutter engine；不依赖 `libbox.aar`。Kotlin/Java 仅保留 Android OS API 与生命周期适配。

实施约束：本机不运行 Go、Gradle、NDK 或 Android 构建，不触发或上传 GitHub Actions；远程编译由用户之后在 GitHub Actions 手动验证。使用 `d:\grit-x86_64-pc-windows-msvc\grit.exe` 替代 Git，不调用 Git。保持 LxBox `minSdk=24`，但区分编译、安装和 API 24 功能运行验收。

## 目标模块结构

在 sing-box-lx 仓库内添加独立 `app/` Go module，保持依赖方向为 app → RyUI 与 sing-box-lx 核心。应用层承载订阅解析、配置构建、持久化、用户设置、工作区、备份、诊断和应用编排；核心继续只负责协议、配置、代理运行和 command API。

Android 包由单一 Go `c-shared` native library 承载 RyUI、LxBox Go 应用层和 sing-box-lx 内核。Android Host 保留 Activity、VpnService、TUN、授权、网络/ DNS/ Wi-Fi、通知、Boot、Watchdog、Quick Settings Tile、SAF、分享、剪贴板、权限、Intent、Tasker/AppFunctions 等系统集成，通过 JNI facade 与 Go 应用层交互。最终不生成或引用 `libbox.aar`。

## 实施阶段

### 1. 建立迁移基线

- 以 `docs/research/lxbox-sing-box-lx-interactions.zh-CN.md` 和当前 Dart/Kotlin 源码建立功能矩阵。
- 覆盖节点、分组、订阅、协议解析、配置构建/校验、VPN 控制、统计、日志、设置、工作区、备份、诊断、Debug API、自动化、Tailscale、Taildrop、OpenConnect、系统入口及文件工作流。
- 记录用户数据结构、默认值、版本迁移、错误恢复、应用 ID、权限、Android manifest 组件、ABI 和发布签名流程。
- 为解析器、配置 builder 和持久化迁移建立 golden fixtures，锁定当前行为。

**门槛：**核心输入输出和旧数据行为可重复验证；不得先删除旧实现。

### 2. 验证统一 Go runtime/JNI 最小闭环

- 在 sing-box-lx 内添加独立 `app/` module，Go 代码直接依赖内核 API 和 RyUI，不经 gomobile Java API。
- 将 RyUI、应用代码、内核链接为同一 Android native library，并验证只有一个 Go runtime。
- 解决 RyUI 与内核 native C 代码都定义 `JNI_OnLoad` 的冲突，提供唯一初始化入口。
- 保留并核对内核所需 fork `replace`（wireguard-go、sing-tun、gvisor、utls）及构建 tags/ldflags。
- 验证 Kotlin/Go JNI 回调、主线程投递、服务生命周期、错误传播和 TUN fd dup/close 所有权。
- 固定 Go 1.26 工具链与 NDK ABI 参数；通过 GitHub Actions 生成 debug APK，不在本机编译。

**门槛：**CI 构建的 APK 可静态确认包含 RyUI 与内核的统一 native library，不含 `libbox.aar` 或重复 Go runtime。

### 3. 建立 Android Host 与应用服务边界

- 保留 Kotlin 的 Android OS 适配，不删除其 VpnService/TUN/权限、网络监控、DNS/Wi-Fi、通知、Boot、Watchdog、Tile、SAF、分享、剪贴板、Intent、自动化入口等能力。
- 将 Flutter MethodChannel/EventChannel 替换为有明确线程、超时、取消、生命周期、错误、事件快照与重新订阅语义的 JNI facade/event bus。
- 将当前依赖 Flutter engine 的自动化动作改为直接调用 Go service API 或明确的 Kotlin→Go 入口。
- 保证 Activity detach/重建不会停止仍在运行的 VPN 服务；冷启动和事件订阅恢复后主动同步完整状态。

**门槛：**无 Flutter engine 时，系统授权、VPN 服务和后台运行仍正常，UI 重连不重复启动服务且状态可恢复。

### 4. 将 Dart 应用逻辑迁入 Go

按领域迁移并保留 golden 测试：

1. 数据模型、持久化、默认值、版本迁移。
2. 协议和订阅解析。
3. 配置 builder、配置校验、拒绝原因与回滚。
4. CommandServer/内核生命周期编排、节点/分组切换、统计与日志。
5. 用户设置、工作区、备份恢复和诊断。
6. Debug API、自动化、Tailscale、Taildrop、OpenConnect 等应用服务。
7. 稳定 Go API 后接入 RyUI 页面。

Go app 不将应用业务塞入 sing-box 核心包；Go UI 的同步调用不得阻塞主线程，耗时工作应异步返回状态和可取消结果。

**门槛：**每个领域通过 Go 测试，golden 差异均有解释，旧版数据可迁移并可恢复。

### 5. 用 RyUI 替换 Flutter 界面

迁移首页启停与节点/分组选择、订阅导入刷新、配置与高级设置、日志统计、诊断、备份恢复、分享/文件导入，以及通知和 Deep Link 导航等工作流。界面仅调用 Go 应用 API，不耦合 sing-box 内部实现；系统入口仍由 Android Host 承接。

**门槛：**功能矩阵中的每个用户工作流均有新 UI 或系统入口替代，VPN 生命周期与前台 UI 独立。

### 6. 删除 Flutter/Dart 与旧构建链路

- 移除应用构建/运行所需 Dart 源码及 Flutter 专用依赖、插件、资源、生成物和文档/脚本引用。
- 移除 Android Flutter embedding、Flutter Gradle 插件、Method/EventChannel 和 Flutter 打包步骤。
- 保留必要的 Android Kotlin/Java OS 集成和原生资源。
- 检查最终 APK，确认无 Flutter engine、Dart snapshot、`libbox.aar` 或重复的内核库。

**门槛：**仓库构建和运行不再依赖任何 Dart/Flutter 内容，所有既有功能都有替代或经过明确批准的移除记录。

### 7. GitHub Actions、兼容性和发布验收

- 添加手动触发 CI，记录源码 ref/commit、Go、JDK、Android SDK/NDK 版本；只由用户之后手动运行。
- 检查 Go 测试、解析器/配置 golden 测试、Kotlin 静态检查、manifest、权限和 Android 组件。
- 检查 APK 的 minSdk=24、target/compile SDK、ABI、native library、16 KB page-size 对齐及 Flutter/Dart/AAR 缺失情况。
- 分别验证 API 24 编译、安装和功能运行；RyUI RuntimeShader 等较新 API 特性不得因编译通过而宣称兼容。
- 在 API 24 与较新 Android 设备/模拟器验证安装、VPN、服务生命周期、通知、文件与自动化入口。许可证兼容性单独审查，不预先作分发许可承诺。

**验收：**功能矩阵全部迁移或审批移除；单一 Go runtime；无 Dart/Flutter 与 `libbox.aar`；用户数据兼容；CI 与测试通过；API 24 和新系统设备运行验收完成。

## 主要风险与控制

- **重复 `JNI_OnLoad`：**先解决单一入口，未通过不扩展业务迁移。
- **Go 依赖/fork 遗漏：**显式保留 replace，检查最终 module graph 并由 CI 构建验证。
- **VPN/UI 生命周期耦合：**VpnService/Host 持有服务生命周期，RyUI 只负责呈现和控制。
- **事件丢失/自动化静默失效：**保留快照、事件恢复、无 Activity 系统调用的测试。
- **数据格式回归：**旧 Dart golden fixtures 作为 Go 迁移验收基线。
- **API 24 误判：**构建、安装、运行分别报告，并保留高 API 专属功能限制。
- **过早删旧实现：**等所有功能域和门槛通过后再统一清理 Flutter/Dart。

## 执行约定

计划获批后按依赖顺序实施，但目标是一次完成完整迁移，不以局部 PoC 作为最终交付。由于本地构建被明确禁止，最终编译结果由用户在 GitHub Actions 手动验证；本地只做静态结构、脚本、YAML 和源代码检查。任何未能在当前仓库/依赖条件下真实实现或验证的部分，必须在交付总结中逐项列明，不能宣称迁移或编译已完成。
