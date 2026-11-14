pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "lxbox-android"
include(":app", ":ryui", ":ryui-scan")

// CI checks out the pinned RyUI commit here. Keep this as a source dependency so
// the app uses the same patched RyUI JNI library as the unified lxbox runtime.
val ryuiRoot = file("../third_party/ryui/platform/android")
project(":ryui").projectDir = ryuiRoot.resolve("ryui")
project(":ryui-scan").projectDir = ryuiRoot.resolve("ryui-scan")
