plugins {
    id("com.android.application")
    id("com.google.devtools.ksp")
}

val appVersionCode = providers.gradleProperty("versionCode").orElse("22521501").get().toInt()
val appVersionName = providers.gradleProperty("versionName").orElse("2.25.22-ryui.1").get()

android {
    namespace = "com.leadaxe.lxbox.android"
    compileSdk = 37
    compileSdkMinor = 0
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.leadaxe.lxbox"
        minSdk = 24
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
        manifestPlaceholders["ryuiAppName"] = "LxBox"
        manifestPlaceholders["ryuiIcon"] = "@drawable/ic_lxbox"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir("src/main/jniLibs")
            assets.srcDir("src/main/assets")
        }
    }
}

dependencies {
    implementation(project(":ryui"))
    // RyUI registers the live CameraX view; scan supplies its ML Kit frame reader.
    implementation(project(":ryui-scan"))
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.0")
    implementation("androidx.appfunctions:appfunctions:1.0.0-rc01")
    ksp("androidx.appfunctions:appfunctions-compiler:1.0.0-rc01")
    testImplementation("junit:junit:4.13.2")
}
