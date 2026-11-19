plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.algor3ithm.scutulbunicii.web"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.algor3ithm.scutulbunicii.web"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = false
    }

    // The readers are NOT copied into git here: one source of truth is integrations/watcher/readers/*.js.
    sourceSets.getByName("main").assets.srcDir(layout.buildDirectory.dir("generated/readerAssets"))
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Copy the desktop watcher's reader scripts into the app's assets at build time (assets/readers/*.js).
val copyReaders by tasks.registering(Copy::class) {
    from(rootProject.layout.projectDirectory.dir("../integrations/watcher/readers")) { include("*.js") }
    into(layout.buildDirectory.dir("generated/readerAssets/readers"))
}

tasks.configureEach {
    if (name.startsWith("merge") && name.endsWith("Assets")) dependsOn(copyReaders)
    if (name.startsWith("lintVital") || name.startsWith("lintAnalyze") || name.startsWith("generate") && name.endsWith("LintReportModel")) {
        dependsOn(copyReaders)
    }
}

// No third-party dependencies on purpose: framework APIs only (WebView, org.json, HttpURLConnection).
