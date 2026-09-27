import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    `maven-publish`
    signing
}

val host = when (System.getProperty("os.name")) {
    "Mac OS X" -> if (System.getProperty("os.arch") == "aarch64") "macosArm64" else "macosX64"
    "Linux" -> if (System.getProperty("os.arch") == "aarch64") "linuxArm64" else "linuxX64"
    else -> error("Build on macOS or Linux; Windows cross builds use Linux + MinGW")
}
val supported = setOf("macosArm64", "macosX64", "linuxX64", "linuxArm64", "iosArm64", "iosSimulatorArm64", "iosX64", "mingwX64", "androidNativeArm64", "androidNativeX64")
val selected = providers.gradleProperty("nativeTargets").orElse(host).get().let {
    if (it == "all") supported else it.split(',').map(String::trim).toSet()
}
require(selected.isNotEmpty() && supported.containsAll(selected)) { "Unknown nativeTargets: $selected" }

kotlin {
    if ("macosArm64" in selected) macosArm64()
    if ("macosX64" in selected) macosX64()
    if ("linuxX64" in selected) linuxX64()
    if ("linuxArm64" in selected) linuxArm64()
    if ("iosArm64" in selected) iosArm64()
    if ("iosSimulatorArm64" in selected) iosSimulatorArm64()
    if ("iosX64" in selected) iosX64()
    if ("mingwX64" in selected) mingwX64()
    if ("androidNativeArm64" in selected) androidNativeArm64()
    if ("androidNativeX64" in selected) androidNativeX64()
    applyDefaultHierarchyTemplate()

    targets.withType<KotlinNativeTarget>().configureEach {
        val targetName = name
        val prefix = rootProject.layout.buildDirectory.dir("openssl/$targetName/install")
        val buildOpenSsl = tasks.register<Exec>("buildOpenSsl" + targetName.replaceFirstChar { it.uppercase() }) {
            inputs.files(rootProject.file("scripts/build-openssl.sh"), rootProject.file("gradle.properties"))
            if (targetName.startsWith("androidNative")) {
                val ndk = providers.environmentVariable("ANDROID_NDK_HOME").orElse("")
                inputs.property("androidNdkHome", ndk)
                if (ndk.get().isNotEmpty()) inputs.file(file("${ndk.get()}/source.properties"))
            }
            outputs.dir(prefix)
            commandLine("bash", rootProject.file("scripts/build-openssl.sh"), targetName)
        }
        compilations.getByName("main").cinterops.create("openssl") {
            definitionFile.set(project.file("src/nativeInterop/cinterop/openssl.def"))
            includeDirs(prefix.map { it.dir("include") }, project.file("src/nativeInterop/cinterop"))
            extraOpts("-libraryPath", prefix.get().dir("lib").asFile.absolutePath)
            if (targetName.startsWith("androidNative")) extraOpts("-staticLibrary", "libopenssl.a")
            else extraOpts("-staticLibrary", "libssl.a", "-staticLibrary", "libcrypto.a")
            tasks.named(interopProcessingTaskName).configure {
                dependsOn(buildOpenSsl)
                inputs.dir(prefix.map { it.dir("include") })
                inputs.files(prefix.map { it.file("lib/libssl.a") }, prefix.map { it.file("lib/libcrypto.a") })
                if (targetName.startsWith("androidNative")) inputs.file(prefix.map { it.file("lib/libopenssl.a") })
                inputs.file(project.file("src/nativeInterop/cinterop/neton_openssl.h"))
            }
        }
    }
    sourceSets {
        commonTest.dependencies { implementation(kotlin("test")) }
        all { languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi") }
    }
}

publishing {
    repositories { maven { name = "staging"; url = rootProject.layout.buildDirectory.dir("staging-repo").get().asFile.toURI() } }
    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("Neton OpenSSL Kotlin")
            description.set("OpenSSL 4.x static libraries, C bindings and Kotlin/Native utilities")
            url.set("https://github.com/netonframework/openssl-kotlin")
            licenses { license { name.set("Apache License, Version 2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0") } }
            developers { developer { id.set("netonframework"); name.set("Neton contributors") } }
            scm { url.set("https://github.com/netonframework/openssl-kotlin"); connection.set("scm:git:https://github.com/netonframework/openssl-kotlin.git") }
        }
    }
}
val key = providers.environmentVariable("SIGNING_KEY")
tasks.withType<Jar>().configureEach {
    from(rootProject.file("LICENSE")) { into("META-INF") }
    from(rootProject.file("NOTICE")) { into("META-INF") }
    from(rootProject.file("licenses/OpenSSL.txt")) { into("META-INF/licenses") }
}
if (key.isPresent) signing {
    useInMemoryPgpKeys(key.get(), providers.environmentVariable("SIGNING_PASSWORD").orNull)
    sign(publishing.publications)
}
