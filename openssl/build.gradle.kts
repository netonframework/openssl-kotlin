import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    `maven-publish`
    signing
}

// The host's Kotlin/Native target; null on Windows, where only the JVM target builds (OpenSSL itself is cross-built for
// mingwX64 on macOS or Linux, and Windows JVM checks use -PjniPrebuilt).
val host = when {
    System.getProperty("os.name") == "Mac OS X" -> if (System.getProperty("os.arch") == "aarch64") "macosArm64" else "macosX64"
    System.getProperty("os.name") == "Linux" -> if (System.getProperty("os.arch") == "aarch64") "linuxArm64" else "linuxX64"
    System.getProperty("os.name").startsWith("Windows") -> null
    else -> error("Build on macOS, Linux or (JVM only) Windows")
}
val supported = setOf("macosArm64", "macosX64", "linuxX64", "linuxArm64", "iosArm64", "iosSimulatorArm64", "iosX64", "mingwX64", "androidNativeArm64", "androidNativeX64")
val selected = providers.gradleProperty("nativeTargets").orElse(host ?: "none").get().let {
    when (it) { "all" -> supported; "none" -> emptySet(); else -> it.split(',').map(String::trim).toSet() }
}
require(supported.containsAll(selected)) { "Unknown nativeTargets: $selected" }

// The JVM jar's JNI libraries (docs/JVM.md), META-INF/native/<os>-<arch>/: by default the host's only, built from its
// OpenSSL archives; -PjniPlatforms=all (or a list of the targets below) cross-builds them all, as a release does, and
// -PjniPrebuilt=<dir> (relative to openssl/) takes an already assembled META-INF/native tree instead (CI tests the released binaries that way).
val desktopJni = mapOf("macosArm64" to "macos-arm64", "macosX64" to "macos-x64", "linuxX64" to "linux-x64",
    "linuxArm64" to "linux-arm64", "mingwX64" to "windows-x64")
val jniTargets = providers.gradleProperty("jniPlatforms").orNull?.let {
    if (it == "all") desktopJni.keys else it.split(',').map(String::trim).toSet()
} ?: setOfNotNull(host)
require(desktopJni.keys.containsAll(jniTargets)) { "Unknown jniPlatforms: $jniTargets" }
val jniPrebuilt = providers.gradleProperty("jniPrebuilt").orNull?.let { file(it) }
fun buildJniTask(target: String, out: Provider<Directory>) = tasks.register<Exec>("buildJni" + target.replaceFirstChar { it.uppercase() }) {
    inputs.files(rootProject.file("scripts/build-jni.sh"), rootProject.file("scripts/build-openssl.sh"), rootProject.file("gradle.properties"))
    inputs.files(fileTree("src/jvmNative"), fileTree("src/nativeInterop/cinterop") { include("*.h") })
    if (target.startsWith("androidNative")) inputs.property("androidNdkHome", providers.environmentVariable("ANDROID_NDK_HOME").orElse(""))
    outputs.dir(out)
    environment("JNI_JAVA_HOME", System.getProperty("java.home"))
    commandLine("bash", rootProject.file("scripts/build-jni.sh"), target, out.get().asFile.absolutePath)
    dependsOn(tasks.matching { it.name == "buildOpenSsl" + target.replaceFirstChar { c -> c.uppercase() } })
}
val desktopJniTasks = if (jniPrebuilt != null) emptyMap() else
    jniTargets.associateWith { buildJniTask(it, layout.buildDirectory.dir("jni/$it")) }
val assembleJni = tasks.register<Sync>("assembleJni") {
    into(layout.buildDirectory.dir("jni-resources"))
    if (jniPrebuilt != null) {
        from(jniPrebuilt) { include("META-INF/native/**") }
        doLast {
            val found = desktopJni.values.filter { File(jniPrebuilt, "META-INF/native/$it").isDirectory }
            check(found.isNotEmpty()) { "-PjniPrebuilt=$jniPrebuilt has no META-INF/native/<platform>/" }
        }
    } else for ((target, buildJni) in desktopJniTasks) {
        from(buildJni) {
            include("*.so", "*.dylib", "*.dll")
            into("META-INF/native/${desktopJni.getValue(target)}")
        }
    }
}

kotlin {
    // The JVM (docs/JVM.md): JNI over the same static OpenSSL, for desktop JVMs and Android apps. Bytecode 1.8, API 2.2
    // and stdlib 2.2.21 so Android hosts on Kotlin 2.1 can use it (neton-io's JVM target does the same).
    coreLibrariesVersion = "2.2.21"
    // Language 2.2 for every source set the JVM compiles (KMP also requires a source set to be no older than the ones it
    // depends on, so native-only ones may stay newer): class metadata then says 2.2, which a Kotlin 2.1 compiler still
    // reads (one version ahead); with the 2.4 default it refuses to compile against these classes.
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
            apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
            languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        }
        compilations.configureEach { allKotlinSourceSets.forAll { it.languageSettings.languageVersion = "2.2" } }
    }
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
                inputs.files(project.fileTree("src/nativeInterop/cinterop") { include("*.h") })
            }
        }
    }
    sourceSets {
        commonTest.dependencies { implementation(kotlin("test")) }
        jvmMain { resources.srcDir(assembleJni) }
        matching { it.name.startsWith("native") || it.name.startsWith("macos") || it.name.startsWith("linux") ||
            it.name.startsWith("ios") || it.name.startsWith("mingw") || it.name.startsWith("android") || it.name.startsWith("apple") }
            .configureEach { languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi") }
    }
}

// Android apps load native code only from an AAR's jni/<abi>/ (docs/JVM.md): the NDK-built libraries of
// scripts/build-jni.sh for the Android targets (arm64-v8a; x86_64 needs an NDK whose clang knows OpenSSL 4.0's SM4
// AVX instructions, 29+), packed with a manifest and an empty classes.jar; the classes are the JVM jar's.
val androidAbis = mapOf("androidNativeArm64" to "arm64-v8a", "androidNativeX64" to "x86_64")
androidAbis.keys.forEach { target -> buildJniTask(target, layout.buildDirectory.dir("jni-android/$target")) }
val androidEmptyClasses = tasks.register<Jar>("androidEmptyClassesJar") {
    archiveFileName.set("classes.jar")
    destinationDirectory.set(layout.buildDirectory.dir("android-aar"))
}
val androidManifest = layout.buildDirectory.file("android-aar/AndroidManifest.xml")
tasks.register<Zip>("androidNativesAar") {
    val abis = providers.gradleProperty("androidAbis").orElse("arm64-v8a").get().split(',')
    archiveBaseName.set("openssl-android-natives")
    archiveExtension.set("aar")
    destinationDirectory.set(layout.buildDirectory.dir("android-aar"))
    for ((target, abi) in androidAbis) if (abi in abis) {
        dependsOn("buildJni" + target.replaceFirstChar { it.uppercase() })
        from(layout.buildDirectory.dir("jni-android/$target")) { include("libneton_openssl.so"); into("jni/$abi") }
    }
    from(androidEmptyClasses)
    doFirst {
        androidManifest.get().asFile.writeText(
            "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.netonstream.openssl\">\n" +
                "    <uses-sdk android:minSdkVersion=\"26\" />\n</manifest>\n",
        )
    }
    from(androidManifest)
}

// -PtestJavaHome=<JDK> runs the JVM tests on that JDK instead of Gradle's own, e.g. the oldest one the bytecode targets (8).
providers.gradleProperty("testJavaHome").orNull?.let { jdk ->
    val java = if (System.getProperty("os.name").startsWith("Windows")) "bin/java.exe" else "bin/java"
    tasks.named<Test>("jvmTest") { executable = File(jdk, java).absolutePath }
}

val apiDocsJar = tasks.register<Jar>("apiDocsJar") {
    archiveClassifier.set("javadoc")
    from(rootProject.file("README.md"))
    from(rootProject.file("docs/SAFE_API.md"))
}
publishing {
    repositories { maven { name = "staging"; url = rootProject.layout.buildDirectory.dir("staging-repo").get().asFile.toURI() } }
    publications.withType<MavenPublication>().configureEach {
        artifact(apiDocsJar)
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
val key = providers.environmentVariable("SIGNING_KEY").orElse(providers.gradleProperty("signingInMemoryKey"))
tasks.withType<Jar>().configureEach {
    from(rootProject.file("LICENSE")) { into("META-INF") }
    from(rootProject.file("NOTICE")) { into("META-INF") }
    from(rootProject.file("licenses/OpenSSL.txt")) { into("META-INF/licenses") }
}
if (key.isPresent) signing {
    useInMemoryPgpKeys(key.get(), providers.environmentVariable("SIGNING_PASSWORD").orElse(providers.gradleProperty("signingInMemoryKeyPassword")).orNull)
    sign(publishing.publications)
}
tasks.withType<org.gradle.api.publish.maven.tasks.AbstractPublishToMaven>().configureEach {
    dependsOn(tasks.withType<org.gradle.plugins.signing.Sign>())
}
