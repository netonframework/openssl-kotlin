plugins { kotlin("jvm") version "2.1.21" }

val openssl = providers.gradleProperty("opensslVersion").getOrElse("4.0.2-3")

dependencies {
    implementation("com.netonstream:openssl:$openssl")
    testImplementation(kotlin("test"))
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8) }
    // The library's common tests (public API only), unchanged.
    sourceSets.test { kotlin.srcDir("../openssl/src/commonTest/kotlin") }
}
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.test {
    useJUnit()
    // -PtestJavaHome=<JDK>: run on that JDK (CI: 8 and 21).
    providers.gradleProperty("testJavaHome").orNull?.let { jdk ->
        executable = File(jdk, if (System.getProperty("os.name").startsWith("Windows")) "bin/java.exe" else "bin/java").absolutePath
    }
    // The library must come from the jar: nothing on this classpath may be the build tree's classes or resources.
    doFirst {
        val local = classpath.filter { it.absolutePath.replace(File.separatorChar, '/').contains("/openssl/build/") }
        check(local.isEmpty) { "build-tree classes on the classpath: ${local.files}" }
    }
}
