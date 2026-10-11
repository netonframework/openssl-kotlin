// The released JVM artifact as a downstream project sees it: Kotlin 2.1 (the oldest the artifact promises), no
// includeBuild, com.netonstream:openssl resolved from -PstagedRepository=<dir> only (exclusively: a same-numbered
// artifact elsewhere cannot stand in). Its tests are the library's own common tests, compiled against the published
// classes, so they exercise the jar's classes, resources (the JNI libraries) and Gradle metadata, not the sources.
pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories {
        val staged = providers.gradleProperty("stagedRepository").orNull
            ?: error("-PstagedRepository=<a Maven repository holding com.netonstream:openssl> is required")
        exclusiveContent {
            forRepository { maven { url = uri(staged) } }
            filter { includeGroup("com.netonstream") }
        }
        mavenCentral()
    }
}
rootProject.name = "openssl-consumer-jvm"
