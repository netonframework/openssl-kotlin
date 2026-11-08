pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement {
    repositories {
        exclusiveContent {
            forRepository {
                maven { url = uri(providers.gradleProperty("stagedRepository").get()) }
            }
            filter { includeGroup("com.netonstream") }
        }
        mavenCentral()
    }
}
rootProject.name = "openssl-native-consumer"
