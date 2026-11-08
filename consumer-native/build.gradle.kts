plugins { kotlin("multiplatform") version "2.4.20" }

kotlin {
    mingwX64()
    sourceSets {
        commonMain.dependencies {
            implementation("com.netonstream:openssl:${providers.gradleProperty("opensslVersion").get()}")
        }
        commonTest {
            kotlin.srcDir("../openssl/src/commonTest/kotlin")
            dependencies { implementation(kotlin("test")) }
        }
    }
}
