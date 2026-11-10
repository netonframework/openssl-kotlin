plugins { kotlin("multiplatform") version "2.4.20" }

// A nonexistent release prevents Maven from masking a broken source substitution.
kotlin {
    linuxX64 { binaries.executable { entryPoint = "main" } }
    sourceSets {
        commonMain.dependencies {
            implementation("com.netonstream:openssl:0.0.0-composite-test")
        }
    }
}
