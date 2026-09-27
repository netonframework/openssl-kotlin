plugins { kotlin("multiplatform") version "2.4.0" }
repositories { mavenLocal(); mavenCentral() }
kotlin {
    val target = when (System.getProperty("os.name")) {
        "Mac OS X" -> if (System.getProperty("os.arch") == "aarch64") macosArm64() else macosX64()
        "Linux" -> if (System.getProperty("os.arch") == "aarch64") linuxArm64() else linuxX64()
        else -> error("Unsupported smoke-test host")
    }
    target.binaries.executable { entryPoint = "main" }
    sourceSets.commonMain.dependencies { implementation("com.netonstream:openssl:4.0.2-1") }
}
