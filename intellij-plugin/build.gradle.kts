plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.25"
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "com.nexus.security"
version = "1.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.code.gson:gson:2.10.1")
}

// Конфигурация целевой IDE для сборки и тестов.
// type "IC" = IntelliJ IDEA Community (бесплатная). Для Ultimate — "IU".
intellij {
    version.set("2023.3")
    type.set("IC")
    plugins.set(listOf())
}

tasks {
    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }

    patchPluginXml {
        sinceBuild.set("233")   // 2023.3
        untilBuild.set("243.*") // до 2024.3.x
    }

    // Плагин не подписан — для личного использования это нормально.
    buildSearchableOptions {
        enabled = false
    }
}
