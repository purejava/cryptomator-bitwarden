plugins {
    id("com.gradleup.shadow") version "8.3.6"
    id("com.github.breadmoirai.github-release") version "2.5.2"
    id("com.palantir.git-version") version "3.3.0"
    id("java")
    id("java-library")
    id("signing")
}

val gitHubPackagesUser: String = System.getenv("PACKAGES_USER") ?: ""
val gitHubPackagesToken: String = System.getenv("PACKAGES_ACCESS_TOKEN") ?: ""
val releaseGradlePluginToken: String = System.getenv("RELEASE_GRADLE_PLUGIN_TOKEN") ?: ""

repositories {
    mavenCentral()
    mavenLocal()
    maven {
        name = "GitHubPackages"
        url = uri("https://maven.pkg.github.com/bitwarden/sdk")
        credentials {
            username = gitHubPackagesUser
            password = gitHubPackagesToken
        }
    }
    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
}

dependencies {
    api(libs.org.cryptomator.integrations.api)
    api(libs.com.bitwarden.sdk.secrets)
    api(libs.org.slf4j.slf4j.api)
    testImplementation(libs.org.slf4j.slf4j.simple)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.api)
    testImplementation(libs.org.junit.jupiter.junit.jupiter.engine)
    testImplementation(libs.org.junit.jupiter.junit.jupiter)
    testRuntimeOnly(libs.org.junit.platform.junit.platform.launcher)
}

group = "org.purejava"
val gitVersion: groovy.lang.Closure<String> by extra
version = gitVersion() // version set by the plugin, based on the Git tag

java {
    sourceCompatibility = JavaVersion.VERSION_20
    withSourcesJar()
    withJavadocJar()
}

tasks.test {
    useJUnitPlatform()
    filter {
        includeTestsMatching("BitwardenAccessTest")
    }
}

// Optional publishing section commented out
/*
publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("cryptomator-bitwarden")
                description.set("Plug-in for Cryptomator to store vault passwords in Bitwarden")
                url.set("https://github.com/purejava/cryptomator-bitwarden")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("purejava")
                        name.set("Ralph Plawetzki")
                        email.set("ralph@purejava.org")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/purejava/cryptomator-bitwarden.git")
                    developerConnection.set("scm:git:ssh://github.com/purejava/cryptomator-bitwarden.git")
                    url.set("https://github.com/purejava/cryptomator-bitwarden/tree/develop")
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/purejava/cryptomator-bitwarden/issues")
                }
            }
        }
    }
}
*/

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveClassifier.set("")
}

tasks.named("githubRelease") {
    dependsOn("sourcesJar")
    dependsOn("javadocJar")
    dependsOn("signArchives")
}

artifacts {
    archives(tasks.named("shadowJar"))
    archives(tasks.named("sourcesJar"))
}

signing {
    useGpgCmd()
    sign(configurations.archives.get())
}

githubRelease {
    token(releaseGradlePluginToken)
    tagName = project.version.toString()
    releaseName = project.version.toString()
    targetCommitish = "develop"
    draft = true
    body = """
        [![Downloads](https://img.shields.io/github/downloads/purejava/cryptomator-bitwarden/latest/cryptomator-bitwarden-${project.version}.jar)](https://github.com/purejava/cryptomator-bitwarden/releases/latest/download/cryptomator-bitwarden-${project.version}.jar)

        - xxx
        """.trimIndent()
    generateReleaseNotes = true
    releaseAssets.from(
        fileTree("${layout.buildDirectory.get()}/libs") {
            include(
                "cryptomator-bitwarden-${version}.jar",
                "cryptomator-bitwarden-${version}.jar.asc",
                "cryptomator-bitwarden-${version}-sources.jar",
                "cryptomator-bitwarden-${version}-sources.jar.asc"
            )
        }
    )
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Javadoc> {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
    (options as StandardJavadocDocletOptions).encoding = "UTF-8"
}
