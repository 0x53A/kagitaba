plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "org.kagitaba.android"
    compileSdk = 35
    ndkVersion = "27.2.12479018"
    defaultConfig {
        applicationId = "org.kagitaba.android"
        minSdk = 34
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk.abiFilters += providers.gradleProperty("kagitabaAbis").orElse("arm64-v8a,x86_64").get().split(",")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources.excludes += setOf("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/LICENSE*", "META-INF/NOTICE*", "OSGI-INF/**")
    }
    sourceSets.getByName("androidTest").assets.srcDir("../../tests/fixtures")
    testOptions { unitTests.isReturnDefaultValues = true }
}
dependencies {
    implementation("com.yubico.yubikit:android:2.9.0")
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.6")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.eclipse.jgit:org.eclipse.jgit:6.10.0.202406032230-r")
    implementation("org.slf4j:slf4j-nop:1.7.36")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
