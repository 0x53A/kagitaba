{ pkgs ? import <nixpkgs> { config = { android_sdk.accept_license = true; allowUnfree = true; }; }, withEmulator ? false }:
let
  android = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "35" ];
    buildToolsVersions = [ "35.0.0" ];
    includeNDK = true;
    ndkVersions = [ "27.2.12479018" ];
    includeEmulator = withEmulator;
    includeSystemImages = withEmulator;
    systemImageTypes = [ "google_apis" ];
    abiVersions = [ "x86_64" ];
  };
in pkgs.mkShell {
  packages = [ pkgs.jdk17 pkgs.gradle pkgs.cargo pkgs.rustc pkgs.rustfmt pkgs.clippy pkgs.uv pkgs.curl pkgs.unzip android.androidsdk ];
  JAVA_HOME = "${pkgs.jdk17}";
  ANDROID_HOME = "${android.androidsdk}/libexec/android-sdk";
  ANDROID_SDK_ROOT = "${android.androidsdk}/libexec/android-sdk";
  ANDROID_NDK_HOME = "${android.androidsdk}/libexec/android-sdk/ndk/27.2.12479018";
  KAGITABA_RUST_LIBRARY_SOURCE = "${pkgs.rustPlatform.rustLibSrc}";
}
