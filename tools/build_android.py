#!/usr/bin/env python3
"""Build the native Android bridge and debug APK with the project Nix shell.

Run: nix-shell android/shell.nix --run 'uv run --no-project tools/build_android.py'
Use --abi x86_64 for an emulator, --abi all to package both 64-bit ABIs.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import shlex

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--abi", choices=["arm64-v8a", "x86_64", "all"], default="all")
    args = parser.parse_args()
    ndk = Path(os.environ["ANDROID_NDK_HOME"])
    version = subprocess.check_output(["rustc", "--version"], text=True).split()[1]
    source = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    output = ROOT / "target" / "android"
    output.mkdir(parents=True, exist_ok=True)
    sysroot = output / f"sysroot-source-{version}"
    rustlib = sysroot / "lib" / "rustlib"
    rustlib.mkdir(parents=True, exist_ok=True)
    for child in (source / "lib").iterdir():
        if child.name != "rustlib" and not (sysroot / "lib" / child.name).exists():
            (sysroot / "lib" / child.name).symlink_to(child)
    for child in (source / "lib" / "rustlib").iterdir():
        if not (rustlib / child.name).exists():
            (rustlib / child.name).symlink_to(child)
    # Nix's source-built compiler is not ABI-compatible with rustup's prebuilt
    # standard libraries, even with the same version. Build Android std with the
    # exact Nix compiler and its matching sources in a local sysroot overlay.
    src = rustlib / "src" / "rust"
    src.mkdir(parents=True, exist_ok=True)
    if not (src / "library").exists():
        (src / "library").symlink_to(os.environ["KAGITABA_RUST_LIBRARY_SOURCE"])
    wrapper = output / "rustc-android"
    wrapper_text = "#!/usr/bin/env bash\nexec " + shlex.quote(shutil.which("rustc")) + " --sysroot " + shlex.quote(str(sysroot)) + ' "$@"\n'
    if not wrapper.exists() or wrapper.read_text() != wrapper_text:
        wrapper.write_text(wrapper_text)
    wrapper.chmod(0o755)
    abis = {"arm64-v8a": "aarch64-linux-android", "x86_64": "x86_64-linux-android"}
    for abi, target in abis.items():
        if args.abi not in ("all", abi):
            continue
        env = dict(os.environ)
        env["RUSTC"] = str(wrapper)
        env["RUSTC_BOOTSTRAP"] = "1"
        prefix = target.upper().replace("-", "_")
        env[f"CARGO_TARGET_{prefix}_LINKER"] = str(ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin" / f"{target}34-clang")
        env["RUSTFLAGS"] = "-C link-arg=-Wl,-z,max-page-size=16384"
        run("cargo", "build", "--locked", "-Z", "build-std=std,panic_abort", "-p", "kagitaba-android", "--release", "--target", target, env=env)
        dest = ROOT / "android/app/src/main/jniLibs" / abi
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "target" / target / "release/libkagitaba_android.so", dest)
    selected = ",".join(abis) if args.abi == "all" else args.abi
    run("gradle", "-p", "android", f"-PkagitabaAbis={selected}", ":app:testDebugUnitTest", ":app:assembleDebug", ":app:lintDebug")
    dest = output / "kagitaba-debug.apk"
    shutil.copy2(ROOT / "android/app/build/outputs/apk/debug/app-debug.apk", dest)
    print(f"Built local debug APK: {dest}")


if __name__ == "__main__":
    main()
