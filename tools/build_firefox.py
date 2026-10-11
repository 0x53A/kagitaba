"""Build the local, unsigned Firefox extension with locked dependencies."""
import pathlib
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args, cwd=ROOT):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    cli = ROOT / "target/browser-tools/bin/wasm-bindgen"
    version = "0.2.129"
    if not cli.exists() or subprocess.check_output([cli, "--version"], text=True).strip() != f"wasm-bindgen {version}":
        run("cargo", "install", "--locked", "--version", version, "--root", "target/browser-tools", "wasm-bindgen-cli")
    run("cargo", "build", "--locked", "-p", "kagitaba-browser", "--target", "wasm32-unknown-unknown", "--release")
    run(str(cli), "--target", "web", "--out-dir", "extension/firefox/pkg", "target/wasm32-unknown-unknown/release/kagitaba_browser.wasm")
    extension = ROOT / "extension/firefox"
    run("npm", "ci", cwd=extension)
    run("npm", "test", cwd=extension)
    run("npm", "run", "build", cwd=extension)
    output = ROOT / "target/kagitaba-firefox-unsigned.xpi"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted((extension / "dist").iterdir()):
            info = zipfile.ZipInfo(source.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, source.read_bytes())
    print(f"Unsigned local Firefox artifact: {output}")


if __name__ == "__main__":
    main()
