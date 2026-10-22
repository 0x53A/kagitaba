"""Register an existing Kagitaba binary as this user's Firefox native host.

Run with uv run --no-project tools/install_native_host.py /absolute/path/kagitaba-app.
Does not build, launch the GUI, or alter Firefox profiles.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--directory", type=Path, default=Path.home() / ".mozilla/native-messaging-hosts")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("binary must be an executable file")
    args.directory.mkdir(parents=True, exist_ok=True)
    manifest = dict(name="kagitaba", description="Kagitaba native wallet gateway",
                    path=str(binary), type="stdio", allowed_extensions=["firefox@kagitaba.local"])
    path = args.directory / "kagitaba.json"
    with tempfile.NamedTemporaryFile(mode="w", dir=args.directory, delete=False) as output:
        temporary = Path(output.name)
        try:
            json.dump(manifest, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    print(f"Registered Firefox native host: {path}")


if __name__ == "__main__":
    main()
