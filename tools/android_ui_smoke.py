#!/usr/bin/env python3
"""Synthetic UI checks on a disposable emulator with PIN 123456; never a phone.

Install the debug APK and boot its MAIN activity first. This script enrolls the
app through real Android device-credential authentication and creates a test
wallet. It neither resets nor uninstalls anything. Use a fresh test AVD.
Run inside android/shell.nix with uv run --no-project tools/android_ui_smoke.py.
"""
import argparse
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--serial", default="emulator-5580")
    args = parser.parse_args()
    if not args.serial.startswith("emulator-"):
        raise SystemExit("Only disposable emulators are supported")

    def adb(*cmd):
        return subprocess.check_output(["adb", "-s", args.serial, *cmd], text=True)

    def nodes():
        adb("shell", "uiautomator", "dump", "/sdcard/kagitaba-smoke.xml")
        return list(ET.fromstring(adb("shell", "cat", "/sdcard/kagitaba-smoke.xml")).iter("node"))

    def tap(node):
        x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.attrib["bounds"]))
        adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2))

    def find(text, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for node in nodes():
                if node.attrib.get("text") == text:
                    return node
            time.sleep(.5)
        labels = [n.get("text") for n in nodes() if n.get("class") == "android.widget.TextView"]
        raise AssertionError(f"Expected UI label did not appear: {text}; visible labels: {labels}")

    def click(text):
        tap(find(text))

    def pin():
        # Device-credential activity has an editable PIN field on this AVD.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            editable = [n for n in nodes() if n.attrib.get("class") == "android.widget.EditText"]
            if editable:
                tap(editable[0]); adb("shell", "input", "text", "123456"); adb("shell", "input", "keyevent", "66"); return
            time.sleep(.5)
        raise AssertionError("Android device-credential prompt did not appear")

    click("Set up this installation")
    pin()
    find("Connect your wallet")
    click("Create a new wallet")
    find("Your wallet")
    click("Add password")
    fields = [n for n in nodes() if n.attrib.get("class") == "android.widget.EditText"]
    assert len(fields) == 4
    for node, value in zip(fields, ["Synthetic-login", "https://example.test", "alice", "test-only-password"]):
        tap(node); adb("shell", "input", "text", value)
    adb("shell", "input", "keyevent", "4")
    click("Save password")
    find("1 accessible entries")
    click("Lock")
    find("Wallet locked")
    click("Unlock")
    pin()
    find("Your wallet")
    find("1 accessible entries")
    print("PASS: real device-PIN enrollment, signed wallet creation, password save, lock and unlock")


if __name__ == "__main__":
    main()
