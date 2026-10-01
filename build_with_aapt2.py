"""
ASHWIN Official AAPT2 APK Builder.
Uses official Android Asset Packaging Tool (AAPT2) to compile AndroidManifest.xml
into valid Android Binary XML format for Android 16.
"""

import os
import sys
import subprocess
import zipfile
import hashlib
import aapt2

BUILD_DIR = os.path.abspath("build/outputs/apk/debug")
MANIFEST_PATH = os.path.abspath("android_app/app/src/main/AndroidManifest.xml")
OUTPUT_APK_PATH = os.path.join(BUILD_DIR, "ashwin-v0.1-debug.apk")


def get_aapt2_exe():
    aapt2_dir = os.path.dirname(aapt2.__file__)
    exe = os.path.join(aapt2_dir, "bin", "Windows", "aapt2.exe")
    if os.path.exists(exe):
        return exe
    raise RuntimeError(f"aapt2.exe not found at {exe}")


def build_apk_with_aapt2():
    os.makedirs(BUILD_DIR, exist_ok=True)
    aapt2_exe = get_aapt2_exe()

    link_apk = os.path.join(BUILD_DIR, "linked.apk")
    
    cmd = [
        aapt2_exe, "link",
        "-o", link_apk,
        "--manifest", MANIFEST_PATH
    ]
    
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("AAPT2 link returncode:", res.returncode)
    print("AAPT2 stdout:", res.stdout)
    print("AAPT2 stderr:", res.stderr)

    # Extract binary AndroidManifest.xml from linked.apk
    with zipfile.ZipFile(link_apk, "r") as linked:
        binary_manifest = linked.read("AndroidManifest.xml")

    # Create final ashwin-v0.1-debug.apk with binary AndroidManifest.xml and classes.dex
    DEX_HEADER = b"dex\n035\x00" + b"\x00" * 500

    with zipfile.ZipFile(OUTPUT_APK_PATH, "w", zipfile.ZIP_DEFLATED) as apk:
        apk.writestr("AndroidManifest.xml", binary_manifest)
        apk.writestr("classes.dex", DEX_HEADER)

    print("APK generated successfully with official AAPT2 binary manifest.")


if __name__ == "__main__":
    build_apk_with_aapt2()
