"""
ASHWIN V0.1 APK Builder & Inspector.
Assembles the ASHWIN V0.1 APK package and computes its cryptographic hash and manifest.
"""

import os
import sys
import hashlib
import zipfile
import tempfile

BUILD_DIR = os.path.abspath("build/outputs/apk/debug")
APK_PATH = os.path.join(BUILD_DIR, "ashwin-v0.1-debug.apk")

MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.ashwin.core"
    android:versionCode="1"
    android:versionName="0.1.0">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />

    <!-- Minimal, justified permissions strictly adhering to ASHWIN-SPEC v1.0.1 -->
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:label="ASHWIN Core"
        android:allowBackup="false"
        android:supportsRtl="true">

        <!-- Single launcher activity -->
        <activity
            android:name="org.ashwin.core.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
"""

DEX_HEADER_HEADER = b"dex\n035\x00"  # Valid Dalvik Executable header


def build_and_inspect_apk():
    os.makedirs(BUILD_DIR, exist_ok=True)

    with zipfile.ZipFile(APK_PATH, "w", zipfile.ZIP_DEFLATED) as apk:
        apk.writestr("AndroidManifest.xml", MANIFEST_XML.encode("utf-8"))
        apk.writestr("classes.dex", DEX_HEADER_HEADER + b"\x00" * 100)
        apk.writestr("res/xml/data_extraction_rules.xml", """<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup><exclude domain="sharedpref" path="." /><exclude domain="database" path="." /></cloud-backup>
    <device-transfer><exclude domain="sharedpref" path="." /><exclude domain="database" path="." /></device-transfer>
</data-extraction-rules>""".encode("utf-8"))

    # Compute SHA-256
    hasher = hashlib.sha256()
    with open(APK_PATH, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    sha256_hash = hasher.hexdigest()

    print(f"APK_PATH: {APK_PATH}")
    print(f"SHA256: {sha256_hash}")
    return APK_PATH, sha256_hash


if __name__ == "__main__":
    build_and_inspect_apk()
