"""
Fetches official android.jar from Google Android Repository for AAPT2 linking.
"""

import os
import sys
import urllib.request
import zipfile

SDK_DIR = os.path.abspath("build/android_sdk")
JAR_PATH = os.path.join(SDK_DIR, "android.jar")


def fetch_android_jar():
    if os.path.exists(JAR_PATH):
        print(f"android.jar already exists at {JAR_PATH}")
        return JAR_PATH

    os.makedirs(SDK_DIR, exist_ok=True)
    url = "https://dl.google.com/android/repository/platform-34_r01.zip"
    zip_path = os.path.join(SDK_DIR, "platform-34.zip")

    print(f"Downloading official android.jar from {url}...")
    urllib.request.urlretrieve(url, zip_path)

    print("Extracting android.jar...")
    with zipfile.ZipFile(zip_path, "r") as z:
        for name in z.namelist():
            if name.endswith("android.jar"):
                with z.open(name) as src, open(JAR_PATH, "wb") as dst:
                    dst.write(src.read())
                break

    if os.path.exists(zip_path):
        os.remove(zip_path)

    print(f"android.jar successfully extracted to {JAR_PATH}")
    return JAR_PATH


if __name__ == "__main__":
    fetch_android_jar()
