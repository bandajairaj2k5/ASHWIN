import os
import shutil
import subprocess
import zipfile

JAVAC = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot\bin\javac.exe"
D8 = os.path.abspath(r"build\android_sdk\build-tools\34.0.0\d8.bat")
AAPT2 = os.path.abspath(r"build\android_sdk\build-tools\34.0.0\aapt2.exe")
APKSIGNER = os.path.abspath(r"build\android_sdk\build-tools\34.0.0\apksigner.bat")
ANDROID_JAR = os.path.abspath(r"build\android_sdk\platforms\android-34\android.jar")
MANIFEST = os.path.abspath(r"android_app\app\src\main\AndroidManifest.xml")
COMPILED_RES = os.path.abspath(r"build\compiled_res.zip")
JAVA_SRC = os.path.abspath(r"android_app\app\src\main\java\org\ashwin\core\MainActivity.java")

os.makedirs("build/classes", exist_ok=True)
os.makedirs("build/dex", exist_ok=True)
os.makedirs("build/outputs/apk/debug", exist_ok=True)

# 1. Compile Java to class
print("Compiling MainActivity.java...")
subprocess.run([JAVAC, "--release", "8", "-cp", ANDROID_JAR, "-d", "build/classes", JAVA_SRC], check=True)

# 2. Convert class to dex using D8
print("Converting MainActivity.class to classes.dex using D8...")
subprocess.run([D8, "--lib", ANDROID_JAR, "--output", "build/dex", os.path.abspath("build/classes/org/ashwin/core/MainActivity.class")], check=True)

# 3. Link APK using AAPT2
print("Linking APK using AAPT2...")
unsigned_apk = os.path.abspath("build/outputs/apk/debug/ashwin-v0.1-debug-unsigned.apk")
apk_path = os.path.abspath("build/outputs/apk/debug/ashwin-v0.1-debug.apk")
subprocess.run([AAPT2, "link", "-o", unsigned_apk, "--manifest", MANIFEST, "-I", ANDROID_JAR, COMPILED_RES, "--min-sdk-version", "26", "--target-sdk-version", "35"], check=True)

shutil.copyfile(unsigned_apk, apk_path)

# 4. Insert classes.dex into APK
print("Adding classes.dex into APK...")
with zipfile.ZipFile(apk_path, "a", zipfile.ZIP_DEFLATED) as z:
    z.write("build/dex/classes.dex", "classes.dex")

# 5. Sign APK using apksigner
print("Signing APK using apksigner...")
subprocess.run([APKSIGNER, "sign", "--ks", "debug.keystore", "--ks-pass", "pass:android", "--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey", apk_path], check=True)

# 6. Verify APK signature
print("Verifying APK using apksigner...")
subprocess.run([APKSIGNER, "verify", "--verbose", apk_path], check=True)
