@echo off
set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
set "ANDROID_HOME=C:\Users\banaj\OneDrive\Desktop\ASHWIN\build\android_sdk"
set "PATH=%JAVA_HOME%\bin;%ANDROID_HOME%\cmdline-tools\bin;%PATH%"
cd /d "c:\Users\banaj\OneDrive\Desktop\ASHWIN\android_app"
"c:\Users\banaj\OneDrive\Desktop\ASHWIN\build\gradle\gradle-8.7\bin\gradle.bat" assembleDebug --no-daemon --stacktrace
