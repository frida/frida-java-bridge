@echo off

npx frida-compile index.js -o out/frida-java-bridge.js -c -S -B esm -T none