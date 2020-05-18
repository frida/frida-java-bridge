# frida-java-bridge

Java runtime interop from Frida. This module is bundled with Frida and exposed
through the global named `Java`.

## Running the test-suite

### Dependencies

- Android SDK Platform-Tools >= 27.0.1
- Android NDK r21

With environment configured accordingly:

```sh
$ export ANDROID_SDK_ROOT=~/Library/Android/Sdk
$ export ANDROID_NDK_ROOT=/usr/local/opt/android-ndk-r21
```

### Configuration

 - Go to `/test/config.mk` for editing the device configuration settings.

### Run

```sh
$ make check
```

### Debug

```sh
$ make check-gdb
```

### Auto-run tests on JavaScript change

```sh
$ make develop
```
