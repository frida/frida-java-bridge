frida_version := 9.0.13

all:
	@echo "Nothing to build. To run the test-suite: make check"

check: tests/build/armeabi-v7a/frida-java-tests
	export ANDROID_SERIAL=emulator-5554 \
		&& adb push $< /data/local/tmp \
		&& adb shell /data/local/tmp/frida-java-tests

tests/build/armeabi-v7a/frida-java-tests: tests/runner.c tests/build/obj/local/armeabi-v7a/libfrida-gumjs.a
	cd tests && \
		$$ANDROID_NDK_ROOT/ndk-build \
			NDK_PROJECT_PATH=$$(pwd) \
			NDK_APPLICATION_MK=$$(pwd)/Application.mk \
			NDK_OUT=$$(pwd)/build/obj \
			NDK_LIBS_OUT=$$(pwd)/build

tests/build/obj/local/armeabi-v7a/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-android-arm.tar.xz | tar -xJf - -C $(@D)

.PHONY: all check
