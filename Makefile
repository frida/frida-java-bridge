all:
	@echo "Nothing to build. To run the test-suite: make check"

check:
	make -C test
	export ANDROID_SERIAL=emulator-5554 \
		&& adb push test/build/armeabi-v7a/frida-java-tests /data/local/tmp \
		&& adb push test/build/frida-java-tests.dex /data/local/tmp/ \
		&& adb shell /data/local/tmp/frida-java-tests

.PHONY: all check
