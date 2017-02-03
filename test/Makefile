ANDROID_SDK_ROOT ?= ~/Library/Android/sdk
ANDROID_NDK_ROOT ?= /usr/local/opt/android-ndk-r13b
DEBUG_PORT ?= 5042

build_os_arch := $(shell uname -s | tr -s "[A-Z]" "[a-z]")-$(shell uname -m)

android_platform := android-23
android_arch := arm
android_abi := armeabi-v7a
android_toolchain := arm-linux-androideabi-4.9
android_toolprefix = arm-linux-androideabi
android_sysroot := $(ANDROID_NDK_ROOT)/platforms/$(android_platform)/arch-$(android_arch)
android_libdir := /system/lib

deploy_prefix := /data/local/tmp
deploy_data_dir := $(deploy_prefix)/frida-java-tests

frida_version := 9.1.1

test_sources := $(wildcard re/frida/*.java)
test_classes := $(patsubst %.java,%.class,$(test_sources))

android_jar := $(abspath $(ANDROID_SDK_ROOT))/platforms/$(android_platform)/android.jar

all:
	@echo "Available targets: deploy run"

clean:
	rm -rf build

deploy: build/armeabi-v7a/runner build/tests.dex build/frida-java.js
	adb shell "rm -rf $(deploy_data_dir) && mkdir -p $(deploy_data_dir)"
	adb push $^ $(deploy_data_dir)

run:
	adb shell $(deploy_data_dir)/runner

watch:
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-java.js \
		-c "adb push build/frida-java.js $(deploy_data_dir) \
			&& adb shell $(deploy_data_dir)/runner"

debug: build/gdb.setup
	adb shell "rm -f $(deploy_data_dir)/debug-socket"
	adb push $(ANDROID_NDK_ROOT)/prebuilt/android-$(android_arch)/gdbserver/gdbserver $(deploy_data_dir)
	adb shell "$(deploy_data_dir)/gdbserver +$(deploy_data_dir)/debug-socket $(deploy_data_dir)/runner" &
	sleep 1
	adb forward tcp:$(DEBUG_PORT) localfilesystem:$(deploy_data_dir)/debug-socket
	$(ANDROID_NDK_ROOT)/prebuilt/$(build_os_arch)/bin/gdb -x build/gdb.setup

build/gdb.setup: build/symbols.stamp
	( \
		echo "set solib-search-path $(abspath build/symbols/$(android_libdir))"; \
		echo "directory $(android_sysroot)/usr/include"; \
		echo "directory $(abspath .)"; \
		echo "file $(abspath build/obj/local/$(android_abi)/runner)"; \
		echo "target remote :$(DEBUG_PORT)"; \
	) > $@

build/symbols.stamp:
	rm -rf build/symbols
	mkdir -p build/symbols/$(android_libdir)/
	adb pull -a \
		$(android_libdir)/libc.so \
		$(android_libdir)/libart.so \
		build/symbols/$(android_libdir)/
	touch $@

build/armeabi-v7a/runner: runner.c build/obj/local/armeabi-v7a/libfrida-gumjs.a
	$(ANDROID_NDK_ROOT)/ndk-build \
		NDK_PROJECT_PATH=$$(pwd) \
		NDK_APPLICATION_MK=$$(pwd)/Application.mk \
		NDK_OUT=$$(pwd)/build/obj \
		NDK_LIBS_OUT=$$(pwd)/build \
		FRIDA_JAVA_TESTS_DATA_DIR=$(deploy_data_dir)

build/obj/local/armeabi-v7a/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-android-arm.tar.xz | tar -xJf - -C $(@D)

build/tests.dex: build/tests.jar
	dx --dex --output=$@ $<

build/tests.jar: $(test_sources) build/junit.jar build/hamcrest.jar
	@rm -rf build/java/
	@mkdir -p build/java/
	cd build/java/ \
		&& jar xf ../junit.jar \
		&& jar xf ../hamcrest.jar
	javac \
		-cp .:build/java/:$(android_jar) \
		-bootclasspath $(android_jar) \
		-source 1.7 \
		-target 1.7 \
		$(test_sources) \
		-d build/java/
	jar cfe $@ re.frida.tests.Runner -C build/java .

build/junit.jar:
	@mkdir -p $(@D)
	curl -Ls https://github.com/junit-team/junit4/releases/download/r4.12/junit-4.12.jar > $@

build/hamcrest.jar:
	@mkdir -p $(@D)
	curl -Ls https://search.maven.org/remotecontent?filepath=org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar > $@

build/frida-java.js: node_modules
	npm run build

node_modules: package.json
	npm install

.PHONY: all clean deploy run watch debug
