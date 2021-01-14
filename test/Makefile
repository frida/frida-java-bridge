include config.mk

build_os_arch := $(shell uname -s | tr -s "[A-Z]" "[a-z]")-$(shell uname -m)

android_platform := android-$(ANDROID_API_LEVEL)
android_sysroot := $(ANDROID_NDK_ROOT)/platforms/$(android_platform)/arch-$(ANDROID_ARCH)

deploy_prefix := /data/local/tmp
deploy_data_dir := $(deploy_prefix)/frida-java-bridge-tests
deploy_cache_dir := $(deploy_data_dir)/dalvik-cache

frida_version := 14.2.3

test_sources := $(wildcard re/frida/*.java)
test_classes := $(patsubst %.java,%.class,$(test_sources))

android_jar := $(ANDROID_SDK_ROOT)/platforms/$(android_platform)/android.jar

all:
	@echo "Available targets: deploy run"

clean:
	rm -rf build

deploy: build/$(ANDROID_ABI)/runner build/tests.dex build/frida-java-bridge.js
	adb shell "rm -rf $(deploy_data_dir) && mkdir -p $(deploy_data_dir)"
	adb push $^ build/$(ANDROID_ABI)/libartpalette.so $(deploy_data_dir)

run:
	adb shell "LD_LIBRARY_PATH='$(APEX_LIBDIRS):$(deploy_data_dir)' $(deploy_data_dir)/runner $(RUNNER_ARGS)"

watch:
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-java-bridge.js \
		-c "adb push build/frida-java-bridge.js $(deploy_data_dir) \
			&& adb shell 'LD_LIBRARY_PATH='$(APEX_LIBDIRS):$(deploy_data_dir)' $(deploy_data_dir)/runner $(RUNNER_ARGS)'"

debug: build/gdb.setup
	adb shell "rm -f $(deploy_data_dir)/debug-socket"
	adb push $(ANDROID_NDK_ROOT)/prebuilt/android-$(ANDROID_ARCH)/gdbserver/gdbserver $(deploy_data_dir)
	adb shell "$(deploy_data_dir)/gdbserver +$(deploy_data_dir)/debug-socket $(deploy_data_dir)/runner $(RUNNER_ARGS)" &
	sleep 1
	adb forward tcp:$(DEBUG_PORT) localfilesystem:$(deploy_data_dir)/debug-socket
	$(ANDROID_NDK_ROOT)/prebuilt/$(build_os_arch)/bin/gdb -x build/gdb.setup

build/gdb.setup: build/symbols.stamp
	( \
		echo "set sysroot $(abspath build/symbols/)"; \
		echo "directory $(android_sysroot)/usr/include"; \
		echo "directory $(abspath .)"; \
		echo "file $(abspath build/obj/local/$(ANDROID_ABI)/runner)"; \
		echo "target remote :$(DEBUG_PORT)"; \
	) > $@

build/symbols.stamp:
	rm -rf build/symbols
	mkdir -p build/symbols/$(ANDROID_BINDIR)/ build/symbols/$(ANDROID_LIBDIR)/
	adb pull -a $(ANDROID_BINDIR)/linker build/symbols/$(ANDROID_BINDIR)/
	adb pull -a $(shell adb shell "ls $(ANDROID_LIBDIR)/*.so") build/symbols/$(ANDROID_LIBDIR)/; \
	touch $@

build/$(ANDROID_ABI)/runner: runner.c artpalette.c build/obj/local/$(ANDROID_ABI)/libfrida-gumjs.a
	$(ANDROID_NDK_ROOT)/ndk-build \
		NDK_PROJECT_PATH=$$(pwd) \
		NDK_APPLICATION_MK=$$(pwd)/Application.mk \
		NDK_OUT=$$(pwd)/build/obj \
		NDK_LIBS_OUT=$$(pwd)/build \
		FRIDA_JAVA_TESTS_DATA_DIR=$(deploy_data_dir) \
		FRIDA_JAVA_TESTS_CACHE_DIR=$(deploy_cache_dir)

build/obj/local/$(ANDROID_ABI)/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-android-$(ANDROID_ARCH).tar.xz | tar -xJf - -C $(@D)

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
		-source 1.8 \
		-target 1.8 \
		-Xlint:deprecation \
		-Xlint:unchecked \
		$(test_sources) \
		-d build/java/
	jar cfe $@ re.frida.tests.Runner -C build/java .

build/junit.jar:
	@mkdir -p $(@D)
	curl -Ls https://github.com/junit-team/junit4/releases/download/r4.12/junit-4.12.jar > $@

build/hamcrest.jar:
	@mkdir -p $(@D)
	curl -Ls https://search.maven.org/remotecontent?filepath=org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar > $@

build/frida-java-bridge.js: node_modules
	npm run build

node_modules: package.json
	npm install

.PHONY: all clean deploy run watch debug
