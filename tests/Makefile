frida_version := 9.1.1

all: build/armeabi-v7a/frida-java-tests build/frida-java-tests.dex

build/armeabi-v7a/frida-java-tests: runner.c build/obj/local/armeabi-v7a/libfrida-gumjs.a
	$$ANDROID_NDK_ROOT/ndk-build \
		NDK_PROJECT_PATH=$$(pwd) \
		NDK_APPLICATION_MK=$$(pwd)/Application.mk \
		NDK_OUT=$$(pwd)/build/obj \
		NDK_LIBS_OUT=$$(pwd)/build

build/obj/local/armeabi-v7a/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-android-arm.tar.xz | tar -xJf - -C $(@D)

build/frida-java-tests.dex: build/frida-java-tests.jar
	dx --dex --output=$@ $<

build/frida-java-tests.jar: build/java/re/frida/test/Runner.class
	jar cfe $@ -C build/java re/

build/java/re/frida/test/Runner.class: re/frida/test/Runner.java
	@mkdir -p build/java/
	javac -cp . -source 1.7 -target 1.7 re/frida/test/Runner.java -d build/java/

.PHONY: all
