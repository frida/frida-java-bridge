frida_version := 9.1.1

test_sources := $(wildcard re/frida/*Test.java)
test_classes := $(patsubst %.java,%.class,$(test_sources))

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

build/frida-java-tests.jar: re/frida/TestRunner.java $(test_sources) build/junit.jar build/hamcrest.jar
	@rm -rf build/java/
	@mkdir -p build/java/
	cd build/java/ \
		&& jar xf ../junit.jar \
		&& jar xf ../hamcrest.jar
	javac \
		-cp .:build/java/ \
		-bootclasspath /Library/Java/JavaVirtualMachines/jdk1.8.0_31.jdk/Contents/Home/jre/lib/rt.jar \
		-source 1.7 \
		-target 1.7 \
		re/frida/TestRunner.java \
		$(test_sources) \
		-d build/java/
	jar cfe $@ re.frida.tests.Runner -C build/java .

build/junit.jar:
	@mkdir -p $(@D)
	curl -Ls https://github.com/junit-team/junit4/releases/download/r4.12/junit-4.12.jar > $@

build/hamcrest.jar:
	@mkdir -p $(@D)
	curl -Ls https://search.maven.org/remotecontent?filepath=org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar > $@

.PHONY: all
