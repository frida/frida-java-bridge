include config.mk

# The NDK aborts when APP_PLATFORM names an API level newer than the headers and stubs
# it ships, so clamp to the newest it knows. Harmless, as APP_PLATFORM is a minimum
# rather than a target: a runner built against an older platform runs on a newer one.
ndk_max_api := $(shell sed -n 's/^[[:space:]]*"max":[[:space:]]*\([0-9]*\).*/\1/p' $(ANDROID_NDK_ROOT)/meta/platforms.json 2>/dev/null)

APP_ABI := $(ANDROID_ABI)
APP_PLATFORM := android-$(firstword $(sort $(ANDROID_API_LEVEL) $(ndk_max_api)))
APP_STL := c++_static
APP_BUILD_SCRIPT := Android.mk
