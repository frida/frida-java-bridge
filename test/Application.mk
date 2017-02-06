include config.mk

APP_ABI := $(ANDROID_ABI)
APP_PLATFORM := android-$(ANDROID_API_LEVEL)
APP_STL := c++_static
APP_BUILD_SCRIPT := Android.mk
