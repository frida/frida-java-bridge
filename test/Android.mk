LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := runner
LOCAL_SRC_FILES := runner.c dummy.cpp
LOCAL_STATIC_LIBRARIES := frida-gumjs
LOCAL_SHARED_LIBRARIES := artpalette
LOCAL_CFLAGS := -Wall -Werror \
	-DFRIDA_JAVA_TESTS_DATA_DIR=\"$(FRIDA_JAVA_TESTS_DATA_DIR)\" \
	-DFRIDA_JAVA_TESTS_CACHE_DIR=\"$(FRIDA_JAVA_TESTS_CACHE_DIR)\"
LOCAL_LDFLAGS := -Wl,--version-script,runner.version -Wl,--export-dynamic
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := frida-gumjs
LOCAL_SRC_FILES := build/obj/local/$(TARGET_ARCH_ABI)/libfrida-gumjs.a
LOCAL_EXPORT_C_INCLUDES := build/obj/local/$(TARGET_ARCH_ABI)
LOCAL_EXPORT_LDLIBS := -llog
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := artpalette
LOCAL_SRC_FILES := artpalette.c
include $(BUILD_SHARED_LIBRARY)
