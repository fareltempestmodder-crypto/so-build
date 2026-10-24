LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := hardening
LOCAL_SRC_FILES := hardening.cpp
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
