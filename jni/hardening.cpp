#define _GNU_SOURCE
#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>

static uint8_t g_derived_key[32];
static bool g_key_initialized = false;

// TRIPWIRE FLAGS:
// 0x01 = JNI_OnLoad initialized & RegisterNatives bound
// 0x02 = Bootstrap / MyApplication boot marked
// 0x04 = AuthHelper beacon / token verified
static volatile int g_tripwire_phase = 0;
static volatile int g_decrypt_count = 0;

// 1. Direct Syscall Kill (ARM64 & ARMv7 Safe)
static void silent_die() {
#if defined(__aarch64__)
    register long x8 __asm__("x8") = 129; // __NR_kill ARM64
    register long x0 __asm__("x0") = getpid();
    register long x1 __asm__("x1") = SIGKILL;
    __asm__ volatile(
        "svc #0\n"
        : "=r"(x0)
        : "r"(x8), "r"(x0), "r"(x1)
        : "memory"
    );
#elif defined(__arm__)
    register long r0 __asm__("r0") = getpid();
    register long r1 __asm__("r1") = SIGKILL;
    __asm__ volatile(
        "push {r7}\n"
        "mov r7, #37\n"       // __NR_kill ARMv7
        "svc #0\n"
        "pop {r7}\n"
        : "=r"(r0)
        : "r"(r0), "r"(r1)
        : "r7", "memory"
    );
#else
    kill(getpid(), SIGKILL);
#endif
    _exit(0);
}

// 2. Anti-Debug Kernel Tracer Check
static void check_tracer() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buffer[1024];
        ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            char* tracer = strstr(buffer, "TracerPid:");
            if (tracer && atoi(tracer + 10) != 0) {
                silent_die();
            }
        }
    }
}

// 3. Helper Context Universal (Android 10 - Android 15 / ColorOS / realme UI)
static bool get_ctx_and_pkg(JNIEnv* env, jobject* outCtx, jstring* outPkg) {
    char pkgBuf[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, pkgBuf, sizeof(pkgBuf) - 1);
        close(fd);
        if (n > 0) {
            pkgBuf[n] = '\0';
            char* colon = strchr(pkgBuf, ':');
            if (colon) *colon = '\0';
        }
    }

    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (!atCls) {
        env->ExceptionClear();
        return false;
    }

    // Jalur 1: currentApplication()
    jmethodID curAppId = env->GetStaticMethodID(atCls, "currentApplication", "()Landroid/app/Application;");
    if (curAppId) {
        jobject appObj = env->CallStaticObjectMethod(atCls, curAppId);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (appObj) {
            *outCtx = appObj;
            if (pkgBuf[0] != '\0') {
                *outPkg = env->NewStringUTF(pkgBuf);
            } else {
                jclass ctxCls = env->GetObjectClass(appObj);
                jmethodID getPkgId = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
                *outPkg = (jstring)env->CallObjectMethod(appObj, getPkgId);
            }
            return (*outPkg != nullptr);
        }
    } else {
        env->ExceptionClear();
    }

    // Jalur 2: currentActivityThread().getSystemContext()
    if (pkgBuf[0] == '\0') return false;

    jmethodID curAtId = env->GetStaticMethodID(atCls, "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (!curAtId) { env->ExceptionClear(); return false; }

    jobject atObj = env->CallStaticObjectMethod(atCls, curAtId);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!atObj) return false;

    jmethodID getSysCtxId = env->GetMethodID(atCls, "getSystemContext", "()Landroid/app/ContextImpl;");
    if (!getSysCtxId) { env->ExceptionClear(); return false; }

    jobject sysCtx = env->CallObjectMethod(atObj, getSysCtxId);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!sysCtx) return false;

    *outCtx = sysCtx;
    *outPkg = env->NewStringUTF(pkgBuf);
    return (*outPkg != nullptr);
}

// 4. Rakit AUTH_SECRET_KEY di Stack ("Sann_026_x9F")
static void get_auth_secret(char out[13]) {
    const uint8_t masked[12] = {
        0x20, 0x12, 0x1D, 0x1D, 0x2C, 0x43,
        0x41, 0x45, 0x2C, 0x0B, 0x4A, 0x35
    };
    for (int i = 0; i < 12; i++) {
        out[i] = (char)(masked[i] ^ 0x73);
    }
    out[12] = '\0';
}

// Rakit URL Endpoint di Stack (XOR 0x55) - Zero Plaintext di Binary .so & Smali
static jstring build_validate_url(JNIEnv* env, jclass clazz) {
    // "http://zanspterodactyl.shoppanel.my.id:2037/api/auth/validate" (61 bytes)
    const uint8_t enc[61] = {
        0x3D, 0x21, 0x21, 0x25, 0x6F, 0x7A, 0x7A,
        0x2F, 0x34, 0x3B, 0x26, 0x25, 0x21, 0x30, 0x27, 0x3A, 0x31, 0x34, 0x36, 0x21, 0x2C, 0x39,
        0x7B, 0x26, 0x3D, 0x3A, 0x25, 0x25, 0x34, 0x3B, 0x30, 0x39,
        0x7B, 0x38, 0x2C, 0x7B, 0x3C, 0x31,
        0x6F, 0x67, 0x65, 0x66, 0x62,
        0x7A, 0x34, 0x25, 0x3C, 0x7A, 0x34, 0x20, 0x21, 0x3D, 0x7A,
        0x23, 0x34, 0x39, 0x3C, 0x31, 0x34, 0x21, 0x30
    };
    char buf[62];
    for (int i = 0; i < 61; i++) {
        buf[i] = (char)(enc[i] ^ 0x55);
    }
    buf[61] = '\0';
    jstring res = env->NewStringUTF(buf);
    memset(buf, 0, sizeof(buf));
    return res;
}

static jstring build_crash_url(JNIEnv* env, jclass clazz) {
    // "http://zanspterodactyl.shoppanel.my.id:2037/api/auth/crash" (58 bytes)
    const uint8_t enc[58] = {
        0x3D, 0x21, 0x21, 0x25, 0x6F, 0x7A, 0x7A,
        0x2F, 0x34, 0x3B, 0x26, 0x25, 0x21, 0x30, 0x27, 0x3A, 0x31, 0x34, 0x36, 0x21, 0x2C, 0x39,
        0x7B, 0x26, 0x3D, 0x3A, 0x25, 0x25, 0x34, 0x3B, 0x30, 0x39,
        0x7B, 0x38, 0x2C, 0x7B, 0x3C, 0x31,
        0x6F, 0x67, 0x65, 0x66, 0x62,
        0x7A, 0x34, 0x25, 0x3C, 0x7A, 0x34, 0x20, 0x21, 0x3D, 0x7A,
        0x36, 0x27, 0x34, 0x26, 0x3D
    };
    char buf[59];
    for (int i = 0; i < 58; i++) {
        buf[i] = (char)(enc[i] ^ 0x55);
    }
    buf[58] = '\0';
    jstring res = env->NewStringUTF(buf);
    memset(buf, 0, sizeof(buf));
    return res;
}


// 5. 32-Byte Rolling SHA-256 Key Derivation dari Signature Runtime
static void set_fallback_key() {
    memset(g_derived_key, 0x5A, 32);
    g_key_initialized = true;
}

static const uint8_t* get_dynamic_key_32(JNIEnv* env) {
    if (g_key_initialized) return g_derived_key;

    jobject context = nullptr;
    jstring pkgName = nullptr;
    if (!get_ctx_and_pkg(env, &context, &pkgName)) {
        set_fallback_key();
        return g_derived_key;
    }

    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getPkgMgr = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pkgMgr = env->CallObjectMethod(context, getPkgMgr);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!pkgMgr) { set_fallback_key(); return g_derived_key; }

    jclass pmCls = env->GetObjectClass(pkgMgr);
    jmethodID getPkgInfo = env->GetMethodID(pmCls, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    jobject pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x08000000); // GET_SIGNING_CERTIFICATES
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!pkgInfo) {
        pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x00000040); // GET_SIGNATURES
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!pkgInfo) { set_fallback_key(); return g_derived_key; }

    jclass piCls = env->GetObjectClass(pkgInfo);
    jbyteArray certBytes = nullptr;

    jfieldID signingInfoField = env->GetFieldID(piCls, "signingInfo", "Landroid/content/pm/SigningInfo;");
    if (signingInfoField) {
        jobject signingInfo = env->GetObjectField(pkgInfo, signingInfoField);
        if (signingInfo) {
            jclass siCls = env->GetObjectClass(signingInfo);
            jmethodID getSigners = env->GetMethodID(siCls, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            jobjectArray sigs = (jobjectArray)env->CallObjectMethod(signingInfo, getSigners);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (sigs && env->GetArrayLength(sigs) > 0) {
                jobject sig = env->GetObjectArrayElement(sigs, 0);
                jclass sigCls = env->GetObjectClass(sig);
                jmethodID toByteArr = env->GetMethodID(sigCls, "toByteArray", "()[B");
                certBytes = (jbyteArray)env->CallObjectMethod(sig, toByteArr);
            }
        }
    } else {
        env->ExceptionClear();
    }

    if (!certBytes) {
        jfieldID sigsField = env->GetFieldID(piCls, "signatures", "[Landroid/content/pm/Signature;");
        if (sigsField) {
            jobjectArray sigs = (jobjectArray)env->GetObjectField(pkgInfo, sigsField);
            if (sigs && env->GetArrayLength(sigs) > 0) {
                jobject sig = env->GetObjectArrayElement(sigs, 0);
                jclass sigCls = env->GetObjectClass(sig);
                jmethodID toByteArr = env->GetMethodID(sigCls, "toByteArray", "()[B");
                certBytes = (jbyteArray)env->CallObjectMethod(sig, toByteArr);
            }
        } else {
            env->ExceptionClear();
        }
    }

    if (!certBytes) { set_fallback_key(); return g_derived_key; }

    jclass mdCls = env->FindClass("java/security/MessageDigest");
    jmethodID getInst = env->GetStaticMethodID(mdCls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring shaStr = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInst, shaStr);

    jmethodID digestMethod = env->GetMethodID(mdCls, "digest", "([B)[B");
    jbyteArray digestBytes = (jbyteArray)env->CallObjectMethod(md, digestMethod, certBytes);
    if (!digestBytes || env->GetArrayLength(digestBytes) < 32) {
        set_fallback_key();
        return g_derived_key;
    }

    jbyte* pBytes = env->GetByteArrayElements(digestBytes, nullptr);
    memcpy(g_derived_key, pBytes, 32);
    env->ReleaseByteArrayElements(digestBytes, pBytes, JNI_ABORT);

    g_key_initialized = true;
    return g_derived_key;
}

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char* in, int in_len, unsigned char* out) {
    int out_len = 0;
    int val = 0, valb = -8;
    for (int i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=') break;
        int d = b64_char_val(c);
        if (d == -1) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            out[out_len++] = (unsigned char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out_len;
}

// 6. Native Implementation Functions
static void JNICALL native_mark_boot(JNIEnv *env, jclass clazz) {
    g_tripwire_phase |= 0x02;
}

static void JNICALL native_beacon(JNIEnv *env, jclass clazz, jlong nonce) {
    if (nonce != 0) {
        g_tripwire_phase |= 0x04;
    }
}

static jstring JNICALL native_decrypt(JNIEnv *env, jclass clazz, jstring input) {
    if (!input) return nullptr;

    check_tracer();
    g_decrypt_count++;

    if ((g_tripwire_phase & 0x03) != 0x03) {
        silent_die();
        return nullptr;
    }

    if (g_decrypt_count > 5000 && (g_tripwire_phase & 0x04) != 0x04) {
        silent_die();
        return nullptr;
    }

    const char* str = env->GetStringUTFChars(input, nullptr);
    if (!str) return nullptr;

    int in_len = strlen(str);
    unsigned char* decoded = (unsigned char*)malloc(in_len + 1);
    if (!decoded) {
        env->ReleaseStringUTFChars(input, str);
        return nullptr;
    }

    int decoded_len = b64_decode(str, in_len, decoded);
    const uint8_t* key32 = get_dynamic_key_32(env);

    for (int i = 0; i < decoded_len; i++) {
        decoded[i] ^= key32[i % 32];
    }
    decoded[decoded_len] = '\0';

    jstring result = env->NewStringUTF((char*)decoded);
    free(decoded);
    env->ReleaseStringUTFChars(input, str);
    return result;
}

static jboolean JNICALL native_verify_token(JNIEnv *env, jclass clazz, jstring hwid, jstring token, jlong ts) {
    check_tracer();

    if (!hwid || !token) {
        silent_die();
        return JNI_FALSE;
    }

    jclass sysCls = env->FindClass("java/lang/System");
    if (sysCls) {
        jmethodID curTimeId = env->GetStaticMethodID(sysCls, "currentTimeMillis", "()J");
        if (curTimeId) {
            jlong nowMs = env->CallStaticLongMethod(sysCls, curTimeId);
            long long diff = (long long)(nowMs - ts);
            if (diff < 0) diff = -diff;
            if (diff > 86400000LL) {
                silent_die();
                return JNI_FALSE;
            }
        }
    }

    const char* cHwid = env->GetStringUTFChars(hwid, nullptr);
    const char* cToken = env->GetStringUTFChars(token, nullptr);

    char payload[256];
    snprintf(payload, sizeof(payload), "%s:%lld", cHwid, (long long)ts);

    char secretKeyStr[13];
    get_auth_secret(secretKeyStr);

    jclass macCls = env->FindClass("javax/crypto/Mac");
    jmethodID getMacInst = env->GetStaticMethodID(macCls, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Mac;");
    jstring algoStr = env->NewStringUTF("HmacSHA256");
    jobject mac = env->CallStaticObjectMethod(macCls, getMacInst, algoStr);

    jclass keySpecCls = env->FindClass("javax/crypto/spec/SecretKeySpec");
    jmethodID keySpecInit = env->GetMethodID(keySpecCls, "<init>", "([BLjava/lang/String;)V");

    jbyteArray keyBytes = env->NewByteArray(12);
    env->SetByteArrayRegion(keyBytes, 0, 12, (const jbyte*)secretKeyStr);
    jobject secretKey = env->NewObject(keySpecCls, keySpecInit, keyBytes, algoStr);

    memset(secretKeyStr, 0, sizeof(secretKeyStr));

    jmethodID macInit = env->GetMethodID(macCls, "init", "(Ljava/security/Key;)V");
    env->CallVoidMethod(mac, macInit, secretKey);

    jbyteArray payloadBytes = env->NewByteArray(strlen(payload));
    env->SetByteArrayRegion(payloadBytes, 0, strlen(payload), (const jbyte*)payload);

    jmethodID doFinalMethod = env->GetMethodID(macCls, "doFinal", "([B)[B");
    jbyteArray hmacBytes = (jbyteArray)env->CallObjectMethod(mac, doFinalMethod, payloadBytes);

    jsize hmacLen = env->GetArrayLength(hmacBytes);
    jbyte* pBytes = env->GetByteArrayElements(hmacBytes, nullptr);

    char expectedHex[65];
    for (int i = 0; i < hmacLen && i < 32; i++) {
        sprintf(expectedHex + (i * 2), "%02x", (unsigned char)pBytes[i]);
    }
    expectedHex[64] = '\0';
    env->ReleaseByteArrayElements(hmacBytes, pBytes, JNI_ABORT);

    bool isValid = (strcasecmp(cToken, expectedHex) == 0);

    env->ReleaseStringUTFChars(hwid, cHwid);
    env->ReleaseStringUTFChars(token, cToken);

    if (!isValid) {
        silent_die();
        return JNI_FALSE;
    }

    g_tripwire_phase |= 0x04;
    return JNI_TRUE;
}

static jobject JNICALL native_load_memory_dex(JNIEnv *env, jclass clazz, jobject context, jbyteArray encDexBytes) {
    if (!context || !encDexBytes) return nullptr;

    jsize len = env->GetArrayLength(encDexBytes);
    if (len < 112) return nullptr;

    jbyte* pData = env->GetByteArrayElements(encDexBytes, nullptr);
    const uint8_t* key32 = get_dynamic_key_32(env);

    uint8_t magic[4];
    for (int i = 0; i < 4; i++) {
        magic[i] = ((uint8_t)pData[i]) ^ key32[i % 32];
    }
    if (magic[0] != 'd' || magic[1] != 'e' || magic[2] != 'x' || magic[3] != '\n') {
        env->ReleaseByteArrayElements(encDexBytes, pData, JNI_ABORT);
        return nullptr;
    }

    jclass bbCls = env->FindClass("java/nio/ByteBuffer");
    jmethodID allocDirect = env->GetStaticMethodID(bbCls, "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
    jobject byteBuffer = env->CallStaticObjectMethod(bbCls, allocDirect, len);
    if (!byteBuffer) {
        env->ReleaseByteArrayElements(encDexBytes, pData, JNI_ABORT);
        return nullptr;
    }

    uint8_t* dstPtr = (uint8_t*)env->GetDirectBufferAddress(byteBuffer);
    if (!dstPtr) {
        env->ReleaseByteArrayElements(encDexBytes, pData, JNI_ABORT);
        return nullptr;
    }

    for (int i = 0; i < len; i++) {
        dstPtr[i] = ((uint8_t)pData[i]) ^ key32[i % 32];
    }
    env->ReleaseByteArrayElements(encDexBytes, pData, JNI_ABORT);

    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getClassLoader = env->GetMethodID(ctxCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject parentLoader = env->CallObjectMethod(context, getClassLoader);

    jclass inMemCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!inMemCls) return nullptr;

    jmethodID initMethod = env->GetMethodID(inMemCls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    return env->NewObject(inMemCls, initMethod, byteBuffer, parentLoader);
}

// 7. Dynamic JNI Binding via AndroidManifest <meta-data> (Safe Init tanpa silent_die)
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }

    jobject sysCtx = nullptr;
    jstring pkgName = nullptr;
    if (!get_ctx_and_pkg(env, &sysCtx, &pkgName)) {
        return JNI_ERR;
    }

    jclass ctxCls = env->GetObjectClass(sysCtx);
    jmethodID getPkgMgr = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pkgMgr = env->CallObjectMethod(sysCtx, getPkgMgr);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!pkgMgr) return JNI_ERR;

    jclass pmCls = env->GetObjectClass(pkgMgr);
    jmethodID getAppInfo = env->GetMethodID(pmCls, "getApplicationInfo", "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(pkgMgr, getAppInfo, pkgName, 0x00000080); // GET_META_DATA
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!appInfo) return JNI_ERR;

    jclass aiCls = env->GetObjectClass(appInfo);
    jfieldID metaField = env->GetFieldID(aiCls, "metaData", "Landroid/os/Bundle;");
    jobject metaBundle = env->GetObjectField(appInfo, metaField);
    if (!metaBundle) return JNI_ERR;

    jclass bundleCls = env->GetObjectClass(metaBundle);
    jmethodID getString = env->GetMethodID(bundleCls, "getString", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring metaKey = env->NewStringUTF("androidx.startup.profile");
    jstring metaVal = (jstring)env->CallObjectMethod(metaBundle, getString, metaKey);
    if (!metaVal) return JNI_ERR;

    const char* rawCfg = env->GetStringUTFChars(metaVal, nullptr);
    char cfgBuf[256];
    strncpy(cfgBuf, rawCfg, sizeof(cfgBuf) - 1);
    cfgBuf[sizeof(cfgBuf) - 1] = '\0';
    env->ReleaseStringUTFChars(metaVal, rawCfg);

    char* sep = strchr(cfgBuf, '|');
    if (!sep) return JNI_ERR;
    *sep = '\0';
    const char* bootClassName = cfgBuf;
    const char* decClassName = sep + 1;

    jclass bootCls = env->FindClass(bootClassName);
    jclass decCls = env->FindClass(decClassName);
    if (!bootCls || !decCls) return JNI_ERR;

    static const JNINativeMethod bootMethods[] = {
        { "markBoot", "()V", (void*)&native_mark_boot }
    };
        static const JNINativeMethod decMethods[] = {
        { "nativeDecrypt", "(Ljava/lang/String;)Ljava/lang/String;", (void*)&native_decrypt },
        { "verifyToken", "(Ljava/lang/String;Ljava/lang/String;J)Z", (void*)&native_verify_token },
        { "beacon", "(J)V", (void*)&native_beacon },
        { "loadMemoryDex", "(Landroid/content/Context;[B)Ljava/lang/ClassLoader;", (void*)&native_load_memory_dex },
        { "getValidateUrl", "()Ljava/lang/String;", (void*)&build_validate_url },
        { "getCrashUrl", "()Ljava/lang/String;", (void*)&build_crash_url }
    };

    if (env->RegisterNatives(bootCls, bootMethods, 1) < 0 ||
        env->RegisterNatives(decCls, decMethods, 6) < 0) {
        return JNI_ERR;
    }

    g_tripwire_phase |= 0x01;
    return JNI_VERSION_1_6;
}
