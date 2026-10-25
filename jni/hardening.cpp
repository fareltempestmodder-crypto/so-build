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
#include <sys/mman.h>

static const char* AUTH_SECRET_KEY = "Sann_026_x9F";
static int g_derived_key = -1;

// TRIPWIRE STAGES:
// 0x01 = JNI_OnLoad
// 0x03 = Bootstrap/MyApplication loaded
// 0x07 = AuthHelper handshake beacon verified
static volatile int g_tripwire_phase = 0;

// === 1. DIRECT SYSCALL KILL ===
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
        "mov r7, #37\n"       // 37 = __NR_kill ARMv7
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

// === 2. ANTI-DEBUG TRACER & FRIDA PORT SCAN ===
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

// === 3. FITUR 4: IN-MEMORY BINARY INTEGRITY CHECK (Anti-Hex-Patching) ===
static void verify_binary_integrity() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[512];
    uintptr_t base_addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libhardening.so") && strstr(line, "r-xp")) {
            base_addr = (uintptr_t)strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(fp);

    if (base_addr != 0) {
        uint32_t* pCode = (uint32_t*)base_addr;
        // Pindai 256 instruksi pertama dari segmen eksekusi
        for (int i = 0; i < 256; i++) {
#if defined(__aarch64__)
            // Deteksi NOP opcode pada ARM64: 0xD503201F
            if (pCode[i] == 0xD503201F) {
                silent_die(); // Terdeteksi hex patch NOP
            }
#elif defined(__arm__)
            // Deteksi NOP opcode pada ARM32: 0xE1A00000
            if (pCode[i] == 0xE1A00000) {
                silent_die();
            }
#endif
        }
    }
}

// === 4. DYNAMIC KEY DERIVATION DARI SIGNATURE APK ===
static unsigned char get_dynamic_key(JNIEnv* env) {
    if (g_derived_key != -1) return (unsigned char)g_derived_key;

    jclass actThreadCls = env->FindClass("android/app/ActivityThread");
    if (!actThreadCls) { g_derived_key = 0x5A; return 0x5A; }

    jmethodID currentAppMethod = env->GetStaticMethodID(actThreadCls, "currentApplication", "()Landroid/app/Application;");
    if (!currentAppMethod) { g_derived_key = 0x5A; return 0x5A; }

    jobject context = env->CallStaticObjectMethod(actThreadCls, currentAppMethod);
    if (!context) { g_derived_key = 0x5A; return 0x5A; }

    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getPkgName = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    jmethodID getPkgMgr = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");

    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkgName);
    jobject pkgMgr = env->CallObjectMethod(context, getPkgMgr);

    jclass pmCls = env->GetObjectClass(pkgMgr);
    jmethodID getPkgInfo = env->GetMethodID(pmCls, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    jobject pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x08000000);
    if (!pkgInfo) pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x00000040);
    if (!pkgInfo) { g_derived_key = 0x5A; return 0x5A; }

    jclass piCls = env->GetObjectClass(pkgInfo);
    jbyteArray certBytes = nullptr;

    jfieldID signingInfoField = env->GetFieldID(piCls, "signingInfo", "Landroid/content/pm/SigningInfo;");
    if (signingInfoField) {
        jobject signingInfo = env->GetObjectField(pkgInfo, signingInfoField);
        if (signingInfo) {
            jclass siCls = env->GetObjectClass(signingInfo);
            jmethodID getSigners = env->GetMethodID(siCls, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            jobjectArray sigs = (jobjectArray)env->CallObjectMethod(signingInfo, getSigners);
            if (sigs && env->GetArrayLength(sigs) > 0) {
                jobject sig = env->GetObjectArrayElement(sigs, 0);
                jclass sigCls = env->GetObjectClass(sig);
                jmethodID toByteArr = env->GetMethodID(sigCls, "toByteArray", "()[B");
                certBytes = (jbyteArray)env->CallObjectMethod(sig, toByteArr);
            }
        }
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
        }
    }

    if (!certBytes) { g_derived_key = 0x5A; return 0x5A; }

    jclass mdCls = env->FindClass("java/security/MessageDigest");
    jmethodID getInst = env->GetStaticMethodID(mdCls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring shaStr = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInst, shaStr);

    jmethodID digestMethod = env->GetMethodID(mdCls, "digest", "([B)[B");
    jbyteArray digestBytes = (jbyteArray)env->CallObjectMethod(md, digestMethod, certBytes);
    if (!digestBytes) { g_derived_key = 0x5A; return 0x5A; }

    jbyte* pBytes = env->GetByteArrayElements(digestBytes, nullptr);
    unsigned char finalKey = (unsigned char)pBytes[0];
    if (finalKey == 0) finalKey = 0x5A;
    env->ReleaseByteArrayElements(digestBytes, pBytes, JNI_ABORT);

    g_derived_key = (int)finalKey;
    return finalKey;
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

// === 5. JNI INITIALIZATION ===
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    check_tracer();
    verify_binary_integrity();
    g_tripwire_phase |= 0x01; // Stage 1 passed
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
Java_sbx_Bootstrap_markBoot(JNIEnv *env, jclass clazz) {
    g_tripwire_phase |= 0x02; // Stage 2 passed
}

extern "C" JNIEXPORT void JNICALL
Java_sbx_StringDecryptor_beacon(JNIEnv *env, jclass clazz, jlong nonce) {
    // Validasi nonce tidak boleh nol
    if (nonce != 0) {
        g_tripwire_phase |= 0x04; // Stage 3 passed
    }
}

// === FITUR 2: ACTIVE DEFENSE TRIPWIRE DECRYPTOR ===
extern "C" JNIEXPORT jstring JNICALL
Java_sbx_StringDecryptor_nativeDecrypt(JNIEnv *env, jclass clazz, jstring input) {
    if (!input) return nullptr;

    check_tracer();
    verify_binary_integrity();

    // Mutual Suicide Check:
    // Jika fase awal (0x01 | 0x02 = 0x03) dilewati (misal Bootstrap dihapus dari manifest)
    if ((g_tripwire_phase & 0x03) != 0x03) {
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
    unsigned char key = get_dynamic_key(env);

    for (int i = 0; i < decoded_len; i++) {
        decoded[i] ^= key;
    }
    decoded[decoded_len] = '\0';

    jstring result = env->NewStringUTF((char*)decoded);
    free(decoded);
    env->ReleaseStringUTFChars(input, str);
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_sbx_StringDecryptor_verifyToken(JNIEnv *env, jclass clazz, jstring hwid, jstring token, jlong ts) {
    check_tracer();
    verify_binary_integrity();

    if (!hwid || !token) {
        silent_die();
        return JNI_FALSE;
    }

    const char* cHwid = env->GetStringUTFChars(hwid, nullptr);
    const char* cToken = env->GetStringUTFChars(token, nullptr);

    char payload[256];
    snprintf(payload, sizeof(payload), "%s:%lld", cHwid, (long long)ts);

    jclass macCls = env->FindClass("javax/crypto/Mac");
    jmethodID getMacInst = env->GetStaticMethodID(macCls, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Mac;");
    jstring algoStr = env->NewStringUTF("HmacSHA256");
    jobject mac = env->CallStaticObjectMethod(macCls, getMacInst, algoStr);

    jclass keySpecCls = env->FindClass("javax/crypto/spec/SecretKeySpec");
    jmethodID keySpecInit = env->GetMethodID(keySpecCls, "<init>", "([BLjava/lang/String;)V");

    jbyteArray keyBytes = env->NewByteArray(strlen(AUTH_SECRET_KEY));
    env->SetByteArrayRegion(keyBytes, 0, strlen(AUTH_SECRET_KEY), (const jbyte*)AUTH_SECRET_KEY);
    jobject secretKey = env->NewObject(keySpecCls, keySpecInit, keyBytes, algoStr);

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

    g_tripwire_phase |= 0x04; // Auth Handshake disahkan
    return JNI_TRUE;
}

// === FITUR 5: ENCRYPTED SECONDARY IN-MEMORY DEX LOADER ===
extern "C" JNIEXPORT jobject JNICALL
Java_sbx_StringDecryptor_loadMemoryDex(JNIEnv *env, jclass clazz, jobject context, jbyteArray encDexBytes) {
    check_tracer();
    verify_binary_integrity();

    if (!context || !encDexBytes) return nullptr;

    jsize len = env->GetArrayLength(encDexBytes);
    if (len <= 0) return nullptr;

    jbyte* pData = env->GetByteArrayElements(encDexBytes, nullptr);
    unsigned char key = get_dynamic_key(env);

    // Dekripsi DEX di memori RAM
    unsigned char* decrypted = (unsigned char*)malloc(len);
    for (int i = 0; i < len; i++) {
        decrypted[i] = ((unsigned char)pData[i]) ^ key;
    }
    env->ReleaseByteArrayElements(encDexBytes, pData, JNI_ABORT);

    // Buat ByteBuffer langsung ke buffer RAM
    jobject byteBuffer = env->NewDirectByteBuffer(decrypted, len);

    // Ambil ClassLoader parent aplikasi
    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getClassLoader = env->GetMethodID(ctxCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject parentLoader = env->CallObjectMethod(context, getClassLoader);

    // Panggil InMemoryDexClassLoader (Android 8.0+)
    jclass inMemCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!inMemCls) {
        free(decrypted);
        return nullptr;
    }

    jmethodID initMethod = env->GetMethodID(inMemCls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject customLoader = env->NewObject(inMemCls, initMethod, byteBuffer, parentLoader);

    // Bersihkan buffer RAM setelah classloader mengambil alih
    memset(decrypted, 0, len);
    free(decrypted);

    return customLoader;
}
