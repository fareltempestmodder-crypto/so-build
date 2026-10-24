#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

// Kunci XOR sinkron dengan sann-apk-hardener.js
static const unsigned char XOR_KEY = 0x5A;

// MASUKKAN HASH SHA-256 DARI KEYSTORE pipeline.jks KAMU (HURUF KECIL, TANPA TITIK DUA)
// Nilai ini bisa diambil dari file keystore/sig.txt
static const char* EXPECTED_SIGNATURE_SHA256 = "a3a440f27e56f99077d23747f6ab55e9496bf17e997bdbec74fa0fd9edcd931b";

static void silent_die() {
    kill(getpid(), SIGKILL);
    exit(0);
}

// 1. Anti-Debug Check
static void check_tracer() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return;

    char buffer[1024];
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        char* tracer = strstr(buffer, "TracerPid:");
        if (tracer) {
            int pid = atoi(tracer + 10);
            if (pid != 0) {
                silent_die();
            }
        }
    }
}

// 2. Verifikasi Signature APK via JNI
static bool verify_signature(JNIEnv* env, jobject context) {
    if (!context || !EXPECTED_SIGNATURE_SHA256 || strlen(EXPECTED_SIGNATURE_SHA256) < 32) {
        return false;
    }

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageNameMethod = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    jmethodID getPackageManagerMethod = env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");

    jstring packageName = (jstring)env->CallObjectMethod(context, getPackageNameMethod);
    jobject packageManager = env->CallObjectMethod(context, getPackageManagerMethod);

    jclass pmClass = env->GetObjectClass(packageManager);
    
    // Flag GET_SIGNING_CERTIFICATES = 0x08000000, GET_SIGNATURES = 0x00000040
    jmethodID getPackageInfoMethod = env->GetMethodID(pmClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    
    jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfoMethod, packageName, 0x08000000);
    if (!packageInfo) {
        // Fallback untuk Android versi lama (< API 28)
        packageInfo = env->CallObjectMethod(packageManager, getPackageInfoMethod, packageName, 0x00000040);
        if (!packageInfo) return false;
    }

    jclass piClass = env->GetObjectClass(packageInfo);
    jbyteArray certBytes = nullptr;

    // Coba baca signingInfo.getApkContentsSigners() (Android 9+)
    jfieldID signingInfoField = env->GetFieldID(piClass, "signingInfo", "Landroid/content/pm/SigningInfo;");
    if (signingInfoField) {
        jobject signingInfo = env->GetObjectField(packageInfo, signingInfoField);
        if (signingInfo) {
            jclass siClass = env->GetObjectClass(signingInfo);
            jmethodID getSignersMethod = env->GetMethodID(siClass, "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
            jobjectArray signatures = (jobjectArray)env->CallObjectMethod(signingInfo, getSignersMethod);
            if (signatures && env->GetArrayLength(signatures) > 0) {
                jobject sig = env->GetObjectArrayElement(signatures, 0);
                jclass sigClass = env->GetObjectClass(sig);
                jmethodID toByteArrayMethod = env->GetMethodID(sigClass, "toByteArray", "()[B");
                certBytes = (jbyteArray)env->CallObjectMethod(sig, toByteArrayMethod);
            }
        }
    }

    // Fallback baca signatures[0] (Android 8 ke bawah)
    if (!certBytes) {
        jfieldID signaturesField = env->GetFieldID(piClass, "signatures", "[Landroid/content/pm/Signature;");
        if (signaturesField) {
            jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, signaturesField);
            if (signatures && env->GetArrayLength(signatures) > 0) {
                jobject sig = env->GetObjectArrayElement(signatures, 0);
                jclass sigClass = env->GetObjectClass(sig);
                jmethodID toByteArrayMethod = env->GetMethodID(sigClass, "toByteArray", "()[B");
                certBytes = (jbyteArray)env->CallObjectMethod(sig, toByteArrayMethod);
            }
        }
    }

    if (!certBytes) return false;

    // Hitung SHA-256 menggunakan MessageDigest
    jclass mdClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstanceMethod = env->GetStaticMethodID(mdClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha256Str = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdClass, getInstanceMethod, sha256Str);

    jmethodID digestMethod = env->GetMethodID(mdClass, "digest", "([B)[B");
    jbyteArray digestBytes = (jbyteArray)env->CallObjectMethod(md, digestMethod, certBytes);
    if (!digestBytes) return false;

    jsize digestLen = env->GetArrayLength(digestBytes);
    jbyte* pBytes = env->GetByteArrayElements(digestBytes, nullptr);

    char hexHash[65];
    for (int i = 0; i < digestLen; i++) {
        sprintf(hexHash + (i * 2), "%02x", (unsigned char)pBytes[i]);
    }
    hexHash[64] = '\0';
    env->ReleaseByteArrayElements(digestBytes, pBytes, JNI_ABORT);

    // Cocokkan dengan signature asli
    return (strcasecmp(hexHash, EXPECTED_SIGNATURE_SHA256) == 0);
}

// 3. Helper Base64 Decoder
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

// 4. Inisialisasi Native dengan Pemeriksaan Context
extern "C" JNIEXPORT void JNICALL
Java_sbx_Bootstrap_initNative(JNIEnv *env, jclass clazz, jobject context) {
    check_tracer();

    if (context) {
        if (!verify_signature(env, context)) {
            silent_die(); // Signature APK dimodifikasi atau di-sign ulang
        }
    }
}

// 5. Native String Decryptor
extern "C" JNIEXPORT jstring JNICALL
Java_sbx_StringDecryptor_nativeDecrypt(JNIEnv *env, jclass clazz, jstring input) {
    if (!input) return nullptr;

    check_tracer();

    const char* str = env->GetStringUTFChars(input, nullptr);
    if (!str) return nullptr;

    int in_len = strlen(str);
    unsigned char* decoded = (unsigned char*)malloc(in_len + 1);
    if (!decoded) {
        env->ReleaseStringUTFChars(input, str);
        return nullptr;
    }

    int decoded_len = b64_decode(str, in_len, decoded);
    for (int i = 0; i < decoded_len; i++) {
        decoded[i] ^= XOR_KEY;
    }
    decoded[decoded_len] = '\0';

    jstring result = env->NewStringUTF((char*)decoded);

    free(decoded);
    env->ReleaseStringUTFChars(input, str);

    return result;
}
