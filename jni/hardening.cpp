#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

static int g_derived_key = -1;

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
                kill(getpid(), SIGKILL);
                exit(0);
            }
        }
    }
}

// Menghitung kunci XOR langsung dari byte pertama SHA-256 sertifikat penandatangan runtime
static unsigned char get_dynamic_key(JNIEnv* env) {
    if (g_derived_key != -1) {
        return (unsigned char)g_derived_key;
    }

    // Ambil Context via ActivityThread.currentApplication()
    jclass actThreadCls = env->FindClass("android/app/ActivityThread");
    if (!actThreadCls) { g_derived_key = 0x00; return 0x00; }

    jmethodID currentAppMethod = env->GetStaticMethodID(actThreadCls, "currentApplication", "()Landroid/app/Application;");
    if (!currentAppMethod) { g_derived_key = 0x00; return 0x00; }

    jobject context = env->CallStaticObjectMethod(actThreadCls, currentAppMethod);
    if (!context) { g_derived_key = 0x00; return 0x00; }

    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getPkgName = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    jmethodID getPkgMgr = env->GetMethodID(ctxCls, "getPackageManager", "()Landroid/content/pm/PackageManager;");

    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkgName);
    jobject pkgMgr = env->CallObjectMethod(context, getPkgMgr);

    jclass pmCls = env->GetObjectClass(pkgMgr);
    jmethodID getPkgInfo = env->GetMethodID(pmCls, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    // 0x08000000 = GET_SIGNING_CERTIFICATES (Android 9+)
    jobject pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x08000000);
    if (!pkgInfo) {
        // Fallback GET_SIGNATURES (0x00000040)
        pkgInfo = env->CallObjectMethod(pkgMgr, getPkgInfo, pkgName, 0x00000040);
        if (!pkgInfo) { g_derived_key = 0x00; return 0x00; }
    }

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

    if (!certBytes) { g_derived_key = 0x00; return 0x00; }

    // Hitung SHA-256 dari sertifikat penandatangan
    jclass mdCls = env->FindClass("java/security/MessageDigest");
    jmethodID getInst = env->GetStaticMethodID(mdCls, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring shaStr = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInst, shaStr);

    jmethodID digestMethod = env->GetMethodID(mdCls, "digest", "([B)[B");
    jbyteArray digestBytes = (jbyteArray)env->CallObjectMethod(md, digestMethod, certBytes);
    if (!digestBytes) { g_derived_key = 0x00; return 0x00; }

    jbyte* pBytes = env->GetByteArrayElements(digestBytes, nullptr);
    // Kunci diturunkan langsung dari byte pertama hash SHA-256
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

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    check_tracer();
    return JNI_VERSION_1_6;
}

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
