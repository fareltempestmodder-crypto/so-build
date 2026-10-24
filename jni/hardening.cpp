#include <jni.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

// Kunci XOR disamakan dengan XOR_KEY di sann-apk-hardener.js
static const unsigned char XOR_KEY = 0x5A;

// 1. Silent Kill: mematikan proses via sinyal Linux
static void silent_die() {
    kill(getpid(), SIGKILL);
    exit(0);
}

// 2. Anti-Debug: cek TracerPid pada /proc/self/status
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

// 3. Helper Base64 Decoder mandiri
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

// 4. Inisialisasi otomatis saat .so dimuat ke memori
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    check_tracer();

    return JNI_VERSION_1_6;
}

// 5. Fungsi JNI String Decryptor
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
