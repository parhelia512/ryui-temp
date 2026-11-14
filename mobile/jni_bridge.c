#include "jni_bridge.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "_cgo_export.h"

static JavaVM *lxbox_vm;
static jobject lxbox_host;
static jmethodID lxbox_call_method;
static pthread_mutex_t host_mutex = PTHREAD_MUTEX_INITIALIZER;
static jstring utf8_to_jstring(JNIEnv *env, const char *s) {
    if (s == NULL) return NULL;
    size_t bytes = strlen(s);
    jchar *units = (jchar *)calloc(bytes + 1, sizeof(jchar));
    if (units == NULL) return NULL;
    size_t i = 0, n = 0;
    while (i < bytes) {
        uint32_t cp; unsigned char c = (unsigned char)s[i++];
        if (c < 0x80) cp = c;
        else if ((c & 0xe0) == 0xc0 && i < bytes) { cp = ((uint32_t)(c & 0x1f) << 6) | ((unsigned char)s[i++] & 0x3f); }
        else if ((c & 0xf0) == 0xe0 && i + 1 < bytes) { cp = ((uint32_t)(c & 0x0f) << 12) | (((unsigned char)s[i++] & 0x3f) << 6); cp |= (unsigned char)s[i++] & 0x3f; }
        else if ((c & 0xf8) == 0xf0 && i + 2 < bytes) {
            uint32_t b1 = (unsigned char)s[i++] & 0x3f;
            uint32_t b2 = (unsigned char)s[i++] & 0x3f;
            uint32_t b3 = (unsigned char)s[i++] & 0x3f;
            cp = ((uint32_t)(c & 7) << 18) | (b1 << 12) | (b2 << 6) | b3;
        }
        else cp = 0xfffd;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
        if (cp <= 0xffff) units[n++] = (jchar)cp;
        else { cp -= 0x10000; units[n++] = (jchar)(0xd800 + (cp >> 10)); units[n++] = (jchar)(0xdc00 + (cp & 0x3ff)); }
    }
    jstring result = (*env)->NewString(env, units, (jsize)n);
    free(units);
    return result;
}

static char *jstring_to_utf8(JNIEnv *env, jstring value) {
    if (value == NULL) return NULL;
    jsize length = (*env)->GetStringLength(env, value);
    const jchar *units = (*env)->GetStringChars(env, value, NULL);
    if (units == NULL) return NULL;
    char *out = (char *)malloc((size_t)length * 4 + 1);
    if (out == NULL) { (*env)->ReleaseStringChars(env, value, units); return NULL; }
    size_t n = 0;
    for (jsize i = 0; i < length; i++) {
        uint32_t cp = units[i];
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < length && units[i+1] >= 0xdc00 && units[i+1] <= 0xdfff) { cp = 0x10000 + (((cp - 0xd800) << 10) | (units[++i] - 0xdc00)); }
        else if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
        if (cp < 0x80) out[n++] = (char)cp;
        else if (cp < 0x800) { out[n++] = (char)(0xc0 | (cp >> 6)); out[n++] = (char)(0x80 | (cp & 0x3f)); }
        else if (cp < 0x10000) { out[n++] = (char)(0xe0 | (cp >> 12)); out[n++] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[n++] = (char)(0x80 | (cp & 0x3f)); }
        else { out[n++] = (char)(0xf0 | (cp >> 18)); out[n++] = (char)(0x80 | ((cp >> 12) & 0x3f)); out[n++] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[n++] = (char)(0x80 | (cp & 0x3f)); }
    }
    out[n] = '\0';
    (*env)->ReleaseStringChars(env, value, units);
    return out;
}

void lxbox_set_vm(JNIEnv *env) {
    if (env == 0) return;
    (*env)->GetJavaVM(env, &lxbox_vm);
}

JNIEnv *lxbox_get_env(int *attached) {
    JNIEnv *env = 0;
    *attached = 0;
    if (lxbox_vm == 0) return 0;
    if ((*lxbox_vm)->GetEnv(lxbox_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*lxbox_vm)->AttachCurrentThread(lxbox_vm, &env, 0) != JNI_OK) return 0;
        *attached = 1;
    }
    return env;
}

void lxbox_detach(int attached) {
    if (attached && lxbox_vm != 0) (*lxbox_vm)->DetachCurrentThread(lxbox_vm);
}

int lxbox_register(JNIEnv *env, jobject host) {
    if (env == 0 || host == 0) return -1;
    lxbox_set_vm(env);
    jclass cls = (*env)->GetObjectClass(env, host);
    if (cls == 0) return -2;
    jmethodID method = (*env)->GetMethodID(env, cls, "call", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (method == 0 || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return -3; }
    jobject global = (*env)->NewGlobalRef(env, host);
    if (global == 0) return -4;
    pthread_mutex_lock(&host_mutex);
    if (lxbox_host != 0) (*env)->DeleteGlobalRef(env, lxbox_host);
    lxbox_host = global;
    lxbox_call_method = method;
    pthread_mutex_unlock(&host_mutex);
    (*env)->DeleteLocalRef(env, cls);
    return 0;
}

char *lxbox_call(const char *method, const char *args, char **error) {
    if (error != 0) *error = 0;
    int attached = 0;
    JNIEnv *env = lxbox_get_env(&attached);
    if (env == 0) { if(error != 0)*error=strdup("JavaVM is unavailable");return 0; }
    pthread_mutex_lock(&host_mutex);
    jobject host = lxbox_host == 0 ? 0 : (*env)->NewLocalRef(env,lxbox_host);
    jmethodID call_method = lxbox_call_method;
    pthread_mutex_unlock(&host_mutex);
    if (host == 0 || call_method == 0) {
        if (error != 0) *error = strdup("Android platform callback is not connected");
        lxbox_detach(attached);
        return 0;
    }
    jstring jmethod = utf8_to_jstring(env, method != 0 ? method : "");
    jstring jargs = utf8_to_jstring(env, args != 0 ? args : "{}");
    jstring result = (jstring)(*env)->CallObjectMethod(env, host, call_method, jmethod, jargs);
    (*env)->DeleteLocalRef(env, host);
    (*env)->DeleteLocalRef(env, jmethod);
    (*env)->DeleteLocalRef(env, jargs);
    if ((*env)->ExceptionCheck(env)) {
        jthrowable ex = (*env)->ExceptionOccurred(env);
        (*env)->ExceptionClear(env);
        if (error != 0) {
            jclass throwable = (*env)->GetObjectClass(env, ex);
            jmethodID to_string = throwable ? (*env)->GetMethodID(env, throwable, "toString", "()Ljava/lang/String;") : 0;
            jstring text = to_string ? (jstring)(*env)->CallObjectMethod(env, ex, to_string) : 0;
            if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env);text=0; }
            *error = text ? jstring_to_utf8(env,text) : strdup("Android platform callback threw");
            if (text) (*env)->DeleteLocalRef(env,text);
            if (throwable) (*env)->DeleteLocalRef(env,throwable);
        }
        if (ex != 0) (*env)->DeleteLocalRef(env, ex);
        lxbox_detach(attached);
        return 0;
    }
    if (result == 0) { lxbox_detach(attached); return strdup("null"); }
    char *copy = jstring_to_utf8(env, result);
    if (copy == 0) copy = strdup("null");
    (*env)->DeleteLocalRef(env, result);
    lxbox_detach(attached);
    return copy;
}

jstring lxbox_bootstrap(JNIEnv *env, jstring data_dir, jobject host) {
    if (env == 0 || data_dir == 0 || host == 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"invalid bootstrap arguments\"}}");
    if (lxbox_register(env, host) != 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"failed to register platform host\"}}");
    char *path = jstring_to_utf8(env, data_dir);
    if (path == 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"invalid data directory\"}}");
    char *result = NativeBootstrap(path);
    free(path);
    if (result == 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"Go bootstrap returned null\"}}");
    jstring output = utf8_to_jstring(env, result);
    NativeFree(result);
    return output;
}

jstring lxbox_app_call(JNIEnv *env, jstring method, jstring args) {
    if (env == 0 || method == 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"method is required\"}}");
    char *m = jstring_to_utf8(env, method);
    char *a = args != 0 ? jstring_to_utf8(env, args) : strdup("{}");
    if (m == 0 || a == 0) { free(m); free(a); return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"invalid JSON arguments\"}}"); }
    char *result = NativeAppCall(m, a);
    free(m); free(a);
    if (result == 0) return utf8_to_jstring(env, "{\"ok\":false,\"data\":null,\"error\":{\"message\":\"Go AppCall returned null\"}}");
    jstring output = utf8_to_jstring(env, result);
    NativeFree(result);
    return output;
}

void lxbox_release(char *value) { free(value); }

JNIEXPORT jstring JNICALL Java_com_leadaxe_lxbox_android_NativeBridge_nativeBootstrap(JNIEnv *env, jclass cls, jstring data_dir, jobject host) {
    (void)cls;
    return lxbox_bootstrap(env, data_dir, host);
}

JNIEXPORT jstring JNICALL Java_com_leadaxe_lxbox_android_NativeBridge_nativeAppCall(JNIEnv *env, jclass cls, jstring method, jstring args) {
    (void)cls;
    return lxbox_app_call(env, method, args);
}

