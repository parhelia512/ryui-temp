#ifndef LXBOX_JNI_BRIDGE_H
#define LXBOX_JNI_BRIDGE_H
#include <jni.h>
#include <stdint.h>

/* RyUI's jni_android.c owns JNI_OnLoad. This bridge only retrieves JavaVM
 * through JavaVM::GetEnv from the supplied JNI environment. */
void lxbox_set_vm(JNIEnv *env);
JNIEnv *lxbox_get_env(int *attached);
void lxbox_detach(int attached);
jstring lxbox_bootstrap(JNIEnv *env, jstring data_dir, jobject host);
char *lxbox_call(const char *method, const char *args, char **error);
void lxbox_release(char *value);

#endif
