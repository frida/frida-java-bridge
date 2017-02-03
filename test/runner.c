#include <dlfcn.h>
#include <fcntl.h>
#include <frida-gumjs.h>
#include <jni.h>

typedef struct _CreateScriptOperation CreateScriptOperation;
typedef struct _DestroyScriptOperation DestroyScriptOperation;

struct _CreateScriptOperation
{
  jweak wrapper;
  const gchar * source_code;

  gboolean done;
  GumScript * script;
  GError * error;

  GMutex lock;
  GCond cond;
};

struct _DestroyScriptOperation
{
  GumScript * script;

  gboolean done;

  GMutex lock;
  GCond cond;
};

static void frida_java_init_vm (JavaVM ** vm, JNIEnv ** env);
static void frida_java_register_script_api (JNIEnv * env);
static JNIEnv * frida_java_get_env (void);

static jlong re_frida_script_create (JNIEnv * env, jobject self, jstring source_code);
static gboolean create_script_on_js_thread (gpointer user_data);
static void on_create_ready (GObject * source_object, GAsyncResult * result, gpointer user_data);
static void on_load_ready (GObject * source_object, GAsyncResult * result, gpointer user_data);
static void re_frida_script_destroy (JNIEnv * env, jobject self, jlong handle);
static gboolean destroy_script_on_js_thread (gpointer user_data);
static void on_unload_ready (GObject * source_object, GAsyncResult * result, gpointer user_data);
static void re_frida_script_on_message (GumScript * script, const gchar * message, GBytes * data, gpointer user_data);

static void destroy_weak_ref (jweak ref);

static const JNINativeMethod re_frida_script_methods[] =
{
  { "create", "(Ljava/lang/String;)J", re_frida_script_create },
  { "destroy", "(J)V", re_frida_script_destroy },
};

static JavaVM * java_vm;
static GumScriptBackend * js_backend;
static GMainContext * js_context;

static jmethodID re_frida_script_on_message_method;

int
main (int argc, char * argv[])
{
  gint result = 0;
  JavaVM * vm;
  JNIEnv * env;
  jclass runner;
  jmethodID runner_main;
  jclass string;
  jobjectArray argv_value;
  jstring data_dir_value;
  guint arg_index;
  GumScriptBackend * backend;
  GCancellable * cancellable = NULL;
  GError * error = NULL;
  GumScript * script;
  GMainContext * context;

  gum_init_embedded ();

  js_backend = gum_script_backend_obtain_v8 ();
  js_context = gum_script_backend_get_main_context (backend);

  frida_java_init_vm (&vm, &env);
  java_vm = vm;

  frida_java_register_script_api (env);

  (*env)->PushLocalFrame (env, 6);

  runner = (*env)->FindClass (env, "re/frida/TestRunner");
  g_assert (runner != NULL);

  runner_main = (*env)->GetStaticMethodID (env, runner, "main", "([Ljava/lang/String;Ljava/lang/String;)V");
  g_assert (runner_main != NULL);

  string = (*env)->FindClass (env, "java/lang/String");
  g_assert (string != NULL);

  argv_value = (*env)->NewObjectArray (env, argc, string, NULL);
  g_assert (argv_value != NULL);

  for (arg_index = 0; arg_index != argc; arg_index++)
  {
    jstring arg_value;

    arg_value = (*env)->NewStringUTF (env, argv[arg_index]);
    (*env)->SetObjectArrayElement (env, argv_value, arg_index, arg_value);
    (*env)->DeleteLocalRef (env, arg_value);
  }

  data_dir_value = (*env)->NewStringUTF (env, FRIDA_JAVA_TESTS_DATA_DIR);

  (*env)->CallStaticVoidMethod (env, runner, runner_main, argv_value, data_dir_value);
  if ((*env)->ExceptionCheck (env))
  {
    (*env)->ExceptionDescribe (env);
    (*env)->ExceptionClear (env);

    result = 1;
  }

  (*env)->PopLocalFrame (env, NULL);

  return result;
}

static void
frida_java_init_vm (JavaVM ** vm, JNIEnv ** env)
{
  void * vm_module, * runtime_module;
  jint (* create_java_vm) (JavaVM ** vm, JNIEnv ** env, void * vm_args);
  jint (* register_natives) (JNIEnv * env, jclass clazz);
  JavaVMOption options[5];
  JavaVMInitArgs args;
  jint result;

  vm_module = dlopen ("libart.so", RTLD_LAZY | RTLD_GLOBAL);
  g_assert (vm_module != NULL);

  runtime_module = dlopen ("libandroid_runtime.so", RTLD_LAZY | RTLD_GLOBAL);
  g_assert (runtime_module != NULL);

  create_java_vm = dlsym (vm_module, "JNI_CreateJavaVM");
  g_assert (create_java_vm != NULL);

  register_natives = dlsym (runtime_module, "Java_com_android_internal_util_WithFramework_registerNatives");
  g_assert (register_natives != NULL);

  options[0].optionString = "-verbose:jni";
  options[1].optionString = "-verbose:gc";
  options[2].optionString = "-Xcheck:jni";
  options[3].optionString = "-Xdebug";
  options[4].optionString = "-Djava.class.path=" FRIDA_JAVA_TESTS_DATA_DIR "/tests.dex";

  args.version = JNI_VERSION_1_6;
  args.nOptions = G_N_ELEMENTS (options);
  args.options = options;
  args.ignoreUnrecognized = JNI_TRUE;

  result = create_java_vm (vm, env, &args);
  g_assert_cmpint (result, ==, JNI_OK);

  result = register_natives (*env, NULL);
  g_assert_cmpint (result, ==, JNI_OK);
}

static void
frida_java_register_script_api (JNIEnv * env)
{
  jclass script;
  jint result;

  script = (*env)->FindClass (env, "re/frida/Script");
  g_assert (script != NULL);

  result = (*env)->RegisterNatives (env, script, re_frida_script_methods, G_N_ELEMENTS (re_frida_script_methods));
  g_assert_cmpint (result, ==, 0);

  re_frida_script_on_message_method = (*env)->GetMethodID (env, script, "onMessage", "(Ljava/lang/String;)V");
  g_assert (re_frida_script_on_message_method != NULL);

  (*env)->DeleteLocalRef (env, script);
}

static JNIEnv *
frida_java_get_env (void)
{
  jint result;
  JNIEnv * env;

  result = (*java_vm)->GetEnv (java_vm, (void **) &env, JNI_VERSION_1_6);
  if (result != JNI_OK)
  {
    g_assert_cmpint (result, ==, JNI_EDETACHED);

    result = (*java_vm)->AttachCurrentThread (java_vm, &env, NULL);
    g_assert_cmpint (result, ==, JNI_OK);
  }

  return env;
}

static jlong
re_frida_script_create (JNIEnv * env, jobject self, jstring source_code)
{
  CreateScriptOperation op;
  GSource * idle_source;

  op.wrapper = (*env)->NewWeakGlobalRef (env, self);
  op.source_code = (*env)->GetStringUTFChars (env, source_code, NULL);

  op.done = FALSE;
  op.script = NULL;
  op.error = NULL;

  g_mutex_init (&op.lock);
  g_cond_init (&op.cond);

  idle_source = g_idle_source_new ();
  g_source_set_callback (idle_source, create_script_on_js_thread, &op, NULL);
  g_source_attach (idle_source, js_context);
  g_source_unref (idle_source);

  g_mutex_lock (&op.lock);
  while (!op.done)
    g_cond_wait (&op.cond, &op.lock);
  g_mutex_unlock (&op.lock);

  g_cond_clear (&op.cond);
  g_mutex_clear (&op.lock);

  (*env)->ReleaseStringUTFChars (env, source_code, op.source_code);

  if (op.error != NULL)
  {
    (*env)->DeleteWeakGlobalRef (env, op.wrapper);

    (*env)->ThrowNew (env, (*env)->FindClass (env, "java/lang/IllegalArgumentException"), op.error->message);
    g_error_free (op.error);

    return 0;
  }

  return (jlong) op.script;
}

static void
create_script_operation_notify_complete (CreateScriptOperation * self)
{
  g_mutex_lock (&self->lock);
  self->done = TRUE;
  g_cond_signal (&self->cond);
  g_mutex_unlock (&self->lock);
}

static gboolean
create_script_on_js_thread (gpointer user_data)
{
  CreateScriptOperation * op = user_data;

  gum_script_backend_create (js_backend, "test", op->source_code, NULL, on_create_ready, op);

  return FALSE;
}

static void
on_create_ready (GObject * source_object, GAsyncResult * result, gpointer user_data)
{
  CreateScriptOperation * op = user_data;
  GError * error = NULL;

  op->script = gum_script_backend_create_finish (js_backend, result, &op->error);
  if (op->error != NULL)
  {
    create_script_operation_notify_complete (op);
    return;
  }

  gum_script_set_message_handler (op->script, re_frida_script_on_message, op->wrapper, destroy_weak_ref);

  gum_script_load (op->script, NULL, on_load_ready, op);
}

static void
on_load_ready (GObject * source_object, GAsyncResult * result, gpointer user_data)
{
  CreateScriptOperation * op = user_data;

  gum_script_load_finish (op->script, result);

  create_script_operation_notify_complete (op);
}

static void
re_frida_script_destroy (JNIEnv * env, jobject self, jlong handle)
{
  DestroyScriptOperation op;
  GSource * idle_source;

  op.script = GUM_SCRIPT (handle);

  op.done = FALSE;

  g_mutex_init (&op.lock);
  g_cond_init (&op.cond);

  idle_source = g_idle_source_new ();
  g_source_set_callback (idle_source, destroy_script_on_js_thread, &op, NULL);
  g_source_attach (idle_source, js_context);
  g_source_unref (idle_source);

  g_mutex_lock (&op.lock);
  while (!op.done)
    g_cond_wait (&op.cond, &op.lock);
  g_mutex_unlock (&op.lock);

  g_cond_clear (&op.cond);
  g_mutex_clear (&op.lock);
}

static void
destroy_script_operation_notify_complete (DestroyScriptOperation * self)
{
  g_mutex_lock (&self->lock);
  self->done = TRUE;
  g_cond_signal (&self->cond);
  g_mutex_unlock (&self->lock);
}

static gboolean
destroy_script_on_js_thread (gpointer user_data)
{
  DestroyScriptOperation * op = user_data;

  gum_script_unload (op->script, NULL, on_unload_ready, op);

  return FALSE;
}

static void
on_unload_ready (GObject * source_object, GAsyncResult * result, gpointer user_data)
{
  DestroyScriptOperation * op = user_data;

  gum_script_unload_finish (op->script, result);

  g_object_unref (op->script);
  op->script = NULL;

  destroy_script_operation_notify_complete (op);
}

static void
re_frida_script_on_message (GumScript * script, const gchar * message, GBytes * data, gpointer user_data)
{
  JNIEnv * env;
  jweak weak_wrapper = user_data;
  jobject wrapper;

  env = frida_java_get_env ();

  (*env)->PushLocalFrame (env, 3);

  wrapper = (*env)->NewLocalRef (env, weak_wrapper);
  if (wrapper != NULL)
  {
    (*env)->CallVoidMethod (env, wrapper, re_frida_script_on_message_method, (*env)->NewStringUTF (env, message));
  }

  (*env)->PopLocalFrame (env, NULL);
}

static void
destroy_weak_ref (jweak ref)
{
  JNIEnv * env;

  env = frida_java_get_env ();

  (*env)->DeleteWeakGlobalRef (env, ref);
}

void
ClaimSignalChain (int signal, struct sigaction * oldaction)
{
  /* g_print ("ClaimSignalChain(signal=%d)\n", signal); */
}

void
UnclaimSignalChain (int signal)
{
  /* g_print ("UnclaimSignalChain(signal=%d)\n", signal); */
}

void
InvokeUserSignalHandler (int signal, siginfo_t * info, void * context)
{
  /* g_print ("InvokeUserSignalHandler(signal=%d)\n", signal); */
}

void
InitializeSignalChain (void)
{
  /* g_print ("InitializeSignalChain()\n"); */
}

void
EnsureFrontOfChain (int signal, struct sigaction * expected_action)
{
  /* g_print ("EnsureFrontOfChain(signal=%d)\n", signal); */
}

void
SetSpecialSignalHandlerFn (int signal, gpointer fn)
{
  /* g_print ("SetSpecialSignalHandlerFn(signal=%d)\n", signal); */
}
