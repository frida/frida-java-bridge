#include <dlfcn.h>
#include <fcntl.h>
#include <frida-gumjs.h>
#include <jni.h>

static void frida_java_init_vm (JavaVM ** vm, JNIEnv ** env);
static void on_message (GumScript * script, const gchar * message, GBytes * data, gpointer user_data);

int
main (int argc, char * argv[])
{
  GTimer * timer;
  JavaVM * vm;
  JNIEnv * env;
  const struct JNINativeInterface * jni;
  jclass runner;
  jmethodID runner_main;
  jclass string;
  jobjectArray argv_value;
  guint arg_index;
  GumScriptBackend * backend;
  GCancellable * cancellable = NULL;
  GError * error = NULL;
  GumScript * script;
  GMainContext * context;

  gum_init_embedded ();

  timer = g_timer_new ();

  frida_java_init_vm (&vm, &env);
  jni = *env;

  g_print ("[*] Java VM initialized in %u ms\n", (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  runner = jni->FindClass (env, "re/frida/TestRunner");
  g_assert (runner != NULL);

  runner_main = jni->GetStaticMethodID (env, runner, "main", "([Ljava/lang/String;)V");
  g_assert (runner_main != NULL);

  string = jni->FindClass (env, "java/lang/String");
  g_assert (string != NULL);

  argv_value = jni->NewObjectArray (env, argc, string, NULL);
  g_assert (argv_value != NULL);

  for (arg_index = 0; arg_index != argc; arg_index++)
  {
    jstring arg_value;

    arg_value = jni->NewStringUTF (env, argv[arg_index]);
    jni->SetObjectArrayElement (env, argv_value, arg_index, arg_value);
    jni->DeleteLocalRef (env, arg_value);
  }

  jni->DeleteLocalRef (env, string);

  jni->CallStaticVoidMethod (env, runner, runner_main, argv_value);

  jni->DeleteLocalRef (env, argv_value);
  jni->DeleteLocalRef (env, runner);

  backend = gum_script_backend_obtain_duk ();

  script = gum_script_backend_create_sync (backend, "example",
      "Interceptor.attach(Module.findExportByName(null, 'open'), {\n"
      "  onEnter: function (args) {\n"
      "    console.log('[*] open(\"' + Memory.readUtf8String(args[0]) + '\")');\n"
      "  }\n"
      "});\n"
      "Interceptor.attach(Module.findExportByName(null, \"close\"), {\n"
      "  onEnter: function (args) {\n"
      "    console.log('[*] close(' + args[0].toInt32() + ')');\n"
      "  }\n"
      "});",
      cancellable, &error);
  g_assert (error == NULL);

  gum_script_set_message_handler (script, on_message, NULL, NULL);

  gum_script_load_sync (script, cancellable);

  close (open ("/etc/hosts", O_RDONLY));
  close (open ("/etc/fstab", O_RDONLY));

  context = g_main_context_get_thread_default ();
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);

  gum_script_unload_sync (script, cancellable);

  g_object_unref (script);

  g_timer_destroy (timer);

  gum_deinit_embedded ();

  return 0;
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
  options[4].optionString = "-Djava.class.path=/data/local/tmp/frida-java-tests.dex";

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
on_message (GumScript * script, const gchar * message, GBytes * data, gpointer user_data)
{
  JsonParser * parser;
  JsonObject * root;
  const gchar * type;

  parser = json_parser_new ();
  json_parser_load_from_data (parser, message, -1, NULL);
  root = json_node_get_object (json_parser_get_root (parser));

  type = json_object_get_string_member (root, "type");
  if (strcmp (type, "log") == 0)
  {
    const gchar * log_message;

    log_message = json_object_get_string_member (root, "payload");
    g_print ("%s\n", log_message);
  }
  else
  {
    g_print ("on_message: %s\n", message);
  }

  g_object_unref (parser);
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
