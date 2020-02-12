const code = `#include <glib.h>

typedef struct _Model Model;
typedef enum _FieldType FieldType;

typedef struct _JavaApi JavaApi;
typedef struct _JavaClassApi JavaClassApi;
typedef struct _JavaMethodApi JavaMethodApi;
typedef struct _JavaFieldApi JavaFieldApi;
typedef struct _JavaModifierApi JavaModifierApi;

typedef struct _JNIEnv JNIEnv;
typedef guint8 jboolean;
typedef gint32 jint;
typedef jint jsize;
typedef gpointer jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef gpointer jfieldID;
typedef gpointer jmethodID;

struct _Model
{
  GHashTable * members;
};

enum _FieldType
{
  FIELD_TYPE_STATIC = 1,
  FIELD_TYPE_INSTANCE
};

struct _JavaClassApi
{
  jmethodID get_declared_methods;
  jmethodID get_declared_fields;
};

struct _JavaMethodApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaFieldApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaModifierApi
{
  jint static_bit;
};

struct _JavaApi
{
  JavaClassApi clazz;
  JavaMethodApi method;
  JavaFieldApi field;
  JavaModifierApi modifier;
};

struct _JNIEnv
{
  gpointer * functions;
};

extern GMutex lock;
extern GArray * models;
extern JavaApi java_api;

static void model_free (Model * model);

static void frida_log (const char * format, ...);
extern void _frida_log (const gchar * message);

void
init (void)
{
  g_mutex_init (&lock);
  models = g_array_new (FALSE, FALSE, sizeof (Model *));
}

void
finalize (void)
{
  guint n, i;

  n = models->len;
  for (i = 0; i != n; i++)
  {
    Model * model = g_array_index (models, Model *, i);
    model_free (model);
  }

  g_array_unref (models);
  g_mutex_clear (&lock);
}

Model *
model_new (jclass klass,
           JNIEnv * env)
{
  Model * model;
  GHashTable * members;
  gpointer * funcs = env->functions;
  jmethodID (* from_reflected_method) (JNIEnv *, jobject) = funcs[7];
  jfieldID (* from_reflected_field) (JNIEnv *, jobject) = funcs[8];
  void (* delete_local_ref) (JNIEnv *, jobject) = funcs[23];
  jobject (* call_object_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[34];
  jint (* call_int_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[49];
  const char * (* get_string_utf_chars) (JNIEnv *, jstring, jboolean *) = funcs[169];
  void (* release_string_utf_chars) (JNIEnv *, jstring, const char *) = funcs[170];
  jsize (* get_array_length) (JNIEnv *, jarray) = funcs[171];
  jobject (* get_object_array_element) (JNIEnv *, jobjectArray, jsize) = funcs[173];
  jobject elements;
  jsize n, i;

  model = g_new (Model, 1);

  members = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  model->members = members;

  elements = call_object_method (env, klass, java_api.clazz.get_declared_methods);
  n = get_array_length (env, elements);
  for (i = 0; i != n; i++)
  {
    jobject method, name;
    const char * name_str;
    jmethodID id;
    jint modifiers;
    gchar * key;
    const gchar * value;

    method = get_object_array_element (env, elements, i);
    name = call_object_method (env, method, java_api.method.get_name);
    name_str = get_string_utf_chars (env, name, NULL);
    id = from_reflected_method (env, method);
    modifiers = call_int_method (env, method, java_api.method.get_modifiers);

    key = g_strdup (name_str);
    value = g_hash_table_lookup (members, key);
    if (value == NULL)
      g_hash_table_insert (members, key, g_strdup_printf ("m:%p,%d", id, modifiers));
    else
      g_hash_table_insert (members, key, g_strdup_printf ("%s:%p,%d", value, id, modifiers));

    release_string_utf_chars (env, name, name_str);
    delete_local_ref (env, name);
    delete_local_ref (env, method);
  }
  delete_local_ref (env, elements);

  elements = call_object_method (env, klass, java_api.clazz.get_declared_fields);
  n = get_array_length (env, elements);
  for (i = 0; i != n; i++)
  {
    jobject field, name;
    const char * name_str;
    jmethodID id;
    jint modifiers;
    gchar * key;
    FieldType type;

    field = get_object_array_element (env, elements, i);
    name = call_object_method (env, field, java_api.field.get_name);
    name_str = get_string_utf_chars (env, name, NULL);
    id = from_reflected_field (env, field);
    modifiers = call_int_method (env, field, java_api.field.get_modifiers);

    key = g_strdup (name_str);
    while (g_hash_table_contains (members, key))
    {
      gchar * new_key = g_strdup_printf ("_%s", key);
      g_free (key);
      key = new_key;
    }

    type = ((modifiers & java_api.modifier.static_bit) != 0)
        ? FIELD_TYPE_STATIC
        : FIELD_TYPE_INSTANCE;

    g_hash_table_insert (members, key, g_strdup_printf ("f:%p,%d", id, type));

    release_string_utf_chars (env, name, name_str);
    delete_local_ref (env, name);
    delete_local_ref (env, field);
  }
  delete_local_ref (env, elements);

  g_mutex_lock (&lock);
  g_array_append_val (models, model);
  g_mutex_unlock (&lock);

  return model;
}

static void
model_free (Model * model)
{
  g_hash_table_unref (model->members);

  g_free (model);
}

gboolean
model_has (Model * self,
            const gchar * member)
{
  return g_hash_table_contains (self->members, member);
}

const gchar *
model_find (Model * self,
            const gchar * member)
{
  return g_hash_table_lookup (self->members, member);
}

gchar *
model_list (Model * self)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  const gchar * name;

  result = g_string_sized_new (128);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, self->members);
  for (i = 0; g_hash_table_iter_next (&iter, (gpointer *) &name, NULL); i++)
  {
    if (i > 0)
      g_string_append_c (result, ',');

    g_string_append_c (result, '"');
    g_string_append (result, name);
    g_string_append_c (result, '"');
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

void
dealloc (gpointer mem)
{
  g_free (mem);
}

static void
frida_log (const char * format,
           ...)
{
  gchar * message;
  va_list args;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  _frida_log (message);

  g_free (message);
}
`;

let cm = null;

class Model {
  static build (handle, env) {
    if (cm === null) {
      cm = compileModule(env);
    }

    return new Model(cm.new(handle, env));
  }

  constructor (handle) {
    this.handle = handle;
  }

  has (member) {
    return cm.has(this.handle, Memory.allocUtf8String(member)) !== 0;
  }

  find (member) {
    return cm.find(this.handle, Memory.allocUtf8String(member)).readUtf8String();
  }

  list () {
    const str = cm.list(this.handle);
    try {
      return JSON.parse(str.readUtf8String());
    } finally {
      cm.dealloc(str);
    }
  }
}

module.exports = Model;

function compileModule (env) {
  const {getDeclaredMethods, getDeclaredFields} = env.javaLangClass();
  const method = env.javaLangReflectMethod();
  const field = env.javaLangReflectField();
  const Modifier = env.javaLangReflectModifier();
  const {pointerSize} = Process;

  const api = Memory.alloc(7 * pointerSize);
  api
      .writePointer(getDeclaredMethods).add(pointerSize)
      .writePointer(getDeclaredFields).add(pointerSize)
      .writePointer(method.getName).add(pointerSize)
      .writePointer(method.getModifiers).add(pointerSize)
      .writePointer(field.getName).add(pointerSize)
      .writePointer(field.getModifiers).add(pointerSize)
      .writeInt(Modifier.STATIC);

  const cm = new CModule(code, {
    lock: Memory.alloc(8),
    models: Memory.alloc(pointerSize),
    java_api: api,
    _frida_log: new NativeCallback(messagePtr => {
      console.log(messagePtr.readUtf8String());
      // Thread.sleep(0.01);
    }, 'void', ['pointer']),
  });

  const reentrantOptions = { exceptions: 'propagate' };
  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    new: new NativeFunction(cm['model_new'], 'pointer', ['pointer', 'pointer'], reentrantOptions),
    has: new NativeFunction(cm['model_has'], 'bool', ['pointer', 'pointer'], fastOptions),
    find: new NativeFunction(cm['model_find'], 'pointer', ['pointer', 'pointer'], fastOptions),
    list: new NativeFunction(cm['model_list'], 'pointer', ['pointer'], fastOptions),
    dealloc: new NativeFunction(cm['dealloc'], 'void', ['pointer'], fastOptions),
  };
}
