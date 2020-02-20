const code = `#include <glib.h>

#define kAccStatic 0x0008
#define kAccConstructor 0x00010000

typedef struct _Model Model;
typedef enum _FieldType FieldType;

typedef struct _JavaApi JavaApi;
typedef struct _JavaClassApi JavaClassApi;
typedef struct _JavaMethodApi JavaMethodApi;
typedef struct _JavaFieldApi JavaFieldApi;
typedef struct _JavaModifierApi JavaModifierApi;
typedef struct _ArtSpec ArtSpec;

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

struct _ArtSpec
{
  gboolean available;

  guint class_offset_ifields;
  guint class_offset_methods;
  guint class_offset_sfields;
  guint class_offset_copied_methods_offset;

  guint method_size;
  guint method_offset_access_flags;

  guint field_size;
  guint field_offset_access_flags;
};

struct _JNIEnv
{
  gpointer * functions;
};

extern GMutex lock;
extern GArray * models;
extern JavaApi java_api;
extern ArtSpec art_spec;

static void model_add_method (Model * self, const gchar * name, jmethodID id, jint modifiers);
static void model_add_field (Model * self, const gchar * name, jfieldID id, jint modifiers);
static void model_free (Model * model);

static gpointer read_art_array (gpointer object_base, guint field_offset, guint length_size, guint * length);

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
model_new (jclass class_handle,
           gpointer class_object,
           JNIEnv * env)
{
  Model * model;
  GHashTable * members;
  gpointer * funcs = env->functions;
  jmethodID (* from_reflected_method) (JNIEnv *, jobject) = funcs[7];
  jfieldID (* from_reflected_field) (JNIEnv *, jobject) = funcs[8];
  jobject (* to_reflected_method) (JNIEnv *, jclass, jmethodID, jboolean) = funcs[9];
  jobject (* to_reflected_field) (JNIEnv *, jclass, jfieldID, jboolean) = funcs[12];
  void (* delete_local_ref) (JNIEnv *, jobject) = funcs[23];
  jobject (* call_object_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[34];
  jint (* call_int_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[49];
  const char * (* get_string_utf_chars) (JNIEnv *, jstring, jboolean *) = funcs[169];
  void (* release_string_utf_chars) (JNIEnv *, jstring, const char *) = funcs[170];
  jsize (* get_array_length) (JNIEnv *, jarray) = funcs[171];
  jobject (* get_object_array_element) (JNIEnv *, jobjectArray, jsize) = funcs[173];
  jsize n, i;

  model = g_new (Model, 1);

  members = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  model->members = members;

  if (art_spec.available)
  {
    gpointer elements;
    guint n, i;
    const guint field_arrays[] = {
      art_spec.class_offset_ifields,
      art_spec.class_offset_sfields
    };
    guint field_array_cursor;

    elements = read_art_array (class_object, art_spec.class_offset_methods, sizeof (gsize), NULL);
    n = *(guint16 *) (class_object + art_spec.class_offset_copied_methods_offset);
    for (i = 0; i != n; i++)
    {
      jmethodID id;
      guint32 access_flags;
      jboolean is_static;
      jobject method, name;
      const char * name_str;
      jint modifiers;

      id = elements + (i * art_spec.method_size);

      access_flags = *(guint32 *) (id + art_spec.method_offset_access_flags);
      if ((access_flags & kAccConstructor) != 0)
        continue;
      is_static = (access_flags & kAccStatic) != 0;
      method = to_reflected_method (env, class_handle, id, is_static);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      modifiers = access_flags & 0xffff;

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }

    for (field_array_cursor = 0; field_array_cursor != G_N_ELEMENTS (field_arrays); field_array_cursor++)
    {
      jboolean is_static;

      is_static = field_array_cursor == 1;

      elements = read_art_array (class_object, field_arrays[field_array_cursor], sizeof (guint32), &n);
      for (i = 0; i != n; i++)
      {
        jfieldID id;
        guint32 access_flags;
        jobject field, name;
        const char * name_str;
        jint modifiers;

        id = elements + (i * art_spec.field_size);

        access_flags = *(guint32 *) (id + art_spec.field_offset_access_flags);
        field = to_reflected_field (env, class_handle, id, is_static);
        name = call_object_method (env, field, java_api.field.get_name);
        name_str = get_string_utf_chars (env, name, NULL);
        modifiers = access_flags & 0xffff;

        model_add_field (model, name_str, id, modifiers);

        release_string_utf_chars (env, name, name_str);
        delete_local_ref (env, name);
        delete_local_ref (env, field);
      }
    }
  }
  else
  {
    jobject elements;

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_methods);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject method, name;
      const char * name_str;
      jmethodID id;
      jint modifiers;

      method = get_object_array_element (env, elements, i);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_method (env, method);
      modifiers = call_int_method (env, method, java_api.method.get_modifiers);

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }
    delete_local_ref (env, elements);

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_fields);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject field, name;
      const char * name_str;
      jfieldID id;
      jint modifiers;

      field = get_object_array_element (env, elements, i);
      name = call_object_method (env, field, java_api.field.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_field (env, field);
      modifiers = call_int_method (env, field, java_api.field.get_modifiers);

      model_add_field (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, field);
    }
    delete_local_ref (env, elements);
  }

  g_mutex_lock (&lock);
  g_array_append_val (models, model);
  g_mutex_unlock (&lock);

  return model;
}

static void
model_add_method (Model * self,
                  const gchar * name,
                  jmethodID id,
                  jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key;
  const gchar * value;

  key = g_strdup (name);
  value = g_hash_table_lookup (members, key);
  if (value == NULL)
    g_hash_table_insert (members, key, g_strdup_printf ("m:%p,%d", id, modifiers));
  else
    g_hash_table_insert (members, key, g_strdup_printf ("%s:%p,%d", value, id, modifiers));
}

static void
model_add_field (Model * self,
                 const gchar * name,
                 jfieldID id,
                 jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key;
  FieldType type;

  key = g_strdup (name);
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

static gpointer
read_art_array (gpointer object_base,
                guint field_offset,
                guint length_size,
                guint * length)
{
  gpointer result, header;
  guint n;

  header = GSIZE_TO_POINTER (*(guint64 *) (object_base + field_offset));
  if (header != NULL)
  {
    result = header + length_size;
    if (length_size == sizeof (guint32))
      n = *(guint32 *) header;
    else
      n = *(guint64 *) header;
  }
  else
  {
    result = NULL;
    n = 0;
  }

  if (length != NULL)
    *length = n;

  return result;
}
`;

const android = require('./android');

let cm = null;
let unwrap = null;

class Model {
  static build (handle, env) {
    if (cm === null) {
      cm = compileModule(env);
      unwrap = makeHandleUnwrapper(cm, env.vm);
    }

    return unwrap(handle, env, object => {
      return new Model(cm.new(handle, object, env));
    });
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
  const {pointerSize} = Process;

  const lockSize = 8;
  const modelsSize = pointerSize;
  const javaApiSize = 7 * pointerSize;
  const artSpecSize = 9 * 4;

  const dataSize = lockSize + modelsSize + javaApiSize + artSpecSize;
  const data = Memory.alloc(dataSize);

  const lock = data;

  const models = lock.add(lockSize);

  const javaApi = models.add(modelsSize);
  const {getDeclaredMethods, getDeclaredFields} = env.javaLangClass();
  const method = env.javaLangReflectMethod();
  const field = env.javaLangReflectField();
  const Modifier = env.javaLangReflectModifier();
  let j = javaApi;
  [
    getDeclaredMethods, getDeclaredFields,
    method.getName, method.getModifiers,
    field.getName, field.getModifiers,
  ]
  .forEach(value => {
    j = j.writePointer(value).add(pointerSize);
  });
  j.writeInt(Modifier.STATIC);

  const artSpec = javaApi.add(javaApiSize);
  const {vm} = env;
  const artClass = android.getArtClassSpec(vm);
  if (artClass !== null) {
    const c = artClass.offset;
    const m = android.getArtMethodSpec(vm);
    const f = android.getArtFieldSpec(vm);
    let s = artSpec;
    [
      1,
      c.ifields, c.methods, c.sfields, c.copiedMethodsOffset,
      m.size, m.offset.accessFlags,
      f.size, f.offset.accessFlags
    ]
    .forEach(value => {
      s = s.writeUInt(value).add(4);
    });
  }

  const cm = new CModule(code, {
    lock,
    models,
    java_api: javaApi,
    art_spec: artSpec,
  });

  const reentrantOptions = { exceptions: 'propagate' };
  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    mode: (artSpec !== null) ? 'full' : 'basic',
    new: new NativeFunction(cm['model_new'], 'pointer', ['pointer', 'pointer', 'pointer'], reentrantOptions),
    has: new NativeFunction(cm['model_has'], 'bool', ['pointer', 'pointer'], fastOptions),
    find: new NativeFunction(cm['model_find'], 'pointer', ['pointer', 'pointer'], fastOptions),
    list: new NativeFunction(cm['model_list'], 'pointer', ['pointer'], fastOptions),
    dealloc: new NativeFunction(cm['dealloc'], 'void', ['pointer'], fastOptions),
  };
}

function makeHandleUnwrapper (cm, vm) {
  if (cm.mode === 'basic') {
    return nullUnwrap;
  }

  const {withRunnableArtThread} = android;
  const decodeGlobal = android.getApi()['art::JavaVMExt::DecodeGlobal'];

  return function (handle, env, fn) {
    let result;

    withRunnableArtThread(vm, env, thread => {
      const object = decodeGlobal(vm, thread, handle);
      result = fn(object);
    });

    return result;
  };
}

function nullUnwrap (handle, env, fn) {
  return fn(NULL);
}
