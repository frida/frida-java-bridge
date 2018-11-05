'use strict';

const Env = require('./env'); // eslint-disable-line
const getApi = require('./api');
const {
  ensureClassInitialized,
  getAndroidVersion,
  getArtMethodSpec,
  getArtThreadSpec,
  withRunnableArtThread,
  cloneArtMethod
} = require('./android');
const mkdex = require('./mkdex');
const {
  JNI_OK, // eslint-disable-line
} = require('./result');

const pointerSize = Process.pointerSize;

const CONSTRUCTOR_METHOD = 1;
const STATIC_METHOD = 2;
const INSTANCE_METHOD = 3;

const STATIC_FIELD = 1;
const INSTANCE_FIELD = 2;

const DVM_JNI_ENV_OFFSET_SELF = 12;

const DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
const DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;

const DVM_OBJECT_OFFSET_CLAZZ = 0;

const DVM_METHOD_SIZE = 56;
const DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
const DVM_METHOD_OFFSET_METHOD_INDEX = 8;
const DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
const DVM_METHOD_OFFSET_OUTS_SIZE = 12;
const DVM_METHOD_OFFSET_INS_SIZE = 14;
const DVM_METHOD_OFFSET_SHORTY = 28;
const DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;

const DALVIK_JNI_RETURN_VOID = 0;
const DALVIK_JNI_RETURN_FLOAT = 1;
const DALVIK_JNI_RETURN_DOUBLE = 2;
const DALVIK_JNI_RETURN_S8 = 3;
const DALVIK_JNI_RETURN_S4 = 4;
const DALVIK_JNI_RETURN_S2 = 5;
const DALVIK_JNI_RETURN_U2 = 6;
const DALVIK_JNI_RETURN_S1 = 7;
const DALVIK_JNI_NO_ARG_INFO = 0x80000000;
const DALVIK_JNI_RETURN_MASK = 0x70000000;
const DALVIK_JNI_RETURN_SHIFT = 28;
const DALVIK_JNI_COUNT_MASK = 0x0f000000;
const DALVIK_JNI_COUNT_SHIFT = 24;

const kAccNative = 0x0100;
const kAccFastNative = 0x00080000;
const kAccXposedHookedMethod = 0x10000000;

const JNILocalRefType = 1;

function ClassFactory (vm) {
  const factory = this;
  let api = null;
  let classes = {};
  let patchedClasses = {};
  const patchedMethods = new Set();
  const ignoredThreads = {};
  let loader = null;
  let cachedLoaderInvoke = null;
  let cachedLoaderMethod = null;
  let cacheDir = '/data/local/tmp';
  let tempFileNaming = {
    prefix: 'frida',
    suffix: 'dat'
  };
  const PENDING_CALLS = Symbol('PENDING_CALLS');

  function initialize () {
    api = getApi();
  }

  this.dispose = function (env) {
    Array.from(patchedMethods).forEach(method => {
      method.implementation = null;
    });
    patchedMethods.clear();

    for (let entryId in patchedClasses) {
      if (patchedClasses.hasOwnProperty(entryId)) {
        const entry = patchedClasses[entryId];
        Memory.writePointer(entry.vtablePtr, entry.vtable);
        Memory.writeS32(entry.vtableCountPtr, entry.vtableCount);
        const targetMethods = entry.targetMethods;

        for (let methodId in targetMethods) {
          if (targetMethods.hasOwnProperty(methodId)) {
            targetMethods[methodId].implementation = null;
            delete targetMethods[methodId];
          }
        }
        delete patchedClasses[entryId];
      }
    }

    classes = {};
  };

  Object.defineProperty(this, 'loader', {
    enumerable: true,
    get: function () {
      return loader;
    },
    set: function (value) {
      loader = value;
    }
  });

  Object.defineProperty(this, 'cacheDir', {
    enumerable: true,
    get: function () {
      return cacheDir;
    },
    set: function (value) {
      cacheDir = value;
    }
  });

  Object.defineProperty(this, 'tempFileNaming', {
    enumerable: true,
    get: function () {
      return tempFileNaming;
    },
    set: function (value) {
      tempFileNaming = value;
    }
  });

  this.use = function (className) {
    let C = classes[className];
    if (!C) {
      const env = vm.getEnv();
      if (loader !== null) {
        const usedLoader = loader;

        if (cachedLoaderMethod === null) {
          cachedLoaderInvoke = env.vaMethod('pointer', ['pointer']);
          cachedLoaderMethod = loader.loadClass.overload('java.lang.String').handle;
        }

        const getClassHandle = function (env) {
          const classNameValue = env.newStringUtf(className);
          const tid = Process.getCurrentThreadId();
          ignore(tid);
          try {
            return cachedLoaderInvoke(env.handle, usedLoader.$handle, cachedLoaderMethod, classNameValue);
          } finally {
            unignore(tid);
            env.deleteLocalRef(classNameValue);
          }
        };

        C = ensureClass(getClassHandle, className);
      } else {
        const canonicalClassName = className.replace(/\./g, '/');

        const getClassHandle = function (env) {
          const tid = Process.getCurrentThreadId();
          ignore(tid);
          try {
            return env.findClass(canonicalClassName);
          } finally {
            unignore(tid);
          }
        };

        C = ensureClass(getClassHandle, className);
      }
    }

    return new C(null);
  };

  function DexFile (path, file = null) {
    this.path = path;
    this.file = file;
  }

  DexFile.fromBuffer = function (buffer) {
    const fileValue = createTemporaryDex();
    const filePath = fileValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();

    return new DexFile(filePath, fileValue);
  };

  DexFile.prototype = {
    load () {
      const DexClassLoader = factory.use('dalvik.system.DexClassLoader');

      let file = this.file;
      if (file === null) {
        file = factory.use('java.io.File').$new(this.path);
      }
      if (!file.exists()) {
        throw new Error('File not found');
      }

      loader = DexClassLoader.$new(file.getCanonicalPath(), cacheDir, null, loader);

      vm.preventDetachDueToClassLoader();
    },
    getClassNames () {
      const DexFile = factory.use('dalvik.system.DexFile');

      const optimizedDex = createTemporaryDex();
      const dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);

      const classNames = [];
      const enumeratorClassNames = dx.entries();
      while (enumeratorClassNames.hasMoreElements()) {
        classNames.push(enumeratorClassNames.nextElement().toString());
      }
      return classNames;
    }
  };

  function createTemporaryDex() {
    const JFile = factory.use('java.io.File');

    const cacheDirValue = JFile.$new(cacheDir);
    cacheDirValue.mkdirs();

    return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix, cacheDirValue);
  }

  this.openClassFile = function (filePath) {
    return new DexFile(filePath);
  };

  this.choose = function (specifier, callbacks) {
    if (api.flavor === 'art') {
      const env = vm.getEnv();
      withRunnableArtThread(vm, env, thread => {
        if (api['art::gc::Heap::VisitObjects'] === undefined) {
          chooseObjectsArtModern(env, thread, specifier, callbacks);
        } else {
          chooseObjectsArtLegacy(env, thread, specifier, callbacks);
        }
      });
    } else {
      chooseObjectsDalvik(specifier, callbacks);
    }
  };

  function chooseObjectsArtModern (env, thread, className, callbacks) {
    const klass = factory.use(className);

    const scope = VariableSizedHandleScope.$new(thread);

    const localClassHandle = klass.$getClassHandle(env);
    const globalClassHandle = env.newGlobalRef(localClassHandle);
    const object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, globalClassHandle);
    const needle = scope.newHandle(object);
    env.deleteGlobalRef(globalClassHandle);
    env.deleteLocalRef(localClassHandle);

    const maxCount = 0;

    const instances = HandleVector.$new();

    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);

    const instanceHandles = instances.handles.map(handle => env.newGlobalRef(handle));

    instances.$delete();
    scope.$delete();

    try {
      for (let handle of instanceHandles) {
        const instance = factory.cast(handle, klass);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }

      callbacks.onComplete();
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }
  }

  const BHS_OFFSET_LINK = 0;
  const BHS_OFFSET_NUM_REFS = pointerSize;
  const BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;

  const kNumReferencesVariableSized = -1;

  class BaseHandleScope {
    $delete () {
      this.finalize();
      api.$delete(this);
    }

    constructor (storage) {
      this.handle = storage;

      this._link = storage.add(BHS_OFFSET_LINK);
      this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
    }

    init (link, numberOfReferences) {
      this.link = link;
      this.numberOfReferences = numberOfReferences;
    }

    finalize () {
    }

    get link () {
      return new BaseHandleScope(Memory.readPointer(this._link));
    }
    set link (value) {
      Memory.writePointer(this._link, value);
    }

    get numberOfReferences () {
      return Memory.readS32(this._numberOfReferences);
    }
    set numberOfReferences (value) {
      Memory.writeS32(this._numberOfReferences, value);
    }
  }

  const VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
  const VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize;
  const VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize;

  class VariableSizedHandleScope extends BaseHandleScope {
    static $new (thread) {
      const scope = new VariableSizedHandleScope(api.$new(VSHS_SIZE));
      scope.init(thread);
      return scope;
    }

    constructor (storage) {
      super(storage);

      this._self = storage.add(VSHS_OFFSET_SELF);
      this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);

      const kLocalScopeSize = 64;
      const kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize - 4 - 4;
      const kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
      this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
      this._topHandleScopePtr = null;
    }

    init (thread) {
      const topHandleScopePtr = thread.add(getArtThreadSpec(vm).offset.topHandleScope);
      this._topHandleScopePtr = topHandleScopePtr;

      super.init(Memory.readPointer(topHandleScopePtr), kNumReferencesVariableSized);

      this.self = thread;
      this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);

      Memory.writePointer(topHandleScopePtr, this);
    }

    finalize () {
      Memory.writePointer(this._topHandleScopePtr, this.link);

      let scope;
      while ((scope = this.currentScope) !== null) {
        const next = scope.link;
        scope.$delete();
        this.currentScope = next;
      }
    }

    get self () {
      return Memory.readPointer(this._self);
    }
    set self (value) {
      Memory.writePointer(this._self, value);
    }

    get currentScope () {
      const storage = Memory.readPointer(this._currentScope);
      if (storage.isNull()) {
        return null;
      }
      return new FixedSizeHandleScope(storage, this._scopeLayout);
    }
    set currentScope (value) {
      Memory.writePointer(this._currentScope, value);
    }

    newHandle (object) {
      return this.currentScope.newHandle(object);
    }
  }

  class FixedSizeHandleScope extends BaseHandleScope {
    static $new (layout) {
      const scope = new FixedSizeHandleScope(api.$new(layout.size), layout);
      scope.init();
      return scope;
    }

    constructor (storage, layout) {
      super(storage);

      const {offset} = layout;
      this._refsStorage = storage.add(offset.refsStorage);
      this._pos = storage.add(offset.pos);

      this._layout = layout;
    }

    init () {
      super.init(NULL, this._layout.numberOfReferences);

      this.pos = 0;
    }

    get pos () {
      return Memory.readU32(this._pos);
    }
    set pos (value) {
      Memory.writeU32(this._pos, value);
    }

    newHandle (object) {
      const pos = this.pos;
      const handle = this._refsStorage.add(pos * 4);
      Memory.writeS32(handle, object.toInt32());
      this.pos = pos + 1;
      return handle;
    }

    static layoutForCapacity (numRefs) {
      const refsStorage = BHS_SIZE;
      const pos = refsStorage + (numRefs * 4);

      return {
        size: pos + 4,
        numberOfReferences: numRefs,
        offset: {
          refsStorage,
          pos
        }
      };
    }
  }

  const STD_VECTOR_SIZE = 3 * pointerSize;

  class StdVector {
    $delete () {
      this.finalize();
      api.$delete(this);
    }

    constructor (storage, elementSize) {
      this.handle = storage;

      this._begin = storage;
      this._end = storage.add(pointerSize);
      this._storage = storage.add(2 * pointerSize);

      this._elementSize = elementSize;
    }

    init () {
      this.begin = NULL;
      this.end = NULL;
      this.storage = NULL;
    }

    finalize () {
      api.$delete(this.begin);
    }

    get begin () {
      return Memory.readPointer(this._begin);
    }
    set begin (value) {
      Memory.writePointer(this._begin, value);
    }

    get end () {
      return Memory.readPointer(this._end);
    }
    set end (value) {
      Memory.writePointer(this._end, value);
    }

    get storage () {
      return Memory.readPointer(this._storage);
    }
    set storage (value) {
      Memory.writePointer(this._storage, value);
    }

    get size () {
      return this.end.sub(this.begin).toInt32() / this._elementSize;
    }
  }

  class HandleVector extends StdVector {
    static $new () {
      const vector = new HandleVector(api.$new(STD_VECTOR_SIZE));
      vector.init();
      return vector;
    }

    constructor (storage) {
      super(storage, pointerSize);
    }

    get handles () {
      const result = [];

      let cur = this.begin;
      const end = this.end;
      while (!cur.equals(end)) {
        result.push(Memory.readPointer(cur));
        cur = cur.add(pointerSize);
      }

      return result;
    }
  }

  function chooseObjectsArtLegacy (env, thread, className, callbacks) {
    const klass = factory.use(className);

    const instanceHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;
    const localClassHandle = klass.$getClassHandle(env);
    const globalClassHandle = env.newGlobalRef(localClassHandle);
    const needle = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, globalClassHandle).toInt32();
    env.deleteGlobalRef(globalClassHandle);
    env.deleteLocalRef(localClassHandle);

    const collectMatchingInstanceHandles = makeObjectVisitorPredicate(needle, object => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });

    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (let handle of instanceHandles) {
        const instance = factory.cast(handle, klass);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  const objectVisitorPredicateFactories = {
    arm: function (needle, onMatch) {
      const size = Process.pageSize;

      const predicate = Memory.alloc(size);

      Memory.protect(predicate, size, 'rwx');

      const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
      predicate._onMatchCallback = onMatchCallback;

      const instructions = [
        0x6801, // ldr r1, [r0]
        0x4a03, // ldr r2, =needle
        0x4291, // cmp r1, r2
        0xd101, // bne mismatch
        0x4b02, // ldr r3, =onMatch
        0x4718, // bx r3
        0x4770, // bx lr
        0xbf00, // nop
      ];
      const needleOffset = instructions.length * 2;
      const onMatchOffset = needleOffset + 4;
      const codeSize = onMatchOffset + 4;

      Memory.patchCode(predicate, codeSize, function (address) {
        instructions.forEach((instruction, index) => {
          Memory.writeU16(address.add(index * 2), instruction);
        });
        Memory.writeS32(address.add(needleOffset), needle);
        Memory.writePointer(address.add(onMatchOffset), onMatchCallback);
      });

      return predicate.or(1);
    },
    arm64: function (needle, onMatch) {
      const size = Process.pageSize;

      const predicate = Memory.alloc(size);

      Memory.protect(predicate, size, 'rwx');

      const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
      predicate._onMatchCallback = onMatchCallback;

      const instructions = [
        0xb9400001, // ldr w1, [x0]
        0x180000c2, // ldr w2, =needle
        0x6b02003f, // cmp w1, w2
        0x54000061, // b.ne mismatch
        0x58000083, // ldr x3, =onMatch
        0xd61f0060, // br x3
        0xd65f03c0, // ret
      ];
      const needleOffset = instructions.length * 4;
      const onMatchOffset = needleOffset + 4;
      const codeSize = onMatchOffset + 8;

      Memory.patchCode(predicate, codeSize, function (address) {
        instructions.forEach((instruction, index) => {
          Memory.writeU32(address.add(index * 4), instruction);
        });
        Memory.writeS32(address.add(needleOffset), needle);
        Memory.writePointer(address.add(onMatchOffset), onMatchCallback);
      });

      return predicate;
    }
  };

  function makeObjectVisitorPredicate (needle, onMatch) {
    const factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
    return factory(needle, onMatch);
  }

  function makeGenericObjectVisitorPredicate (needle, onMatch) {
    return new NativeCallback(object => {
      const klass = Memory.readS32(object);
      if (klass === needle) {
        onMatch(object);
      }
    }, 'void', ['pointer', 'pointer']);
  }

  function chooseObjectsDalvik (className, callbacks) {
    const klass = factory.use(className);

    let enumerateInstances = function (className, callbacks) {
      const env = vm.getEnv();
      const thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
      const classHandle = klass.$getClassHandle(env);
      const ptrClassObject = api.dvmDecodeIndirectRef(thread, classHandle);
      env.deleteLocalRef(classHandle);

      const pattern = ptrClassObject.toMatchPattern();
      const heapSourceBase = api.dvmHeapSourceGetBase();
      const heapSourceLimit = api.dvmHeapSourceGetLimit();
      const size = heapSourceLimit.sub(heapSourceBase).toInt32();
      Memory.scan(heapSourceBase, size, pattern, {
        onMatch (address, size) {
          if (api.dvmIsValidObject(address)) {
            vm.perform(() => {
              const env = vm.getEnv();
              const thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
              let instance;
              const localReference = api.addLocalReference(thread, address);
              try {
                instance = factory.cast(localReference, klass);
              } finally {
                env.deleteLocalRef(localReference);
              }

              const result = callbacks.onMatch(instance);
              if (result === 'stop') {
                return 'stop';
              }
            });
          }
        },
        onError (reason) {},
        onComplete () {
          callbacks.onComplete();
        }
      });
    };

    if (api.addLocalReference === null) {
      const libdvm = Process.getModuleByName('libdvm.so');
      let pattern;
      if (getAndroidVersion(factory).indexOf('4.2.') === 0) {
        // Verified with 4.2.2
        pattern = 'F8 B5 06 46 0C 46 31 B3 43 68 00 F1 A8 07 22 46';
      } else {
        // Verified with 4.3.1 and 4.4.4
        pattern = '2D E9 F0 41 05 46 15 4E 0C 46 7E 44 11 B3 43 68';
      }
      Memory.scan(libdvm.base, libdvm.size, pattern,
        {
          onMatch (address, size) {
            if (Process.arch === 'arm') {
              address = address.or(1); // Thumb
            }
            api.addLocalReference = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
            vm.perform(() => {
              enumerateInstances(className, callbacks);
            });
            return 'stop';
          },
          onError (reason) {},
          onComplete () {}
        });
    } else {
      enumerateInstances(className, callbacks);
    }
  }

  this.cast = function (obj, klass) {
    const env = vm.getEnv();

    const handle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;

    const classHandle = klass.$getClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, classHandle);
      if (!isValidCast) {
        throw new Error("Cast from '" + env.getObjectClassName(handle) + "' to '" + env.getClassName(classHandle) + "' isn't possible");
      }
    } finally {
      env.deleteLocalRef(classHandle);
    }

    const C = klass.$classWrapper;
    return new C(handle);
  };

  this.array = function (type, elements) {
    const env = vm.getEnv();

    const primitiveType = getPrimitiveType(type);
    if (primitiveType !== undefined) {
      type = primitiveType.name;
    }
    const arrayType = getArrayType('[' + type, false, this);

    const rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env);
  };

  this.registerClass = registerClass;

  function ensureClass (getClassHandle, name) {
    let klass = classes[name];
    if (klass !== undefined) {
      return klass;
    }

    let env = vm.getEnv();

    let classHandle = getClassHandle(env);
    env.checkForExceptionAndThrowIt();

    let superKlass;
    let superHandle = env.getSuperclass(classHandle);
    if (!superHandle.isNull()) {
      const getSuperClassHandle = function (env) {
        const classHandle = getClassHandle(env);
        const superHandle = env.getSuperclass(classHandle);
        env.deleteLocalRef(classHandle);
        return superHandle;
      };

      try {
        superKlass = ensureClass(getSuperClassHandle, env.getClassName(superHandle));
      } finally {
        env.deleteLocalRef(superHandle);
      }
    } else {
      superKlass = null;
    }
    superHandle = null;

    ensureClassInitialized(env, classHandle);

    eval('klass = function (handle) {' + // eslint-disable-line
      'var env = vm.getEnv();' +
      'this.$classWrapper = klass;' +
      'this.$getClassHandle = getClassHandle;' +
      'if (handle !== null) {' +
      '  this.$handle = env.newGlobalRef(handle);' +
      '  this.$weakRef = WeakRef.bind(this, makeHandleDestructor(vm, this.$handle));' +
      '}' +
      '};');

    Object.defineProperty(klass, 'className', {
      enumerable: true,
      value: basename(name)
    });

    classes[name] = klass;

    function initializeClass () {
      klass.__name__ = name;

      let ctor = null;
      let getCtor = function (type) {
        if (ctor === null) {
          vm.perform(() => {
            const env = vm.getEnv();
            const classHandle = getClassHandle(env);
            try {
              ctor = makeConstructor(classHandle, env);
            } finally {
              env.deleteLocalRef(classHandle);
            }
          });
        }
        if (!ctor[type]) throw new Error('assertion !ctor[type] failed');
        return ctor[type];
      };
      Object.defineProperty(klass.prototype, '$new', {
        get: function () {
          return getCtor('allocAndInit');
        }
      });
      Object.defineProperty(klass.prototype, '$alloc', {
        get: function () {
          return function () {
            const env = vm.getEnv();
            const classHandle = this.$getClassHandle(env);
            try {
              const obj = env.allocObject(classHandle);
              return factory.cast(obj, this);
            } finally {
              env.deleteLocalRef(classHandle);
            }
          };
        }
      });
      Object.defineProperty(klass.prototype, '$init', {
        get: function () {
          return getCtor('initOnly');
        }
      });
      klass.prototype.$dispose = dispose;

      klass.prototype.$isSameObject = function (obj) {
        const env = vm.getEnv();
        return env.isSameObject(obj.$handle, this.$handle);
      };

      Object.defineProperty(klass.prototype, 'class', {
        get: function () {
          const env = vm.getEnv();
          const classHandle = this.$getClassHandle(env);
          try {
            return factory.cast(classHandle, factory.use('java.lang.Class'));
          } finally {
            env.deleteLocalRef(classHandle);
          }
        }
      });

      Object.defineProperty(klass.prototype, '$className', {
        get: function () {
          const env = vm.getEnv();

          const handle = this.$handle;
          if (handle !== undefined)
            return env.getObjectClassName(this.$handle);

          const classHandle = this.$getClassHandle(env);
          try {
            return env.getClassName(classHandle);
          } finally {
            env.deleteLocalRef(classHandle);
          }
        }
      });

      addMethodsAndFields();
    }

    function dispose () {
      /* jshint validthis: true */
      const ref = this.$weakRef;
      if (ref !== undefined) {
        delete this.$weakRef;
        WeakRef.unbind(ref);
      }
    }

    function makeConstructor (classHandle, env) {
      const Constructor = env.javaLangReflectConstructor();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const jsCtorMethods = [];
      const jsInitMethods = [];
      const jsRetType = getTypeFromJniTypeName(name, false);
      const jsVoidType = getTypeFromJniTypeName('void', false);
      const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredConstructors);
      try {
        const numConstructors = env.getArrayLength(constructors);
        for (let constructorIndex = 0; constructorIndex !== numConstructors; constructorIndex++) {
          const constructor = env.getObjectArrayElement(constructors, constructorIndex);
          try {
            const methodId = env.fromReflectedMethod(constructor);

            const types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
            const jsArgTypes = readTypeNames(env, types).map(name => getTypeFromJniTypeName(name));
            env.deleteLocalRef(types);

            jsCtorMethods.push(makeMethod(basename(name), CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
            jsInitMethods.push(makeMethod(basename(name), INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
          } finally {
            env.deleteLocalRef(constructor);
          }
        }
      } finally {
        env.deleteLocalRef(constructors);
      }

      if (jsInitMethods.length === 0) {
        throw new Error('no supported overloads');
      }

      return {
        'allocAndInit': makeMethodDispatcher('<init>', jsCtorMethods),
        'initOnly': makeMethodDispatcher('<init>', jsInitMethods)
      };
    }

    function makeField (name, params, classHandle, env) {
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const {getGenericType} = env.javaLangReflectField();

      const [fieldId, jsType] = params;

      let jsFieldType;
      const isStatic = jsType === STATIC_FIELD ? 1 : 0;
      const handle = env.toReflectedField(classHandle, fieldId, isStatic);
      try {
        const fieldType = invokeObjectMethodNoArgs(env.handle, handle, getGenericType);
        try {
          jsFieldType = getTypeFromJniTypeName(env.getTypeName(fieldType));
        } finally {
          env.deleteLocalRef(fieldType);
        }
      } catch (e) {
        return null;
      } finally {
        env.deleteLocalRef(handle);
      }

      return createField(name, jsType, fieldId, jsFieldType, env);
    }

    function createField (name, type, targetFieldId, fieldType, env) {
      const rawFieldType = fieldType.type;
      let invokeTarget = null; // eslint-disable-line
      if (type === STATIC_FIELD) {
        invokeTarget = env.getStaticField(rawFieldType);
      } else if (type === INSTANCE_FIELD) {
        invokeTarget = env.getField(rawFieldType);
      }

      let frameCapacity = 3;
      const callArgs = [
        'env.handle',
        type === INSTANCE_FIELD ? 'this.$handle' : 'this.$getClassHandle(env)',
        'targetFieldId'
      ];

      let returnCapture, returnStatements;
      if (fieldType.fromJni) {
        frameCapacity++;
        returnCapture = 'rawResult = ';
        returnStatements = 'try {' +
          'result = fieldType.fromJni.call(this, rawResult, env);' +
          '} finally {' +
          'env.popLocalFrame(NULL);' +
          '} ' +
          'return result;';
      } else {
        returnCapture = 'result = ';
        returnStatements = 'env.popLocalFrame(NULL);' +
          'return result;';
      }

      let getter;
      eval('getter = function () {' + // eslint-disable-line
        'var isInstance = this.$handle !== undefined;' +
        'if (type === INSTANCE_FIELD && !isInstance) { ' +
        "throw new Error('getter of ' + name + ': cannot get an instance field without an instance.');" +
        '}' +
        'var env = vm.getEnv();' +
        'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' +
        'env.exceptionClear();' +
        'throw new Error("Out of memory");' +
        '}' +
        'var result, rawResult;' +
        'try {' +
        returnCapture + 'invokeTarget(' + callArgs.join(', ') + ');' +
        '} catch (e) {' +
        'env.popLocalFrame(NULL);' +
        'throw e;' +
        '}' +
        'try {' +
        'env.checkForExceptionAndThrowIt();' +
        '} catch (e) {' +
        'env.popLocalFrame(NULL); ' +
        'throw e;' +
        '}' +
        returnStatements +
        '}');

      let setFunction = null; // eslint-disable-line
      if (type === STATIC_FIELD) {
        setFunction = env.setStaticField(rawFieldType);
      } else if (type === INSTANCE_FIELD) {
        setFunction = env.setField(rawFieldType);
      }

      let inputStatement;
      if (fieldType.toJni) {
        inputStatement = 'var input = fieldType.toJni.call(this, value, env);';
      } else {
        inputStatement = 'var input = value;';
      }

      let setter;
      eval('setter = function (value) {' + // eslint-disable-line
        'var isInstance = this.$handle !== undefined;' +
        'if (type === INSTANCE_FIELD && !isInstance) { ' +
        "throw new Error('setter of ' + name + ': cannot set an instance field without an instance');" +
        '}' +
        'if (!fieldType.isCompatible(value)) {' +
        'throw new Error(\'Field "\' + name + \'" expected value compatible with ' + fieldType.className + ".');" +
        '}' +
        'var env = vm.getEnv();' +
        'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' +
        'env.exceptionClear();' +
        'throw new Error("Out of memory");' +
        '}' +
        'try {' +
        inputStatement +
        'setFunction(' + callArgs.join(', ') + ', input);' +
        '} catch (e) {' +
        'throw e;' +
        '} finally {' +
        'env.popLocalFrame(NULL);' +
        '}' +
        'env.checkForExceptionAndThrowIt();' +
        '}');

      const f = {};
      Object.defineProperty(f, 'value', {
        enumerable: true,
        get: function () {
          return getter.call(this.$holder);
        },
        set: function (value) {
          setter.call(this.$holder, value);
        }
      });

      Object.defineProperty(f, 'holder', {
        enumerable: true,
        value: klass
      });

      Object.defineProperty(f, 'fieldType', {
        enumerable: true,
        value: type
      });

      Object.defineProperty(f, 'fieldReturnType', {
        enumerable: true,
        value: fieldType
      });

      return [f, getter, setter];
    }

    function addMethodsAndFields () {
      const Modifier = env.javaLangReflectModifier();
      const getMethodModifiers = env.javaLangReflectMethod().getModifiers;
      const getFieldModifiers = env.javaLangReflectField().getModifiers;
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const invokeIntMethodNoArgs = env.vaMethod('int32', []);
      const methodGetName = env.javaLangReflectMethod().getName;
      const fieldGetName = env.javaLangReflectField().getName;
      const jsMethods = {};
      const jsFields = {};

      const methods = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredMethods);
      try {
        const numMethods = env.getArrayLength(methods);
        for (let methodIndex = 0; methodIndex !== numMethods; methodIndex++) {
          const method = env.getObjectArrayElement(methods, methodIndex);
          try {
            const methodName = invokeObjectMethodNoArgs(env.handle, method, methodGetName);
            try {
              const methodJsName = env.stringFromJni(methodName);
              const methodId = env.fromReflectedMethod(method);
              const modifiers = invokeIntMethodNoArgs(env.handle, method, getMethodModifiers);

              let jsOverloads;
              if (!jsMethods.hasOwnProperty(methodJsName)) {
                jsOverloads = [];
                jsMethods[methodJsName] = jsOverloads;
              } else {
                jsOverloads = jsMethods[methodJsName];
              }

              jsOverloads.push([methodId, modifiers]);
            } finally {
              env.deleteLocalRef(methodName);
            }
          } finally {
            env.deleteLocalRef(method);
          }
        }
      } finally {
        env.deleteLocalRef(methods);
      }

      const fields = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredFields);
      try {
        const numFields = env.getArrayLength(fields);
        for (let fieldIndex = 0; fieldIndex !== numFields; fieldIndex++) {
          const field = env.getObjectArrayElement(fields, fieldIndex);
          try {
            const fieldName = invokeObjectMethodNoArgs(env.handle, field, fieldGetName);
            try {
              let fieldJsName = env.stringFromJni(fieldName);
              while (jsMethods.hasOwnProperty(fieldJsName)) {
                fieldJsName = '_' + fieldJsName;
              }
              const fieldId = env.fromReflectedField(field);
              const modifiers = invokeIntMethodNoArgs(env.handle, field, getFieldModifiers);
              const jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_FIELD : INSTANCE_FIELD;

              jsFields[fieldJsName] = [fieldId, jsType];
            } finally {
              env.deleteLocalRef(fieldName);
            }
          } finally {
            env.deleteLocalRef(field);
          }
        }
      } finally {
        env.deleteLocalRef(fields);
      }

      Object.keys(jsMethods).forEach(name => {
        const overloads = jsMethods[name];

        let v = null;
        Object.defineProperty(klass.prototype, name, {
          get: function () {
            if (v === null) {
              vm.perform(() => {
                const env = vm.getEnv();
                const classHandle = getClassHandle(env);
                try {
                  v = makeMethodFromOverloads(name, overloads, classHandle, env);
                } finally {
                  env.deleteLocalRef(classHandle);
                }
              });
            }

            return v;
          }
        });
      });

      Object.keys(jsFields).forEach(name => {
        const params = jsFields[name];
        const jsType = params[1];

        let v = null;
        Object.defineProperty(klass.prototype, name, {
          get: function () {
            if (v === null) {
              vm.perform(() => {
                const env = vm.getEnv();
                const classHandle = getClassHandle(env);
                try {
                  v = makeField(name, params, classHandle, env);
                } finally {
                  env.deleteLocalRef(classHandle);
                }

                if (jsType === STATIC_FIELD) {
                  v[0].$holder = this;
                }
              });
            }

            const [protoField, getter, setter] = v;

            if (jsType === STATIC_FIELD)
              return protoField;

            if (this.$handle === undefined)
              throw new Error('Unable to access instance field without an instance');

            const field = {};

            Object.defineProperties(field, {
              value: {
                enumerable: true,
                get: () => {
                  return getter.call(this);
                },
                set: (value) => {
                  setter.call(this, value);
                }
              },
              holder: {
                enumerable: true,
                value: protoField.holder
              },
              fieldType: {
                enumerable: true,
                value: protoField.fieldType
              },
              fieldReturnType: {
                enumerable: true,
                value: protoField.fieldReturnType
              },
            });

            Object.defineProperty(this, name, {
              enumerable: false,
              value: field
            });

            return field;
          }
        });
      });
    }

    function makeMethodFromOverloads (name, overloads, classHandle, env) {
      const Method = env.javaLangReflectMethod();
      const Modifier = env.javaLangReflectModifier();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

      const methods = overloads.map(function (params) {
        const [methodId, modifiers] = params;

        const isStatic = (modifiers & Modifier.STATIC) === 0 ? 0 : 1;
        const jsType = isStatic ? STATIC_METHOD : INSTANCE_METHOD;

        let jsRetType;
        const jsArgTypes = [];
        const handle = env.toReflectedMethod(classHandle, methodId, isStatic);
        try {
          const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

          const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
          env.checkForExceptionAndThrowIt();
          try {
            jsRetType = getTypeFromJniTypeName(env.getTypeName(retType));
          } finally {
            env.deleteLocalRef(retType);
          }

          const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
          env.checkForExceptionAndThrowIt();
          try {
            const numArgTypes = env.getArrayLength(argTypes);
            for (let argTypeIndex = 0; argTypeIndex !== numArgTypes; argTypeIndex++) {
              const t = env.getObjectArrayElement(argTypes, argTypeIndex);
              try {
                const argClassName = (isVarArgs && argTypeIndex === numArgTypes - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
                const argType = getTypeFromJniTypeName(argClassName);
                jsArgTypes.push(argType);
              } finally {
                env.deleteLocalRef(t);
              }
            }
          } finally {
            env.deleteLocalRef(argTypes);
          }
        } catch (e) {
          return null;
        } finally {
          env.deleteLocalRef(handle);
        }

        return makeMethod(name, jsType, methodId, jsRetType, jsArgTypes, env);
      }).filter(function (m) {
        return m !== null;
      });

      if (methods.length === 0) {
        throw new Error('No supported overloads');
      }

      if (name === 'valueOf') {
        const hasDefaultValueOf = methods.some(function implementsDefaultValueOf (m) {
          return m.type === INSTANCE_METHOD && m.argumentTypes.length === 0;
        });
        if (!hasDefaultValueOf) {
          const defaultValueOf = function defaultValueOf () {
            return this;
          };

          Object.defineProperty(defaultValueOf, 'holder', {
            enumerable: true,
            value: klass
          });

          Object.defineProperty(defaultValueOf, 'type', {
            enumerable: true,
            value: INSTANCE_METHOD
          });

          Object.defineProperty(defaultValueOf, 'returnType', {
            enumerable: true,
            value: getTypeFromJniTypeName('int')
          });

          Object.defineProperty(defaultValueOf, 'argumentTypes', {
            enumerable: true,
            value: []
          });

          Object.defineProperty(defaultValueOf, 'canInvokeWith', {
            enumerable: true,
            value: function (args) {
              return args.length === 0;
            }
          });

          methods.push(defaultValueOf);
        }
      }

      return makeMethodDispatcher(name, methods);
    }

    function makeMethodDispatcher (name, methods) {
      const candidates = {};
      methods.forEach(function (m) {
        const numArgs = m.argumentTypes.length;
        let group = candidates[numArgs];
        if (!group) {
          group = [];
          candidates[numArgs] = group;
        }
        group.push(m);
      });

      function f (...args) {
        /* jshint validthis: true */
        const isInstance = this.$handle !== undefined;
        const group = candidates[args.length];
        if (!group) {
          throwOverloadError(name, methods, `argument count of ${args.length} does not match any of:`);
        }
        for (let i = 0; i !== group.length; i++) {
          const method = group[i];
          if (method.canInvokeWith(args)) {
            if (method.type === INSTANCE_METHOD && !isInstance) {
              if (name === 'toString') {
                return '<' + this.$classWrapper.__name__ + '>';
              }
              throw new Error(name + ': cannot call instance method without an instance');
            }
            return method.apply(this, args);
          }
        }
        throwOverloadError(name, methods, 'argument types do not match any of:');
      }

      Object.defineProperty(f, 'overloads', {
        enumerable: true,
        value: methods
      });

      Object.defineProperty(f, 'overload', {
        enumerable: true,
        value: function (...args) {
          const group = candidates[args.length];
          if (!group) {
            throwOverloadError(name, methods, `argument count of ${args.length} does not match any of:`);
          }

          const signature = args.join(':');
          for (let i = 0; i !== group.length; i++) {
            const method = group[i];
            const s = method.argumentTypes.map(function (t) {
              return t.className;
            }).join(':');
            if (s === signature) {
              return method;
            }
          }
          throwOverloadError(name, methods, 'specified argument types do not match any of:');
        }
      });

      Object.defineProperty(f, 'holder', {
        enumerable: true,
        get: methods[0].holder
      });

      Object.defineProperty(f, 'type', {
        enumerable: true,
        value: methods[0].type
      });

      if (methods.length === 1) {
        Object.defineProperty(f, 'implementation', {
          enumerable: true,
          get: function () {
            return methods[0].implementation;
          },
          set: function (imp) {
            methods[0].implementation = imp;
          }
        });

        Object.defineProperty(f, 'returnType', {
          enumerable: true,
          value: methods[0].returnType
        });

        Object.defineProperty(f, 'argumentTypes', {
          enumerable: true,
          value: methods[0].argumentTypes
        });

        Object.defineProperty(f, 'canInvokeWith', {
          enumerable: true,
          value: methods[0].canInvokeWith
        });

        Object.defineProperty(f, 'handle', {
          enumerable: true,
          value: methods[0].handle
        });
      } else {
        const throwAmbiguousError = function () {
          throwOverloadError(name, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
        };

        Object.defineProperty(f, 'implementation', {
          enumerable: true,
          get: throwAmbiguousError,
          set: throwAmbiguousError
        });

        Object.defineProperty(f, 'returnType', {
          enumerable: true,
          get: throwAmbiguousError
        });

        Object.defineProperty(f, 'argumentTypes', {
          enumerable: true,
          get: throwAmbiguousError
        });

        Object.defineProperty(f, 'canInvokeWith', {
          enumerable: true,
          get: throwAmbiguousError
        });

        Object.defineProperty(f, 'handle', {
          enumerable: true,
          get: throwAmbiguousError
        });
      }

      return f;
    }

    function makeMethod (methodName, type, methodId, retType, argTypes, env) {
      let dalvikTargetMethodId = methodId;
      let dalvikOriginalMethod = null;
      let artHookedMethodId = methodId;
      let artOriginalMethodInfo = null;

      const rawRetType = retType.type;
      const rawArgTypes = argTypes.map((t) => t.type);

      let invokeTargetVirtually, invokeTargetDirectly; // eslint-disable-line
      if (type === CONSTRUCTOR_METHOD) {
        invokeTargetVirtually = env.constructor(rawArgTypes);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === STATIC_METHOD) {
        invokeTargetVirtually = env.staticVaMethod(rawRetType, rawArgTypes);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === INSTANCE_METHOD) {
        invokeTargetVirtually = env.vaMethod(rawRetType, rawArgTypes);
        invokeTargetDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes);
      }

      let frameCapacity = 2;
      const argVariableNames = argTypes.map((t, i) => ('a' + (i + 1)));
      const callArgsVirtual = [
        'env.handle',
        type === INSTANCE_METHOD ? 'this.$handle' : 'this.$getClassHandle(env)',
        ((api.flavor === 'art') ? 'resolveArtTargetMethodId()' : 'dalvikTargetMethodId')
      ].concat(argTypes.map((t, i) => {
        if (t.toJni) {
          frameCapacity++;
          return ['argTypes[', i, '].toJni.call(this, ', argVariableNames[i], ', env)'].join('');
        } else {
          return argVariableNames[i];
        }
      }));
      let callArgsDirect;
      if (type === INSTANCE_METHOD) {
        callArgsDirect = callArgsVirtual.slice();
        callArgsDirect.splice(2, 0, 'this.$getClassHandle(env)');
      } else {
        callArgsDirect = callArgsVirtual;
      }

      let returnCapture, returnStatements;
      if (rawRetType === 'void') {
        returnCapture = '';
        returnStatements = 'env.popLocalFrame(NULL);';
      } else {
        if (retType.fromJni) {
          frameCapacity++;
          returnCapture = 'rawResult = ';
          returnStatements = 'try {' +
            'result = retType.fromJni.call(this, rawResult, env);' +
            '} finally {' +
            'env.popLocalFrame(NULL);' +
            '}' +
            'return result;';
        } else {
          returnCapture = 'result = ';
          returnStatements = 'env.popLocalFrame(NULL);' +
            'return result;';
        }
      }
      let f;
      const pendingCalls = new Set();
      eval('f = function (' + argVariableNames.join(', ') + ') {' + // eslint-disable-line
        'var env = vm.getEnv();' +
        'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' +
        'env.exceptionClear();' +
        'throw new Error("Out of memory");' +
        '}' +
        'var result, rawResult;' +
        'try {' +
        ((api.flavor === 'dalvik') ? (
          'synchronizeDalvikVtable.call(this, env, type === INSTANCE_METHOD);' +
          returnCapture + 'invokeTargetVirtually(' + callArgsVirtual.join(', ') + ');'
          ) : (
          'if (pendingCalls.has(Process.getCurrentThreadId())) {' +
          returnCapture + 'invokeTargetDirectly(' + callArgsDirect.join(', ') + ');' +
          '} else {' +
          returnCapture + 'invokeTargetVirtually(' + callArgsVirtual.join(', ') + ');' +
          '}'
          )) +
        '} catch (e) {' +
        'env.popLocalFrame(NULL);' +
        'throw e;' +
        '}' +
        'try {' +
        'env.checkForExceptionAndThrowIt();' +
        '} catch (e) {' +
        'env.popLocalFrame(NULL); ' +
        'throw e;' +
        '}' +
        returnStatements +
        '};');

      Object.defineProperty(f, 'methodName', {
        enumerable: true,
        value: methodName
      });

      Object.defineProperty(f, 'holder', {
        enumerable: true,
        value: klass
      });

      Object.defineProperty(f, 'type', {
        enumerable: true,
        value: type
      });

      Object.defineProperty(f, 'handle', {
        enumerable: true,
        value: methodId
      });

      function fetchMethod (methodId) {
        const artMethodSpec = getArtMethodSpec(vm);
        const artMethodOffset = artMethodSpec.offset;
        return (['jniCode', 'accessFlags', 'quickCode', 'interpreterCode']
          .reduce((original, name) => {
            const offset = artMethodOffset[name];
            if (offset === undefined) {
              return original;
            }
            const address = methodId.add(offset);
            const suffix = (name === 'accessFlags' ? 'U32' : 'Pointer');
            original[name] = Memory['read' + suffix](address);
            return original;
          }, {}));
      }

      function patchMethod (methodId, patches) {
        const artMethodSpec = getArtMethodSpec(vm);
        const artMethodOffset = artMethodSpec.offset;
        Object.keys(patches).forEach(name => {
          const offset = artMethodOffset[name];
          if (offset === undefined) {
            return;
          }
          const address = methodId.add(offset);
          const suffix = (name === 'accessFlags' ? 'U32' : 'Pointer');
          Memory['write' + suffix](address, patches[name]);
        });
      }

      let implementation = null;
      function resolveArtTargetMethodId () { // eslint-disable-line
        if (artOriginalMethodInfo === null) {
          return methodId;
        }

        const target = cloneArtMethod(artHookedMethodId);
        patchMethod(target, artOriginalMethodInfo);
        return target;
      }
      function replaceArtImplementation (fn) {
        if (fn === null && artOriginalMethodInfo === null) {
          return;
        }

        const artMethodSpec = getArtMethodSpec(vm);
        const artMethodOffset = artMethodSpec.offset;

        if (artOriginalMethodInfo === null) {
          artOriginalMethodInfo = fetchMethod(methodId);
          if ((artOriginalMethodInfo.accessFlags & kAccXposedHookedMethod) !== 0) {
            const hookInfo = artOriginalMethodInfo.jniCode;
            artHookedMethodId = Memory.readPointer(hookInfo.add(2 * pointerSize));
            artOriginalMethodInfo = fetchMethod(artHookedMethodId);
          }
        }

        if (fn !== null) {
          implementation = implement(f, fn);

          // kAccFastNative so that the VM doesn't get suspended while executing JNI
          // (so that we can modify the ArtMethod on the fly)
          patchMethod(artHookedMethodId, {
            'jniCode': implementation,
            'accessFlags': (Memory.readU32(artHookedMethodId.add(artMethodOffset.accessFlags)) | kAccNative | kAccFastNative) >>> 0,
            'quickCode': api.artQuickGenericJniTrampoline,
            'interpreterCode': api.artInterpreterToCompiledCodeBridge
          });

          patchedMethods.add(f);
        } else {
          patchedMethods.delete(f);

          patchMethod(artHookedMethodId, artOriginalMethodInfo);
          implementation = null;
        }
      }
      function replaceDalvikImplementation (fn) {
        if (fn === null && dalvikOriginalMethod === null) {
          return;
        }

        if (dalvikOriginalMethod === null) {
          dalvikOriginalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);
          dalvikTargetMethodId = Memory.dup(methodId, DVM_METHOD_SIZE);
        }

        if (fn !== null) {
          implementation = implement(f, fn);

          let argsSize = argTypes.reduce((acc, t) => (acc + t.size), 0);
          if (type === INSTANCE_METHOD) {
            argsSize++;
          }

          /*
           * make method native (with kAccNative)
           * insSize and registersSize are set to arguments size
           */
          const accessFlags = (Memory.readU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS)) | kAccNative) >>> 0;
          const registersSize = argsSize;
          const outsSize = 0;
          const insSize = argsSize;

          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS), accessFlags);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE), registersSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE), outsSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_INS_SIZE), insSize);
          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO), computeDalvikJniArgInfo(methodId));

          api.dvmUseJNIBridge(methodId, implementation);

          patchedMethods.add(f);
        } else {
          patchedMethods.delete(f);

          Memory.copy(methodId, dalvikOriginalMethod, DVM_METHOD_SIZE);
          implementation = null;
        }
      }
      function synchronizeDalvikVtable (env, instance) { // eslint-disable-line
        /* jshint validthis: true */

        if (dalvikOriginalMethod === null) {
          return; // nothing to do -- implementation hasn't been replaced
        }

        const thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
        const objectPtr = api.dvmDecodeIndirectRef(thread, instance ? this.$handle : this.$getClassHandle(env));
        let classObject;
        if (instance) {
          classObject = Memory.readPointer(objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ));
        } else {
          classObject = objectPtr;
        }
        let key = classObject.toString(16);
        let entry = patchedClasses[key];
        if (!entry) {
          const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
          const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
          const vtable = Memory.readPointer(vtablePtr);
          const vtableCount = Memory.readS32(vtableCountPtr);

          const vtableSize = vtableCount * pointerSize;
          const shadowVtable = Memory.alloc(2 * vtableSize);
          Memory.copy(shadowVtable, vtable, vtableSize);
          Memory.writePointer(vtablePtr, shadowVtable);

          entry = {
            classObject: classObject,
            vtablePtr: vtablePtr,
            vtableCountPtr: vtableCountPtr,
            vtable: vtable,
            vtableCount: vtableCount,
            shadowVtable: shadowVtable,
            shadowVtableCount: vtableCount,
            targetMethods: {}
          };
          patchedClasses[key] = entry;
        }

        key = methodId.toString(16);
        const method = entry.targetMethods[key];
        if (!method) {
          const methodIndex = entry.shadowVtableCount++;
          Memory.writePointer(entry.shadowVtable.add(methodIndex * pointerSize), dalvikTargetMethodId);
          Memory.writeU16(dalvikTargetMethodId.add(DVM_METHOD_OFFSET_METHOD_INDEX), methodIndex);
          Memory.writeS32(entry.vtableCountPtr, entry.shadowVtableCount);

          entry.targetMethods[key] = f;
        }
      }
      Object.defineProperty(f, 'implementation', {
        enumerable: true,
        get: function () {
          return implementation;
        },
        set: (type === CONSTRUCTOR_METHOD) ? function () {
          throw new Error('Reimplementing $new is not possible. Please replace implementation of $init instead.');
        } : (api.flavor === 'art' ? replaceArtImplementation : replaceDalvikImplementation)
      });

      Object.defineProperty(f, 'returnType', {
        enumerable: true,
        value: retType
      });

      Object.defineProperty(f, 'argumentTypes', {
        enumerable: true,
        value: argTypes
      });

      Object.defineProperty(f, 'canInvokeWith', {
        enumerable: true,
        value: function (args) {
          if (args.length !== argTypes.length) {
            return false;
          }

          return argTypes.every(function (t, i) {
            return t.isCompatible(args[i]);
          });
        }
      });

      Object.defineProperty(f, PENDING_CALLS, {
        enumerable: true,
        value: pendingCalls
      });

      return f;
    }

    if (superKlass !== null) {
      const Surrogate = function () {
        this.constructor = klass;
      };
      Surrogate.prototype = superKlass.prototype;
      klass.prototype = new Surrogate();

      klass.__super__ = superKlass.prototype;
    } else {
      klass.__super__ = null;
    }

    initializeClass();

    // Guard against use-after-"free"
    env.deleteLocalRef(classHandle);
    classHandle = null;
    env = null;

    return klass;
  }

  function registerClass (spec) {
    const env = vm.getEnv();

    const localHandles = [];
    try {
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const className = spec.name;
      const interfaces = (spec.implements || []);

      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: 'Ljava/lang/Object;',
        interfaces: interfaces.map(iface => makeJniObjectTypeName(iface.$classWrapper.__name__)),
        methods: dexMethods
      };

      const baseMethods = {};
      const pendingOverloads = {};
      interfaces.forEach(iface => {
        const ifaceHandle = iface.$getClassHandle(env);
        localHandles.push(ifaceHandle);

        const ifaceProto = Object.getPrototypeOf(iface);
        Object.getOwnPropertyNames(ifaceProto)
          .filter(name => {
            return name[0] !== '$' && name !== 'constructor' && name !== 'class';
          })
          .forEach(name => {
            const method = iface[name];

            const overloads = method.overloads;
            const overloadIds = overloads.map(overload => makeOverloadId(name, overload.returnType, overload.argumentTypes));

            baseMethods[name] = [method, overloadIds, ifaceHandle];
            overloads.forEach((overload, index) => {
              const id = overloadIds[index];
              pendingOverloads[id] = [overload, ifaceHandle];
            });
          });
      });

      const methods = spec.methods || {};
      const methodNames = Object.keys(methods);
      const methodEntries = methodNames.reduce((result, name) => {
        const entry = methods[name];
        if (entry instanceof Array) {
          result.push(...entry.map(e => [name, e]));
        } else {
          result.push([name, entry]);
        }
        return result;
      }, []);
      const numMethods = methodEntries.length;

      const nativeMethods = [];
      const temporaryHandles = [];

      let methodElements = null;

      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize;
        methodElements = Memory.alloc(numMethods * methodElementSize);

        methodEntries.forEach(([name, methodValue], index) => {
          let method = null;
          let returnType;
          let argumentTypes;
          let thrownTypeNames = [];
          let impl;

          if (typeof methodValue === 'function') {
            const m = baseMethods[name];
            if (m !== undefined) {
              const [baseMethod, overloadIds, parentTypeHandle] = m;

              if (overloadIds.length > 1) {
                throw new Error(`More than one overload matching '${name}': signature must be specified`);
              }
              delete pendingOverloads[overloadIds[0]];
              const overload = baseMethod.overloads[0];

              method = overload;
              returnType = overload.returnType;
              argumentTypes = overload.argumentTypes;
              impl = methodValue;

              const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
              const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
              thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
              env.deleteLocalRef(thrownTypes);
            } else {
              returnType = getTypeFromJniTypeName('void');
              argumentTypes = [];
              impl = methodValue;
            }
          } else {
            returnType = getTypeFromJniTypeName(methodValue.returnType || 'void');
            argumentTypes = (methodValue.argumentTypes || []).map(name => getTypeFromJniTypeName(name));
            impl = methodValue.implementation;
            if (typeof impl !== 'function') {
              throw new Error('Expected a function implementation for method: ' + name);
            }

            const id = makeOverloadId(name, returnType, argumentTypes);
            const pendingOverload = pendingOverloads[id];
            if (pendingOverload !== undefined) {
              const [overload, parentTypeHandle] = pendingOverload;
              delete pendingOverloads[id];

              method = overload;

              const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
              const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
              thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
              env.deleteLocalRef(thrownTypes);
            }
          }

          if (method === null) {
            method = {
              methodName: name,
              type: INSTANCE_METHOD,
              returnType: returnType,
              argumentTypes: argumentTypes,
              holder: placeholder
            };
            method[PENDING_CALLS] = new Set();
          }

          const returnTypeName = returnType.name;
          const argumentTypeNames = argumentTypes.map(t => t.name);

          dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames]);

          const signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;

          const rawName = Memory.allocUtf8String(name);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(method, impl);

          Memory.writePointer(methodElements.add(index * methodElementSize), rawName);
          Memory.writePointer(methodElements.add((index * methodElementSize) + pointerSize), rawSignature);
          Memory.writePointer(methodElements.add((index * methodElementSize) + (2 * pointerSize)), rawImpl);

          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });

        const unimplementedMethodIds = Object.keys(pendingOverloads);
        if (unimplementedMethodIds.length > 0) {
          throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
        }
      }

      const dex = DexFile.fromBuffer(mkdex(dexSpec));
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }

      const Klass = factory.use(spec.name);
      Klass.$classWrapper.$nativeMethods = nativeMethods;

      if (numMethods > 0) {
        const classHandle = Klass.$getClassHandle(env);
        localHandles.push(classHandle);
        env.registerNatives(classHandle, methodElements, numMethods);
        env.checkForExceptionAndThrowIt();
      }

      const C = classes[spec.name];

      function placeholder (...args) {
        return new C(...args);
      }

      return Klass;
    } finally {
      localHandles.forEach(handle => {
        env.deleteLocalRef(handle);
      });
    }
  }

  function implement (method, fn) {
    if (method.hasOwnProperty('overloads')) {
      throw new Error('Only re-implementing a concrete (specific) method is possible, not a method "dispatcher"');
    }

    const C = method.holder; // eslint-disable-line
    const type = method.type;
    const retType = method.returnType;
    const argTypes = method.argumentTypes;
    const methodName = method.methodName;
    const rawRetType = retType.type;
    const rawArgTypes = argTypes.map((t) => (t.type));
    const pendingCalls = method[PENDING_CALLS]; // eslint-disable-line

    let frameCapacity = 2;
    const argVariableNames = argTypes.map((t, i) => ('a' + (i + 1)));
    const callArgs = argTypes.map((t, i) => {
      if (t.fromJni) {
        frameCapacity++;
        return ['argTypes[', i, '].fromJni.call(self, ', argVariableNames[i], ', env)'].join('');
      } else {
        return argVariableNames[i];
      }
    });
    let returnCapture, returnStatements, returnNothing;
    if (rawRetType === 'void') {
      returnCapture = '';
      returnStatements = 'env.popLocalFrame(NULL);';
      returnNothing = 'return;';
    } else {
      if (retType.toJni) {
        frameCapacity++;
        returnCapture = 'result = ';
        returnStatements = 'var rawResult;' +
          'try {' +
          'if (retType.isCompatible.call(this, result)) {' +
          'rawResult = retType.toJni.call(this, result, env);' +
          '} else {' +
          'throw new Error("Implementation for " + methodName + " expected return value compatible with \'" + retType.className + "\'.");' +
          '}';
        if (retType.type === 'pointer') {
          returnStatements += '} catch (e) {' +
            'env.popLocalFrame(NULL);' +
            'throw e;' +
            '}' +
            'return env.popLocalFrame(rawResult);';
          returnNothing = 'return NULL;';
        } else {
          returnStatements += '} finally {' +
            'env.popLocalFrame(NULL);' +
            '}' +
            'return rawResult;';
          returnNothing = 'return 0;';
        }
      } else {
        returnCapture = 'result = ';
        returnStatements = 'env.popLocalFrame(NULL);' +
          'return result;';
        returnNothing = 'return 0;';
      }
    }
    let f;
    eval('f = function (' + ['envHandle', 'thisHandle'].concat(argVariableNames).join(', ') + ') {' + // eslint-disable-line
      'var env = new Env(envHandle, vm);' +
      'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' +
      'return;' +
      '}' +
      'var self = ' + ((type === INSTANCE_METHOD) ? 'new C(thisHandle);' : 'new C(null);') +
      'var result;' +
      'var tid = Process.getCurrentThreadId();' +
      'try {' +
      'pendingCalls.add(tid);' +
      'if (ignoredThreads[tid] === undefined) {' +
      returnCapture + 'fn.call(' + ['self'].concat(callArgs).join(', ') + ');' +
      '} else {' +
      returnCapture + 'method.call(' + ['self'].concat(callArgs).join(', ') + ');' +
      '}' +
      '} catch (e) {' +
      'env.popLocalFrame(NULL);' +
      "if (typeof e === 'object' && e.hasOwnProperty('$handle')) {" +
      'env.throw(e.$handle);' +
      returnNothing +
      '} else {' +
      'throw e;' +
      '}' +
      '} finally {' +
      'pendingCalls.delete(tid);' +
      '}' +
      returnStatements +
      '};');

    Object.defineProperty(f, 'methodName', {
      enumerable: true,
      value: methodName
    });

    Object.defineProperty(f, 'type', {
      enumerable: true,
      value: type
    });

    Object.defineProperty(f, 'returnType', {
      enumerable: true,
      value: retType
    });

    Object.defineProperty(f, 'argumentTypes', {
      enumerable: true,
      value: argTypes
    });

    Object.defineProperty(f, 'canInvokeWith', {
      enumerable: true,
      value: function (args) {
        if (args.length !== argTypes.length) {
          return false;
        }

        return argTypes.every((t, i) => (t.isCompatible(args[i])));
      }
    });

    return new NativeCallback(f, rawRetType, ['pointer', 'pointer'].concat(rawArgTypes));
  }

  function getTypeFromJniTypeName (typeName, unbox = true) {
    return getType(typeName, unbox, factory);
  }

  function ignore (threadId) {
    let count = ignoredThreads[threadId];
    if (count === undefined) {
      count = 0;
    }
    count++;
    ignoredThreads[threadId] = count;
  }

  function unignore (threadId) {
    let count = ignoredThreads[threadId];
    if (count === undefined) {
      throw new Error(`Thread ${threadId} is not ignored`);
    }
    count--;
    if (count === 0) {
      delete ignoredThreads[threadId];
    } else {
      ignoredThreads[threadId] = count;
    }
  }

  initialize.call(this);
}

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function makeJniObjectTypeName (typeName) {
  return 'L' + typeName.replace(/\./g, '/') + ';';
}

function readTypeNames (env, types) {
  const names = [];

  const numTypes = env.getArrayLength(types);
  for (let typeIndex = 0; typeIndex !== numTypes; typeIndex++) {
    const t = env.getObjectArrayElement(types, typeIndex);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeOverloadId (name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map(t => t.className).join(', ')})`;
}

function throwOverloadError (name, methods, message) {
  const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
  const overloads = methodsSortedByArity.map(m => {
    const argTypes = m.argumentTypes;
    if (argTypes.length > 0) {
      return '.overload(\'' + m.argumentTypes.map(t => t.className).join('\', \'') + '\')';
    } else {
      return '.overload()';
    }
  });
  throw new Error(`${name}(): ${message}\n\t${overloads.join('\n\t')}`);
}

/*
 * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
 * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
 */
function getType (typeName, unbox, factory) {
  let type = getPrimitiveType(typeName);
  if (!type) {
    if (typeName.indexOf('[') === 0) {
      type = getArrayType(typeName, unbox, factory);
    } else {
      if (typeName[0] === 'L' && typeName[typeName.length - 1] === ';') {
        typeName = typeName.substring(1, typeName.length - 1);
      }
      type = getObjectType(typeName, unbox, factory);
    }
  }

  const result = {
    className: typeName
  };
  for (let key in type) {
    if (type.hasOwnProperty(key)) {
      result[key] = type[key];
    }
  }
  return result;
}

const primitiveTypes = {
  boolean: {
    name: 'Z',
    type: 'uint8',
    size: 1,
    byteSize: 1,
    isCompatible: function (v) {
      return typeof v === 'boolean';
    },
    fromJni: function (v) {
      return !!v;
    },
    toJni: function (v) {
      return v ? 1 : 0;
    },
    memoryRead: Memory.readU8,
    memoryWrite: Memory.writeU8
  },
  byte: {
    name: 'B',
    type: 'int8',
    size: 1,
    byteSize: 1,
    isCompatible: function (v) {
      return Number.isInteger(v) && v >= -128 && v <= 127;
    },
    memoryRead: Memory.readS8,
    memoryWrite: Memory.writeS8
  },
  char: {
    name: 'C',
    type: 'uint16',
    size: 1,
    byteSize: 2,
    isCompatible: function (v) {
      if (typeof v === 'string' && v.length === 1) {
        const charCode = v.charCodeAt(0);
        return charCode >= 0 && charCode <= 65535;
      } else {
        return false;
      }
    },
    fromJni: function (c) {
      return String.fromCharCode(c);
    },
    toJni: function (s) {
      return s.charCodeAt(0);
    },
    memoryRead: Memory.readU16,
    memoryWrite: Memory.writeU16
  },
  short: {
    name: 'S',
    type: 'int16',
    size: 1,
    byteSize: 2,
    isCompatible: function (v) {
      return Number.isInteger(v) && v >= -32768 && v <= 32767;
    },
    memoryRead: Memory.readS16,
    memoryWrite: Memory.writeS16
  },
  int: {
    name: 'I',
    type: 'int32',
    size: 1,
    byteSize: 4,
    isCompatible: function (v) {
      return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
    },
    memoryRead: Memory.readS32,
    memoryWrite: Memory.writeS32
  },
  long: {
    name: 'J',
    type: 'int64',
    size: 2,
    byteSize: 8,
    isCompatible: function (v) {
      return typeof v === 'number' || v instanceof Int64;
    },
    memoryRead: Memory.readS64,
    memoryWrite: Memory.writeS64
  },
  float: {
    name: 'F',
    type: 'float',
    size: 1,
    byteSize: 4,
    isCompatible: function (v) {
      // TODO
      return typeof v === 'number';
    },
    memoryRead: Memory.readFloat,
    memoryWrite: Memory.writeFloat
  },
  double: {
    name: 'D',
    type: 'double',
    size: 2,
    byteSize: 8,
    isCompatible: function (v) {
      // TODO
      return typeof v === 'number';
    },
    memoryRead: Memory.readDouble,
    memoryWrite: Memory.writeDouble
  },
  void: {
    name: 'V',
    type: 'void',
    size: 0,
    byteSize: 0,
    isCompatible: function (v) {
      return v === undefined;
    }
  },
};

function getPrimitiveType (name) {
  return primitiveTypes[name];
}

const cachedObjectTypesWithUnbox = {};
const cachedObjectTypesWithoutUnbox = {};

function getObjectType (typeName, unbox, factory) {
  const cache = unbox ? cachedObjectTypesWithUnbox : cachedObjectTypesWithoutUnbox;

  let type = cache[typeName];
  if (type !== undefined) {
    return type;
  }

  if (typeName === 'java.lang.Object') {
    type = getJavaLangObjectType(factory);
  } else {
    type = getAnyObjectType(typeName, unbox, factory);
  }

  cache[typeName] = type;

  return type;
}

function getJavaLangObjectType (factory) {
  return {
    name: 'Ljava/lang/Object;',
    type: 'pointer',
    size: 1,
    isCompatible: function (v) {
      if (v === null) {
        return true;
      }

      const jsType = typeof v;

      if (jsType === 'string') {
        return true;
      }

      return jsType === 'object' && v.hasOwnProperty('$handle');
    },
    fromJni: function (h, env) {
      if (h.isNull()) {
        return null;
      }

      if (this && this.$handle !== undefined && env.isSameObject(h, this.$handle)) {
        return this;
      }

      return factory.cast(h, factory.use('java.lang.Object'));
    },
    toJni: function (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$handle;
    }
  };
}

function getAnyObjectType (typeName, unbox, factory) {
  let cachedClass = null;
  let cachedIsInstance = null;
  let cachedIsDefaultString = null;

  function getClass () {
    if (cachedClass === null) {
      cachedClass = factory.use(typeName).class;
    }
    return cachedClass;
  }

  function isInstance (v) {
    const klass = getClass();

    if (cachedIsInstance === null) {
      cachedIsInstance = klass.isInstance.overload('java.lang.Object');
    }

    return cachedIsInstance.call(klass, v);
  }

  function typeIsDefaultString () {
    if (cachedIsDefaultString === null) {
      cachedIsDefaultString = factory.use('java.lang.String').class.isAssignableFrom(getClass());
    }
    return cachedIsDefaultString;
  }

  return {
    name: makeJniObjectTypeName(typeName),
    type: 'pointer',
    size: 1,
    isCompatible: function (v) {
      if (v === null) {
        return true;
      }

      const jsType = typeof v;

      if (jsType === 'string' && typeIsDefaultString()) {
        return true;
      }

      const isWrapper = jsType === 'object' && v.hasOwnProperty('$handle');
      if (!isWrapper) {
        return false;
      }

      return isInstance(v);
    },
    fromJni: function (h, env) {
      if (h.isNull()) {
        return null;
      }

      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }

      if (this && this.$handle !== undefined && env.isSameObject(h, this.$handle)) {
        return this;
      }

      return factory.cast(h, factory.use(typeName));
    },
    toJni: function (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$handle;
    }
  };
}

const primitiveArrayTypes = [
    ['Z', 'boolean'],
    ['B', 'byte'],
    ['C', 'char'],
    ['D', 'double'],
    ['F', 'float'],
    ['I', 'int'],
    ['J', 'long'],
    ['S', 'short'],
  ]
  .reduce((result, [shorty, name]) => {
    result['[' + shorty] = makePrimitiveArrayType(name);
    return result;
  }, {});

function makePrimitiveArrayType (name) {
  const envProto = Env.prototype;

  const nameTitled = toTitleCase(name);
  const spec = {
    typeName: name,
    newArray: envProto['new' + nameTitled + 'Array'],
    setRegion: envProto['set' + nameTitled + 'ArrayRegion'],
    getElements: envProto['get' + nameTitled + 'ArrayElements'],
    releaseElements: envProto['release' + nameTitled + 'ArrayElements'],
  };

  return {
    name: name,
    type: 'pointer',
    size: 1,
    isCompatible: function (v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni: function (h, env) {
      return fromJniPrimitiveArray(h, spec, env);
    },
    toJni: function (arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}

function getArrayType (typeName, unbox, factory) {
  const primitiveType = primitiveArrayTypes[typeName];
  if (primitiveType !== undefined) {
    return primitiveType;
  }

  if (typeName.indexOf('[') !== 0) {
    throw new Error('Unsupported type: ' + typeName);
  }

  let elementTypeName = typeName.substring(1);
  const elementType = getType(elementTypeName, unbox, factory);

  if (elementTypeName[0] === 'L' && elementTypeName[elementTypeName.length - 1] === ';') {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }

  return {
    name: typeName.replace(/\./g, '/'),
    type: 'pointer',
    size: 1,
    isCompatible: function (v) {
      if (v === null) {
        return true;
      } else if (typeof v !== 'object' || !v.hasOwnProperty('length')) {
        return false;
      }
      return v.every(function (element) {
        return elementType.isCompatible(element);
      });
    },
    fromJni: function (arr, env) {
      return fromJniObjectArray.call(this, arr, env, function (self, elem) {
        return elementType.fromJni.call(self, elem, env);
      });
    },
    toJni: function (elements, env) {
      const klassObj = factory.use(elementTypeName);
      const classHandle = klassObj.$getClassHandle(env);

      try {
        return toJniObjectArray(elements, env, classHandle,
          function (i, result) {
            const handle = elementType.toJni.call(this, elements[i], env);
            try {
              env.setObjectArrayElement(result, i, handle);
            } finally {
              if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
                env.deleteLocalRef(handle);
              }
            }
          });
      } finally {
        env.deleteLocalRef(classHandle);
      }
    }
  };
}

function fromJniObjectArray (arr, env, convertFromJniFunc) {
  if (arr.isNull()) {
    return null;
  }
  const result = [];
  const length = env.getArrayLength(arr);
  for (let i = 0; i !== length; i++) {
    const elemHandle = env.getObjectArrayElement(arr, i);

    // Maybe ArrayIndexOutOfBoundsException: if 'i' does not specify a valid index in the array - should not be the case
    env.checkForExceptionAndThrowIt();
    try {
      /* jshint validthis: true */
      result.push(convertFromJniFunc(this, elemHandle));
    } finally {
      env.deleteLocalRef(elemHandle);
    }
  }
  return result;
}

function toJniObjectArray (arr, env, classHandle, setObjectArrayFunc) {
  if (arr === null) {
    return NULL;
  }

  if (!(arr instanceof Array)) {
    throw new Error("Expected an array.");
  }

  const length = arr.length;
  const result = env.newObjectArray(length, classHandle, NULL);
  env.checkForExceptionAndThrowIt();
  if (result.isNull()) {
    return NULL;
  }
  for (let i = 0; i !== length; i++) {
    setObjectArrayFunc.call(env, i, result);
    env.checkForExceptionAndThrowIt();
  }
  return result;
}

class PrimitiveArray {
  constructor(handle, type, length) {
    this.$handle = handle;
    this.type = type;
    this.length = length;
  }
}

function fromJniPrimitiveArray (arr, spec, env) {
  if (arr.isNull()) {
    return null;
  }

  const typeName = spec.typeName;
  const type = getPrimitiveType(typeName);
  const elementSize = type.byteSize;
  const readElement = type.memoryRead;
  const writeElement = type.memoryWrite;
  const parseElementValue = type.fromJni || identity;
  const unparseElementValue = type.toJni || identity;

  const handle = env.newGlobalRef(arr);
  const length = env.getArrayLength(handle);
  const vm = env.vm;

  const storage = new PrimitiveArray(handle, typeName, length);

  let wrapper = new Proxy(storage, {
    has (target, property) {
      return hasProperty.call(target, property);
    },
    get (target, property, receiver) {
      switch (property) {
        case 'hasOwnProperty':
          return hasProperty.bind(target);
        case 'toJSON':
          return toJSON;
        default:
          if (typeof property === 'symbol') {
            return target[property];
          }
          const index = tryParseIndex(property);
          if (index === null) {
            return target[property];
          }
          return withElements(elements => {
            return parseElementValue.call(type, readElement.call(type, elements.add(index * elementSize)));
          });
      }
    },
    set (target, property, value, receiver) {
      const index = tryParseIndex(property);
      if (index === null) {
        target[property] = value;
        return true;
      }

      const env = vm.getEnv();

      const element = Memory.alloc(elementSize);
      writeElement.call(type, element, unparseElementValue(value));
      spec.setRegion.call(env, handle, index, 1, element);

      return true;
    },
    ownKeys (target) {
      const keys = [ '$handle', 'type', 'length' ];
      for (let index = 0; index !== length; index++) {
        keys.push(index.toString());
      }
      return keys;
    },
    getOwnPropertyDescriptor (target, property) {
      return {
        writable: false,
        configurable: true,
        enumerable: true
      };
    },
  });

  WeakRef.bind(wrapper, makeHandleDestructor(vm, handle));
  Script.nextTick(() => { wrapper = null; });

  env = null;

  return wrapper;

  function tryParseIndex (rawIndex) {
    const index = parseInt(rawIndex);
    if (isNaN(index) || index < 0 || index >= length) {
      return null;
    }
    return index;
  }

  function withElements (perform) {
    const env = vm.getEnv();

    const elements = spec.getElements.call(env, handle);
    if (elements.isNull()) {
      throw new Error('Unable to get array elements');
    }

    try {
      return perform(elements);
    } finally {
      spec.releaseElements.call(env, handle, elements);
    }
  }

  function hasProperty (property) {
    const index = tryParseIndex(property);
    if (index === null) {
      return this.hasOwnProperty(property);
    }
    return true;
  }

  function toJSON () {
    return withElements(elements => {
      const values = [];
      for (let index = 0; index !== length; index++) {
        const value = parseElementValue.call(type, readElement.call(type, elements.add(index * elementSize)));
        values.push(value);
      }
      return values;
    });
  }
}

function toJniPrimitiveArray (arr, spec, env) {
  if (arr === null) {
    return NULL;
  }

  const handle = arr.$handle;
  if (handle !== undefined) {
    return handle;
  }

  const length = arr.length;
  const type = getPrimitiveType(spec.typeName);
  const result = spec.newArray.call(env, length);
  if (result.isNull()) {
    throw new Error('Unable to construct array');
  }

  if (length > 0) {
    const elementSize = type.byteSize;
    const writeElement = type.memoryWrite;
    const unparseElementValue = type.toJni || identity;

    const elements = Memory.alloc(length * type.byteSize);
    for (let index = 0; index !== length; index++) {
      writeElement.call(type, elements.add(index * elementSize), unparseElementValue(arr[index]));
    }
    spec.setRegion.call(env, result, 0, length, elements);
    env.checkForExceptionAndThrowIt();
  }

  return result;
}

function isCompatiblePrimitiveArray (value, typeName) {
  if (value === null) {
    return true;
  }

  if (value instanceof PrimitiveArray) {
    return value.type === typeName;
  }

  const isArrayLike = typeof value === 'object' && value.hasOwnProperty('length');
  if (!isArrayLike) {
    return false;
  }

  const elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, element => elementType.isCompatible(element));
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

function toTitleCase (str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function makeHandleDestructor (vm, handle) {
  return () => {
    vm.perform(() => {
      const env = vm.getEnv();
      env.deleteGlobalRef(handle);
    });
  };
}

function alignPointerOffset (offset) {
  const remainder = offset % pointerSize;
  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }
  return offset;
}

function identity (value) {
  return value;
}

function computeDalvikJniArgInfo (methodId) {
  if (Process.arch !== 'ia32')
    return DALVIK_JNI_NO_ARG_INFO;

  // For the x86 ABI, valid hints should always be generated.
  const shorty = Memory.readCString(Memory.readPointer(methodId.add(DVM_METHOD_OFFSET_SHORTY)));
  if (shorty === null || shorty.length === 0 || shorty.length > 0xffff)
    return DALVIK_JNI_NO_ARG_INFO;

  let returnType;
  switch (shorty[0]) {
    case 'V':
      returnType = DALVIK_JNI_RETURN_VOID;
      break;
    case 'F':
      returnType = DALVIK_JNI_RETURN_FLOAT;
      break;
    case 'D':
      returnType = DALVIK_JNI_RETURN_DOUBLE;
      break;
    case 'J':
      returnType = DALVIK_JNI_RETURN_S8;
      break;
    case 'Z':
    case 'B':
      returnType = DALVIK_JNI_RETURN_S1;
      break;
    case 'C':
      returnType = DALVIK_JNI_RETURN_U2;
      break;
    case 'S':
      returnType = DALVIK_JNI_RETURN_S2;
      break;
    default:
      returnType = DALVIK_JNI_RETURN_S4;
      break;
  }

  let hints = 0;
  for (let i = shorty.length - 1; i > 0; i--) {
    const ch = shorty[i];
    hints += (ch === 'D' || ch === 'J') ? 2 : 1;
  }

  return (returnType << DALVIK_JNI_RETURN_SHIFT) | hints;
}

module.exports = ClassFactory;

/* global Int64, Memory, NativeCallback, NativeFunction, NULL, Process, WeakRef */
