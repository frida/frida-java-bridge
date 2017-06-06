'use strict';

const Env = require('./env'); // eslint-disable-line
const getApi = require('./api');
const {
  ensureClassInitialized,
  getAndroidVersion,
  getArtMethodSpec,
  withAllArtThreadsSuspended,
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
const DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;

const kAccNative = 0x0100;
const kAccFastNative = 0x00080000;

const JNILocalRefType = 1;

function ClassFactory (vm) {
  const factory = this;
  let api = null;
  let classes = {};
  let patchedClasses = {};
  const patchedMethods = new Set();
  let loader = null;
  const FILE_PATH = Symbol('FILE_PATH');
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

    for (let classId in classes) {
      if (classes.hasOwnProperty(classId)) {
        const klass = classes[classId];

        // prevent argument confusion (forEach passes not only the element but also indexes and the entire array)
        klass.__methods__.forEach((m) => env.deleteGlobalRef(m), env);
        klass.__fields__.forEach((f) => env.deleteGlobalRef(f), env);
        env.deleteGlobalRef(klass.__handle__);
        delete classes[classId];
      }
    }
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

  this.use = function (className) {
    let C = classes[className];
    if (!C) {
      const env = vm.getEnv();
      if (loader !== null) {
        const klassObj = loader.loadClass(className);
        C = ensureClass(klassObj.$handle, className);
      } else {
        const handle = env.findClass(className.replace(/\./g, '/'));
        try {
          C = ensureClass(handle, className);
        } finally {
          env.deleteLocalRef(handle);
        }
      }
    }

    return new C(C.__handle__, null);
  };

  function DexFile (filePath) {
    this[FILE_PATH] = filePath;
  }

  DexFile.fromBuffer = function (buffer) {
    const ActivityThread = factory.use('android.app.ActivityThread');
    const JFile = factory.use('java.io.File');

    const app = ActivityThread.currentApplication();
    const tempDir = (app !== null) ? app.getCacheDir() : JFile.$new('/data/local/tmp');
    const filePathValue = JFile.createTempFile('raw', 'dex', tempDir);
    filePathValue.deleteOnExit();

    const filePath = filePathValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();

    return new DexFile(filePath);
  };

  DexFile.prototype = {
    load () {
      const ActivityThread = factory.use('android.app.ActivityThread');
      const DexClassLoader = factory.use('dalvik.system.DexClassLoader');
      const JFile = factory.use('java.io.File');

      const file = JFile.$new(this[FILE_PATH]);
      if (!file.exists()) {
        throw new Error('File not found');
      }

      const app = ActivityThread.currentApplication();
      const optimizedDir = (app !== null) ? app.getCacheDir().getCanonicalPath() : '/data/local/tmp';

      let parentLoader = loader;
      if (parentLoader === null && currentApplication !== null) {
        parentLoader = currentApplication.getClassLoader();
      }

      loader = DexClassLoader.$new(file.getCanonicalPath(), optimizedDir, null, parentLoader);

      vm.preventDetachDueToClassLoader();
    },
    getClassNames () {
      const ActivityThread = factory.use('android.app.ActivityThread');
      const DexFile = factory.use('dalvik.system.DexFile');
      const JFile = factory.use('java.io.File');

      const app = ActivityThread.currentApplication();
      const optimizedDir = (app !== null) ? app.getCacheDir() : JFile.$new('/data/local/tmp');
      const optimizedDex = JFile.createTempFile('opt', 'dex', optimizedDir);
      optimizedDex.deleteOnExit();
      const dx = DexFile.loadDex(this[FILE_PATH], optimizedDex.getCanonicalPath(), 0);

      const classNames = [];
      const enumeratorClassNames = dx.entries();
      while (enumeratorClassNames.hasMoreElements()) {
        classNames.push(enumeratorClassNames.nextElement().toString());
      }
      return classNames;
    }
  };

  this.openClassFile = function (filePath) {
    return new DexFile(filePath);
  };

  this.choose = function (className, callbacks) {
    if (api.flavor === 'art') {
      chooseObjectsArt(className, callbacks);
    } else {
      chooseObjectsDalvik(className, callbacks);
    }
  };

  function chooseObjectsArt (className, callbacks) {
    const env = vm.getEnv();
    const klass = factory.use(className);

    const instanceHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;
    const threadHandle = Memory.readPointer(env.handle.add(pointerSize));
    const needle = api['art::JavaVMExt::DecodeGlobal'](api.vm, threadHandle, klass.$classHandle).toInt32();
    const collectMatchingInstanceHandles = new NativeCallback(object => {
      const klass = Memory.readS32(object);
      if (klass === needle) {
        instanceHandles.push(addGlobalReference(vmHandle, threadHandle, object));
      }
    }, 'void', ['pointer', 'pointer']);

    withAllArtThreadsSuspended(() => {
      api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);
    });

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

  function chooseObjectsDalvik (className, callbacks) {
    const env = vm.getEnv();
    const klass = factory.use(className);

    let enumerateInstances = function (className, callbacks) {
      const thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
      const ptrClassObject = api.dvmDecodeIndirectRef(thread, klass.$classHandle);

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
        // verified with 4.2.2
        pattern = 'F8 B5 06 46 0C 46 31 B3 43 68 00 F1 A8 07 22 46';
      } else {
        // verified with 4.3.1 and 4.4.4
        pattern = '2D E9 F0 41 05 46 15 4E 0C 46 7E 44 11 B3 43 68';
      }
      Memory.scan(libdvm.base, libdvm.size, pattern,
        {
          onMatch (address, size) {
            // Note that on 32-bit ARM this address must have its least significant bit set to 0 for ARM functions, and 1 for Thumb functions. => So set it to 1
            if (Process.arch === 'arm') {
              address = address.or(1);
            }
            api.addLocalReference = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
            enumerateInstances(className, callbacks);
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
    if (env.isInstanceOf(handle, klass.$classHandle)) {
      const C = klass.$classWrapper;
      return new C(C.__handle__, handle);
    } else {
      throw new Error("Cast from '" + env.getObjectClassName(handle) + "' to '" + env.getClassName(klass.$classHandle) + "' isn't possible");
    }
  };

  this.registerClass = registerClass;

  function ensureClass (classHandle, cachedName) {
    let env = vm.getEnv();

    const name = (cachedName !== null) ? cachedName : env.getClassName(classHandle);
    let klass = classes[name];
    if (klass) {
      return klass;
    }

    const superHandle = env.getSuperclass(classHandle);
    let superKlass;
    if (!superHandle.isNull()) {
      try {
        superKlass = ensureClass(superHandle, null);
      } finally {
        env.deleteLocalRef(superHandle);
      }
    } else {
      superKlass = null;
    }

    ensureClassInitialized(env, classHandle);

    const simpleName = basename(name);
    eval('klass = function ' + simpleName.replace(/^[^a-zA-Z$_]|[^a-zA-Z0-9$_]/g, '_') + '(classHandle, handle) {' + // eslint-disable-line
      'var env = vm.getEnv();' +
      'this.$classWrapper = klass;' +
      'this.$classHandle = env.newGlobalRef(classHandle);' +
      'this.$handle = (handle !== null) ? env.newGlobalRef(handle) : null;' +
      'this.$weakRef = WeakRef.bind(this, makeHandleDestructor(this.$handle, this.$classHandle));' +
      '};');

    Object.defineProperty(klass, 'className', {
      enumerable: true,
      value: simpleName
    });

    classes[name] = klass;

    function initializeClass () {
      klass.__name__ = name;
      klass.__handle__ = env.newGlobalRef(classHandle);
      klass.__methods__ = [];
      klass.__fields__ = [];

      let ctor = null;
      let getCtor = function (type) {
        if (ctor === null) {
          vm.perform(() => {
            ctor = makeConstructor(klass.__handle__, vm.getEnv());
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
            const obj = env.allocObject(this.$classHandle);
            return factory.cast(obj, this);
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
          const Clazz = factory.use('java.lang.Class');
          return factory.cast(this.$classHandle, Clazz);
        }
      });

      Object.defineProperty(klass.prototype, '$className', {
        get: function () {
          const env = vm.getEnv();
          return this.hasOwnProperty('$handle') ? env.getObjectClassName(this.$handle) : env.getClassName(this.$classHandle);
        }
      });

      addMethodsAndFields();
    }

    function dispose () {
      /* jshint validthis: true */
      WeakRef.unbind(this.$weakRef);
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

    function makeField (name, handle, env) {
      const Field = env.javaLangReflectField();
      const Modifier = env.javaLangReflectModifier();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const invokeIntMethodNoArgs = env.vaMethod('int32', []);

      const fieldId = env.fromReflectedField(handle);
      const modifiers = invokeIntMethodNoArgs(env.handle, handle, Field.getModifiers);
      const jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_FIELD : INSTANCE_FIELD;
      const fieldType = invokeObjectMethodNoArgs(env.handle, handle, Field.getGenericType);

      let jsFieldType;
      try {
        jsFieldType = getTypeFromJniTypeName(env.getTypeName(fieldType));
      } catch (e) {
        return null;
      } finally {
        env.deleteLocalRef(fieldType);
      }

      const field = createField(name, jsType, fieldId, jsFieldType, env);
      if (field === null) {
        throw new Error('Unsupported field');
      }

      return field;
    }

    function createField (name, type, targetFieldId, fieldType, env) {
      const rawFieldType = fieldType.type;
      let invokeTarget = null; // eslint-disable-line
      if (type === STATIC_FIELD) {
        invokeTarget = env.getStaticField(rawFieldType);
      } else if (type === INSTANCE_FIELD) {
        invokeTarget = env.getField(rawFieldType);
      }

      let frameCapacity = 2;
      const callArgs = [
        'env.handle',
        type === INSTANCE_FIELD ? 'this.$handle' : 'this.$classHandle',
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

      const sanitizedName = name.replace(/^[^a-zA-Z_]|[^a-zA-Z0-9_]/g, '_');

      let getter;
      eval('getter = function get' + sanitizedName + '() {' + // eslint-disable-line
        'var isInstance = this.$handle !== null;' +
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
      eval('setter = function set' + sanitizedName + '(value) {' + // eslint-disable-line
        'var isInstance = this.$handle !== null;' +
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
          return getter.call(this.self);
        },
        set: function (value) {
          setter.call(this.self, value);
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

      return f;
    }

    function myAssign (target, ...sources) {
      sources.forEach(source => {
        Object.defineProperties(target, Object.keys(source).reduce((descriptors, key) => {
          if (key === 'holder' && target.hasOwnProperty('holder')) {
            // there is already holder property
          } else {
            descriptors[key] = Object.getOwnPropertyDescriptor(source, key);
          }
          return descriptors;
        }, {}));
      });
      return target;
    }

    function addMethodsAndFields () {
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const methodGetName = env.javaLangReflectMethod().getName;
      const fieldGetName = env.javaLangReflectField().getName;
      const fieldHandles = klass.__fields__;
      const methodHandles = klass.__methods__;
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
              const methodjsName = env.stringFromJni(methodName);
              const methodHandle = env.newGlobalRef(method);
              methodHandles.push(methodHandle);
              let jsOverloads;
              if (jsMethods.hasOwnProperty(methodjsName)) {
                jsOverloads = jsMethods[methodjsName];
              } else {
                jsOverloads = [];
                jsMethods[methodjsName] = jsOverloads;
              }
              jsOverloads.push(methodHandle);
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
        for (let fieldIndex = 0; fieldIndex < numFields; fieldIndex++) {
          const field = env.getObjectArrayElement(fields, fieldIndex);
          try {
            const fieldName = invokeObjectMethodNoArgs(env.handle, field, fieldGetName);
            try {
              let fieldjsName = env.stringFromJni(fieldName);
              while (jsMethods.hasOwnProperty(fieldjsName)) {
                fieldjsName = "_" + fieldjsName;
              }

              const fieldHandle = env.newGlobalRef(field);
              fieldHandles.push(fieldHandle);

              jsFields[fieldjsName] = fieldHandle;
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

      // define access to the fields in the class (klass)
      const values = myAssign({}, jsFields, jsMethods);
      Object.keys(values).forEach(name => {
        let v = null;
        Object.defineProperty(klass.prototype, name, {
          get: function () {
            if (v === null) {
              vm.perform(() => {
                const env = vm.getEnv();
                let f = {};
                if (jsFields.hasOwnProperty(name)) {
                  f = makeField(name, jsFields[name], env);
                }

                let m = {};
                if (jsMethods.hasOwnProperty(name)) {
                  m = makeMethodFromOverloads(name, jsMethods[name], env);
                }
                v = myAssign(m, f);
              });
            }
            // TODO there should be a better way to do that
            // set the reference for accessing fields
            v.self = this;

            return v;
          }
        });
      });
    }

    function makeMethodFromOverloads (name, overloads, env) {
      const Method = env.javaLangReflectMethod();
      const Modifier = env.javaLangReflectModifier();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      const invokeIntMethodNoArgs = env.vaMethod('int32', []);
      const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

      const methods = overloads.map(function (handle) {
        const methodId = env.fromReflectedMethod(handle);
        const modifiers = invokeIntMethodNoArgs(env.handle, handle, Method.getModifiers);

        const jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_METHOD : INSTANCE_METHOD;
        const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);
        let jsRetType;
        const jsArgTypes = [];
        try {
          const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
          env.checkForExceptionAndThrowIt();
          try {
            jsRetType = getTypeFromJniTypeName(env.getTypeName(retType));
          } finally {
            env.deleteLocalRef(retType);
          }
          const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericParameterTypes);
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
        const isInstance = this.$handle !== null;
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
        type === INSTANCE_METHOD ? 'this.$handle' : 'this.$classHandle',
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
        callArgsDirect.splice(2, 0, 'this.$classHandle');
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
      const sanitizedName = methodName.replace(/^[^a-zA-Z_]|[^a-zA-Z0-9_]/g, '_');
      const pendingCalls = new Set();
      eval('f = function ' + sanitizedName + '(' + argVariableNames.join(', ') + ') {' + // eslint-disable-line
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

        const target = cloneArtMethod(methodId);
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
        }

        if (fn !== null) {
          implementation = implement(f, fn);

          // kAccFastNative so that the VM doesn't get suspended while executing JNI
          // (so that we can modify the ArtMethod on the fly)
          patchMethod(methodId, {
            'jniCode': implementation,
            'accessFlags': Memory.readU32(methodId.add(artMethodOffset.accessFlags)) | kAccNative | kAccFastNative,
            'quickCode': api.artQuickGenericJniTrampoline,
            'interpreterCode': api.artInterpreterToCompiledCodeBridge
          });

          patchedMethods.add(f);
        } else {
          patchedMethods.delete(f);

          patchMethod(methodId, artOriginalMethodInfo);
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
          const accessFlags = Memory.readU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS)) | kAccNative;
          const registersSize = argsSize;
          const outsSize = 0;
          const insSize = argsSize;
          // parse method arguments
          const jniArgInfo = 0x80000000;

          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS), accessFlags);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE), registersSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE), outsSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_INS_SIZE), insSize);
          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO), jniArgInfo);

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
        const objectPtr = api.dvmDecodeIndirectRef(thread, instance ? this.$handle : this.$classHandle);
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
    classHandle = null;
    env = null;

    return klass;
  }

  function registerClass (spec) {
    const env = vm.getEnv();
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

    const pendingMethods = interfaces.reduce((result, iface) => {
      const ifaceHandle = iface.$classHandle;
      const ifaceProto = Object.getPrototypeOf(iface);
      Object.getOwnPropertyNames(ifaceProto)
        .filter(name => {
          return name[0] !== '$' && name !== 'constructor' && name !== 'class';
        })
        .forEach(name => {
          result[name] = [ifaceHandle, ifaceProto];
        });
      return result;
    }, {});

    const methods = spec.methods || {};
    const methodNames = Object.keys(methods);
    const numMethods = methodNames.length;

    const nativeMethods = [];
    const temporaryHandles = [];

    let methodElements = null;

    if (numMethods > 0) {
      const methodElementSize = 3 * pointerSize;
      methodElements = Memory.alloc(numMethods * methodElementSize);

      methodNames.forEach((name, index) => {
        const methodValue = methods[name];

        let method = null;
        let returnType;
        let argumentTypes;
        let thrownTypeNames = [];
        let impl;

        const m = pendingMethods[name];
        if (m !== undefined) {
          const [ifaceHandle, ifaceProto] = m;
          delete pendingMethods[name];

          if (typeof methodValue !== 'function') {
            throw new Error('Expected a function for method: ' + name);
          }
          impl = methodValue;

          method = ifaceProto[name];
          const overloads = method.overloads;
          if (overloads.length > 1) {
            throw new Error('More than one overload matching: ' + name);
          }
          method = overloads[0];

          returnType = method.returnType;
          argumentTypes = method.argumentTypes;

          const reflectedMethod = env.toReflectedMethod(ifaceHandle, method.handle, 0);
          const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
          thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
          env.deleteLocalRef(thrownTypes);
        } else if (typeof methodValue === 'function') {
          returnType = getTypeFromJniTypeName('void');
          argumentTypes = [];
          impl = methodValue;
        } else {
          returnType = getTypeFromJniTypeName(methodValue.returnType || 'void');
          argumentTypes = (methodValue.argumentTypes || []).map(name => getTypeFromJniTypeName(name));
          impl = methodValue.implementation;
          if (typeof impl !== 'function') {
            throw new Error('Expected a function implementation for method: ' + name);
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

      const unimplementedMethodNames = Object.keys(pendingMethods);
      if (unimplementedMethodNames.length > 0) {
        throw new Error('Missing implementation for: ' + unimplementedMethodNames.join(', '));
      }
    }

    const dexFile = DexFile.fromBuffer(mkdex(dexSpec));
    dexFile.load();

    const Klass = factory.use(spec.name);
    Klass.$nativeMethods = nativeMethods;

    if (numMethods > 0) {
      env.registerNatives(Klass.$classHandle, methodElements, numMethods);
      env.checkForExceptionAndThrowIt();
    }

    const C = classes[spec.name];

    function placeholder (...args) {
      return new C(...args);
    }
    placeholder.__handle__ = Klass.__handle__;

    return Klass;
  }

  function makeSourceFileName (className) {
    const tokens = className.split('.');
    return tokens[tokens.length - 1] + '.java';
  }

  function makeHandleDestructor () { // eslint-disable-line
    const handles = Array.prototype.slice.call(arguments).filter((h) => (h !== null));
    return () => {
      vm.perform(() => {
        const env = vm.getEnv();
        handles.forEach((ref) => (env.deleteGlobalRef(ref)), env);
      });
    };
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
    const sanitizedName = methodName.replace(/^[^a-zA-Z$_]|[^a-zA-Z0-9$_]/g, '_');
    let f;
    eval('f = function ' + sanitizedName + '(' + ['envHandle', 'thisHandle'].concat(argVariableNames).join(', ') + ') {' + // eslint-disable-line
      'var env = new Env(envHandle, vm);' +
      'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' +
      'return;' +
      '}' +
      'var self = ' + ((type === INSTANCE_METHOD) ? 'new C(C.__handle__, thisHandle);' : 'new C(thisHandle, null);') +
      'var result;' +
      'var tid = Process.getCurrentThreadId();' +
      'try {' +
      'pendingCalls.add(tid);' +
      returnCapture + 'fn.call(' + ['self'].concat(callArgs).join(', ') + ');' +
      '} catch (e) {' +
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

function getPrimitiveType (type) {
  switch (type) {
    case 'boolean':
      return {
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
      };
    case 'byte':
      return {
        name: 'B',
        type: 'int8',
        size: 1,
        byteSize: 1,
        isCompatible: function (v) {
          return Number.isInteger(v) && v >= -128 && v <= 127;
        },
        memoryRead: Memory.readS8,
        memoryWrite: Memory.writeS8
      };
    case 'char':
      return {
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
      };
    case 'short':
      return {
        name: 'S',
        type: 'int16',
        size: 1,
        byteSize: 2,
        isCompatible: function (v) {
          return Number.isInteger(v) && v >= -32768 && v <= 32767;
        },
        memoryRead: Memory.readS16,
        memoryWrite: Memory.writeS16
      };
    case 'int':
      return {
        name: 'I',
        type: 'int32',
        size: 1,
        byteSize: 4,
        isCompatible: function (v) {
          return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
        },
        memoryRead: Memory.readS32,
        memoryWrite: Memory.writeS32
      };
    case 'long':
      return {
        name: 'J',
        type: 'int64',
        size: 2,
        byteSize: 8,
        isCompatible: function (v) {
          return typeof v === 'number' || v instanceof Int64;
        },
        memoryRead: Memory.readS64,
        memoryWrite: Memory.writeS64
      };
    case 'float':
      return {
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
      };
    case 'double':
      return {
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
      };
    case 'void':
      return {
        name: 'V',
        type: 'void',
        size: 0,
        byteSize: 0,
        isCompatible: function (v) {
          return v === undefined;
        }
      };
    default:
      return undefined;
  }
}

function getObjectType (typeName, unbox, factory) {
  return {
    name: makeJniObjectTypeName(typeName),
    type: 'pointer',
    size: 1,
    isCompatible: function (v) {
      if (v === null) {
        return true;
      } else if (typeof v === 'string' && (typeName === 'java.lang.Object' || typeName === 'java.lang.CharSequence' || typeName === 'java.lang.String')) {
        return true;
      }

      return typeof v === 'object' && v.hasOwnProperty('$handle'); // TODO: improve strictness
    },
    fromJni: function (h, env) {
      if (h.isNull()) {
        return null;
      } else if (typeName === 'java.lang.String' && unbox) {
        return env.stringFromJni(h);
      } else if (this && this.$handle !== null && env.isSameObject(h, this.$handle)) {
        return this;
      } else {
        return factory.cast(h, factory.use(typeName));
      }
    },
    toJni: function (o, env) {
      if (o === null) {
        return NULL;
      } else if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$handle;
    }
  };
}

function getArrayType (typeName, unbox, factory) {
  switch (typeName) {
    case '[Z':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'boolean', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'boolean', env, env.getArrayLength, env.getBooleanArrayElements, env.releaseBooleanArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'boolean', env, env.newBooleanArray, env.setBooleanArrayRegion, factory);
        }
      };
    case '[B':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'byte', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'byte', env, env.getArrayLength, env.getByteArrayElements, env.releaseByteArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'byte', env, env.newByteArray, env.setByteArrayRegion, factory);
        }
      };
    case '[C':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'char', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'char', env, env.getArrayLength, env.getCharArrayElements, env.releaseCharArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'char', env, env.newCharArray, env.setCharArrayRegion, factory);
        }
      };
    case '[D':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'double', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'double', env, env.getArrayLength, env.getDoubleArrayElements, env.releaseDoubleArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'double', env, env.newDoubleArray, env.setDoubleArrayRegion, factory);
        }
      };
    case '[F':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'float', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'float', env, env.getArrayLength, env.getFloatArrayElements, env.releaseFloatArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'float', env, env.newFloatArray, env.setFloatArrayRegion, factory);
        }
      };
    case '[I':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'int', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'int', env, env.getArrayLength, env.getIntArrayElements, env.releaseIntArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'int', env, env.newIntArray, env.setIntArrayRegion, factory);
        }
      };
    case '[J':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'long', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'long', env, env.getArrayLength, env.getLongArrayElements, env.releaseLongArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'long', env, env.newLongArray, env.setLongArrayRegion, factory);
        }
      };
    case '[S':
      return {
        name: typeName,
        type: 'pointer',
        size: 1,
        isCompatible: function (v) {
          return isCompatiblePrimitiveArray(v, 'short', factory);
        },
        fromJni: function (h, env) {
          return fromJniPrimitiveArray(h, 'short', env, env.getArrayLength, env.getShortArrayElements, env.releaseShortArrayElements, factory);
        },
        toJni: function (arr, env) {
          return toJniPrimitiveArray(arr, 'short', env, env.newShortArray, env.setShortArrayRegion, factory);
        }
      };
    default:
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
          let classHandle, klassObj;

          const loader = factory.loader;
          if (loader !== null) {
            klassObj = factory.use(elementTypeName);
            classHandle = klassObj.$classHandle;
          } else {
            classHandle = env.findClass(elementTypeName.replace(/\./g, '/'));
          }

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
            if (loader !== null) {
              classHandle = null;
              klassObj = null;
            } else {
              env.deleteLocalRef(classHandle);
            }
          }
        }
      };
  }
}

function fromJniObjectArray (arr, env, convertFromJniFunc) {
  if (arr.isNull()) {
    return null;
  }
  const result = [];
  const length = env.getArrayLength(arr);
  for (let i = 0; i < length; i++) {
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
  const length = arr.length;
  const result = env.newObjectArray(length, classHandle, NULL);

  // Maybe OutOfMemoryError
  env.checkForExceptionAndThrowIt();
  if (result.isNull()) {
    return NULL;
  }
  for (let i = 0; i < length; i++) {
    setObjectArrayFunc.call(env, i, result);
    // maybe ArrayIndexOutOfBoundsException or ArrayStoreException
    env.checkForExceptionAndThrowIt();
  }
  return result;
}

function fromJniPrimitiveArray (arr, typeName, env, getArrayLengthFunc, getArrayElementsFunc, releaseArrayElementsFunc, factory) {
  if (arr.isNull()) {
    return null;
  }
  const result = [];
  const type = getType(typeName, true, factory);
  const length = getArrayLengthFunc.call(env, arr);
  const cArr = getArrayElementsFunc.call(env, arr);
  if (cArr.isNull()) {
    throw new Error("Can't get the array elements.");
  }
  try {
    const offset = type.byteSize;
    for (let i = 0; i < length; i++) {
      const value = type.memoryRead(cArr.add(i * offset));
      if (type.fromJni) {
        result.push(type.fromJni(value));
      } else {
        result.push(value);
      }
    }
  } finally {
    releaseArrayElementsFunc.call(env, arr, cArr);
  }

  return result;
}

function toJniPrimitiveArray (arr, typeName, env, newArrayFunc, setArrayFunc, factory) {
  if (arr === null) {
    return NULL;
  }
  const length = arr.length;
  const type = getType(typeName, true, factory);
  const result = newArrayFunc.call(env, length);
  if (result.isNull()) {
    throw new Error("The array can't be constructed.");
  }

  // we have to alloc memory only if there are array items
  if (length > 0) {
    const cArray = Memory.alloc(length * type.byteSize);
    for (let i = 0; i < length; i++) {
      if (type.toJni) {
        type.memoryWrite(cArray.add(i * type.byteSize), type.toJni(arr[i]));
      } else {
        type.memoryWrite(cArray.add(i * type.byteSize), arr[i]);
      }
    }
    setArrayFunc.call(env, result, 0, length, cArray);
    // check for ArrayIndexOutOfBoundsException
    env.checkForExceptionAndThrowIt();
  }

  return result;
}

function isCompatiblePrimitiveArray (v, typeName, factory) {
  return v === null || typeof v === 'object' && v.hasOwnProperty('length') &&
    Array.prototype.every.call(v, elem => getType(typeName, true, factory).isCompatible(elem));
}

module.exports = ClassFactory;

/* global Int64, Memory, NativeCallback, NativeFunction, NULL, Process, WeakRef */
