import Env from './env.js';
import * as android from './android.js';
import { ensureClassInitialized as jvmEnsureClassInitialized, makeMethodMangler as jvmMakeMethodMangler } from './jvm.js';
import ClassModel from './class-model.js';
import LRU from './lru.js';
import mkdex from './mkdex.js';
import {
  getType,
  getPrimitiveType,
  getArrayType,
  makeJniObjectTypeName
} from './types.js';
const jsizeSize = 4;
let {
  ensureClassInitialized,
  makeMethodMangler
} = android;

const kAccStatic = 0x0008;

const CONSTRUCTOR_METHOD = 1;
const STATIC_METHOD = 2;
const INSTANCE_METHOD = 3;

const STATIC_FIELD = 1;
const INSTANCE_FIELD = 2;

const STRATEGY_VIRTUAL = 1;
const STRATEGY_DIRECT = 2;

const PENDING_USE = Symbol('PENDING_USE');

const DEFAULT_CACHE_DIR = '/data/local/tmp';

const {
  getCurrentThreadId,
  pointerSize
} = Process;

const factoryCache = {
  state: 'empty',
  factories: [],
  loaders: null,
  Integer: null
};

let vm = null;
let api = null;
let isArtVm = null;

let wrapperHandler = null;
let dispatcherPrototype = null;
let methodPrototype = null;
let valueOfPrototype = null;

let cachedLoaderInvoke = null;
let cachedLoaderMethod = null;

const ignoredThreads = new Map();

export default class ClassFactory {
  static _initialize (_vm, _api) {
    vm = _vm;
    api = _api;
    isArtVm = _api.flavor === 'art';
    if (_api.flavor === 'jvm') {
      ensureClassInitialized = jvmEnsureClassInitialized;
      makeMethodMangler = jvmMakeMethodMangler;
    }
  }

  static _disposeAll (env) {
    factoryCache.factories.forEach(factory => {
      factory._dispose(env);
    });
  }

  static get (classLoader) {
    const cache = getFactoryCache();

    const defaultFactory = cache.factories[0];

    if (classLoader === null) {
      return defaultFactory;
    }

    const indexObj = cache.loaders.get(classLoader);
    if (indexObj !== null) {
      const index = defaultFactory.cast(indexObj, cache.Integer);
      return cache.factories[index.intValue()];
    }

    const factory = new ClassFactory();
    factory.loader = classLoader;
    factory.cacheDir = defaultFactory.cacheDir;
    addFactoryToCache(factory, classLoader);

    return factory;
  }

  constructor () {
    this.cacheDir = DEFAULT_CACHE_DIR;
    this.codeCacheDir = DEFAULT_CACHE_DIR + '/dalvik-cache';

    this.tempFileNaming = {
      prefix: 'frida',
      suffix: ''
    };

    this._classes = {};
    this._classHandles = new LRU(10, releaseClassHandle);
    this._patchedMethods = new Set();
    this._loader = null;
    this._types = [{}, {}];

    factoryCache.factories.push(this);
  }

  _dispose (env) {
    Array.from(this._patchedMethods).forEach(method => {
      method.implementation = null;
    });
    this._patchedMethods.clear();

    android.revertGlobalPatches();

    this._classHandles.dispose(env);
    this._classes = {};
  }

  get loader () {
    return this._loader;
  }

  set loader (value) {
    const isInitial = this._loader === null && value !== null;

    this._loader = value;

    if (isInitial && factoryCache.state === 'ready' && this === factoryCache.factories[0]) {
      addFactoryToCache(this, value);
    }
  }

  use (className, options = {}) {
    const allowCached = options.cache !== 'skip';

    let C = allowCached ? this._getUsedClass(className) : undefined;
    if (C === undefined) {
      try {
        const env = vm.getEnv();

        const { _loader: loader } = this;
        const getClassHandle = (loader !== null)
          ? makeLoaderClassHandleGetter(className, loader, env)
          : makeBasicClassHandleGetter(className);

        C = this._make(className, getClassHandle, env);
      } finally {
        if (allowCached) {
          this._setUsedClass(className, C);
        }
      }
    }

    return C;
  }

  _getUsedClass (className) {
    let c;
    while ((c = this._classes[className]) === PENDING_USE) {
      Thread.sleep(0.05);
    }
    if (c === undefined) {
      this._classes[className] = PENDING_USE;
    }
    return c;
  }

  _setUsedClass (className, c) {
    if (c !== undefined) {
      this._classes[className] = c;
    } else {
      delete this._classes[className];
    }
  }

  _make (name, getClassHandle, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      [Symbol.for('n')]: {
        value: name
      },
      $n: {
        get () {
          return this[Symbol.for('n')];
        }
      },
      [Symbol.for('C')]: {
        value: C
      },
      $C: {
        get () {
          return this[Symbol.for('C')];
        }
      },
      [Symbol.for('w')]: {
        value: null,
        writable: true
      },
      $w: {
        get () {
          return this[Symbol.for('w')];
        },
        set (val) {
          this[Symbol.for('w')] = val;
        }
      },
      [Symbol.for('_s')]: {
        writable: true
      },
      $_s: {
        get () {
          return this[Symbol.for('_s')];
        },
        set (val) {
          this[Symbol.for('_s')] = val;
        }
      },
      [Symbol.for('c')]: {
        value: [null]
      },
      $c: {
        get () {
          return this[Symbol.for('c')];
        }
      },
      [Symbol.for('m')]: {
        value: new Map()
      },
      $m: {
        get () {
          return this[Symbol.for('m')];
        }
      },
      [Symbol.for('l')]: {
        value: null,
        writable: true
      },
      $l: {
        get () {
          return this[Symbol.for('l')];
        },
        set (val) {
          this[Symbol.for('l')] = val;
        }
      },
      [Symbol.for('gch')]: {
        value: getClassHandle
      },
      $gch: {
        get () {
          return this[Symbol.for('gch')];
        }
      },
      [Symbol.for('f')]: {
        value: this
      },
      $f: {
        get () {
          return this[Symbol.for('f')];
        }
      }
    });
    C.prototype = proto;

    const classWrapper = new C(null);
    proto[Symbol.for('w')] = classWrapper;
    proto.$w = classWrapper;

    const h = classWrapper.$borrowClassHandle(env);
    try {
      const classHandle = h.value;

      ensureClassInitialized(env, classHandle);

      proto.$l = ClassModel.build(classHandle, env);
    } finally {
      h.unref(env);
    }

    return classWrapper;
  }

  retain (obj) {
    const env = vm.getEnv();
    return obj.$clone(env);
  }

  cast (obj, klass, owned) {
    const env = vm.getEnv();

    let handle = obj.$h;
    if (handle === undefined) {
      handle = obj;
    }

    const h = klass.$borrowClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, h.value);
      if (!isValidCast) {
        throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$n}' isn't possible`);
      }
    } finally {
      h.unref(env);
    }

    const C = klass.$C;
    return new C(handle, STRATEGY_VIRTUAL, env, owned);
  }

  wrap (handle, klass, env) {
    const C = klass.$C;
    const wrapper = new C(handle, STRATEGY_VIRTUAL, env, false);
    wrapper.$r = Script.bindWeak(wrapper, vm.makeHandleDestructor(handle));
    return wrapper;
  }

  array (type, elements) {
    const env = vm.getEnv();

    const primitiveType = getPrimitiveType(type);
    if (primitiveType !== null) {
      type = primitiveType.name;
    }
    const arrayType = getArrayType('[' + type, false, this);

    const rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env, true);
  }

  registerClass (spec) {
    const env = vm.getEnv();

    const tempHandles = [];
    try {
      const Class = this.use('java.lang.Class');
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const className = spec.name;
      const interfaces = (spec.implements || []);
      const superClass = (spec.superClass || this.use('java.lang.Object'));

      const dexFields = [];
      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: makeJniObjectTypeName(superClass.$n),
        interfaces: interfaces.map(iface => makeJniObjectTypeName(iface.$n)),
        fields: dexFields,
        methods: dexMethods
      };

      const allInterfaces = interfaces.slice();
      interfaces.forEach(iface => {
        Array.prototype.slice.call(iface.class.getInterfaces())
          .forEach(baseIface => {
            const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
            allInterfaces.push(this.use(baseIfaceName));
          });
      });

      const fields = spec.fields || {};
      Object.getOwnPropertyNames(fields).forEach(name => {
        const fieldType = this._getType(fields[name]);
        dexFields.push([name, fieldType.name]);
      });

      const baseMethods = {};
      const pendingOverloads = {};
      allInterfaces.forEach(iface => {
        const h = iface.$borrowClassHandle(env);
        tempHandles.push(h);
        const ifaceHandle = h.value;

        iface.$ownMembers
          .filter(name => {
            return iface[name].overloads !== undefined;
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
        const rawName = (name === '$init') ? '<init>' : name;
        if (entry instanceof Array) {
          result.push(...entry.map(e => [rawName, e]));
        } else {
          result.push([rawName, entry]);
        }
        return result;
      }, []);

      const implMethods = [];

      methodEntries.forEach(([name, methodValue]) => {
        let type = INSTANCE_METHOD;
        let returnType;
        let argumentTypes;
        let thrownTypeNames = [];
        let impl;

        if (typeof methodValue === 'function') {
          const m = baseMethods[name];
          if (m !== undefined && Array.isArray(m)) {
            const [baseMethod, overloadIds, parentTypeHandle] = m;

            if (overloadIds.length > 1) {
              throw new Error(`More than one overload matching '${name}': signature must be specified`);
            }
            delete pendingOverloads[overloadIds[0]];
            const overload = baseMethod.overloads[0];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;
            impl = methodValue;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          } else {
            returnType = this._getType('void');
            argumentTypes = [];
            impl = methodValue;
          }
        } else {
          if (methodValue.isStatic) {
            type = STATIC_METHOD;
          }
          returnType = this._getType(methodValue.returnType || 'void');
          argumentTypes = (methodValue.argumentTypes || []).map(name => this._getType(name));
          impl = methodValue.implementation;
          if (typeof impl !== 'function') {
            throw new Error('Expected a function implementation for method: ' + name);
          }

          const id = makeOverloadId(name, returnType, argumentTypes);
          const pendingOverload = pendingOverloads[id];
          if (pendingOverload !== undefined) {
            const [overload, parentTypeHandle] = pendingOverload;
            delete pendingOverloads[id];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          }
        }

        const returnTypeName = returnType.name;
        const argumentTypeNames = argumentTypes.map(t => t.name);
        const signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;

        dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames, (type === STATIC_METHOD) ? kAccStatic : 0]);
        implMethods.push([name, signature, type, returnType, argumentTypes, impl]);
      });

      const unimplementedMethodIds = Object.keys(pendingOverloads);
      if (unimplementedMethodIds.length > 0) {
        throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
      }

      const dex = DexFile.fromBuffer(mkdex(dexSpec), this);
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }

      const classWrapper = this.use(spec.name);

      const numMethods = methodEntries.length;
      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize;
        const methodElements = Memory.alloc(numMethods * methodElementSize);

        const nativeMethods = [];
        const temporaryHandles = [];

        implMethods.forEach(([name, signature, type, returnType, argumentTypes, impl], index) => {
          const rawName = Memory.allocUtf8String(name);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(name, classWrapper, type, returnType, argumentTypes, impl);

          methodElements.add(index * methodElementSize).writePointer(rawName);
          methodElements.add((index * methodElementSize) + pointerSize).writePointer(rawSignature);
          methodElements.add((index * methodElementSize) + (2 * pointerSize)).writePointer(rawImpl);

          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });

        const h = classWrapper.$borrowClassHandle(env);
        tempHandles.push(h);
        const classHandle = h.value;

        env.registerNatives(classHandle, methodElements, numMethods);
        env.throwIfExceptionPending();

        classWrapper.$nativeMethods = nativeMethods;
      }

      return classWrapper;
    } finally {
      tempHandles.forEach(h => { h.unref(env); });
    }
  }

  choose (specifier, callbacks) {
    const env = vm.getEnv();
    const { flavor } = api;
    if (flavor === 'jvm') {
      this._chooseObjectsJvm(specifier, env, callbacks);
    } else if (flavor === 'art') {
      const legacyApiMissing = api['art::gc::Heap::VisitObjects'] === undefined;
      if (legacyApiMissing) {
        const preA12ApiMissing = api['art::gc::Heap::GetInstances'] === undefined;
        if (preA12ApiMissing) {
          return this._chooseObjectsJvm(specifier, env, callbacks);
        }
      }
      android.withRunnableArtThread(vm, env, thread => {
        if (legacyApiMissing) {
          this._chooseObjectsArtPreA12(specifier, env, thread, callbacks);
        } else {
          this._chooseObjectsArtLegacy(specifier, env, thread, callbacks);
        }
      });
    } else {
      this._chooseObjectsDalvik(specifier, env, callbacks);
    }
  }

  _chooseObjectsJvm (className, env, callbacks) {
    const classWrapper = this.use(className);
    const { jvmti } = api;
    const JVMTI_ITERATION_CONTINUE = 1;
    const JVMTI_HEAP_OBJECT_EITHER = 3;

    const h = classWrapper.$borrowClassHandle(env);
    const tag = int64(h.value.toString());
    try {
      const heapObjectCallback = new NativeCallback((classTag, size, tagPtr, userData) => {
        tagPtr.writeS64(tag);
        return JVMTI_ITERATION_CONTINUE;
      }, 'int', ['int64', 'int64', 'pointer', 'pointer']);
      jvmti.iterateOverInstancesOfClass(h.value, JVMTI_HEAP_OBJECT_EITHER, heapObjectCallback, h.value);

      const tagPtr = Memory.alloc(8);
      tagPtr.writeS64(tag);
      const countPtr = Memory.alloc(jsizeSize);
      const objectsPtr = Memory.alloc(pointerSize);
      jvmti.getObjectsWithTags(1, tagPtr, countPtr, objectsPtr, NULL);

      const count = countPtr.readS32();
      const objects = objectsPtr.readPointer();
      const handles = [];
      for (let i = 0; i !== count; i++) {
        handles.push(objects.add(i * pointerSize).readPointer());
      }
      jvmti.deallocate(objects);

      try {
        for (const handle of handles) {
          const instance = this.cast(handle, classWrapper);
          const result = callbacks.onMatch(instance);
          if (result === 'stop') {
            break;
          }
        }

        callbacks.onComplete();
      } finally {
        handles.forEach(handle => {
          env.deleteLocalRef(handle);
        });
      }
    } finally {
      h.unref(env);
    }
  }

  _chooseObjectsArtPreA12 (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const scope = android.VariableSizedHandleScope.$new(thread, vm);

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, h.value);
      needle = scope.newHandle(object);
    } finally {
      h.unref(env);
    }

    const maxCount = 0;

    const instances = android.HandleVector.$new();

    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);

    const instanceHandles = instances.handles.map(handle => env.newGlobalRef(handle));

    instances.$delete();
    scope.$delete();

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
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

  _chooseObjectsArtLegacy (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const instanceHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      needle = api['art::JavaVMExt::DecodeGlobal'](vmHandle, thread, h.value).toInt32();
    } finally {
      h.unref(env);
    }

    const collectMatchingInstanceHandles = android.makeObjectVisitorPredicate(needle, object => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });

    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
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

  _chooseObjectsDalvik (className, callerEnv, callbacks) {
    const classWrapper = this.use(className);

    if (api.addLocalReference === null) {
      const libdvm = Process.getModuleByName('libdvm.so');

      let pattern;
      switch (Process.arch) {
        case 'arm':
          // Verified with 4.3.1 and 4.4.4
          pattern = '2d e9 f0 41 05 46 15 4e 0c 46 7e 44 11 b3 43 68';
          break;
        case 'ia32':
          // Verified with 4.3.1 and 4.4.2
          pattern = '8d 64 24 d4 89 5c 24 1c 89 74 24 20 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 d2';
          break;
      }

      Memory.scan(libdvm.base, libdvm.size, pattern, {
        onMatch: (address, size) => {
          let wrapper;
          if (Process.arch === 'arm') {
            address = address.or(1); // Thumb
            wrapper = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
          } else {
            const thunk = Memory.alloc(Process.pageSize);
            Memory.patchCode(thunk, 16, code => {
              const cw = new X86Writer(code, { pc: thunk });
              cw.putMovRegRegOffsetPtr('eax', 'esp', 4);
              cw.putMovRegRegOffsetPtr('edx', 'esp', 8);
              cw.putJmpAddress(address);
              cw.flush();
            });
            wrapper = new NativeFunction(thunk, 'pointer', ['pointer', 'pointer']);
            wrapper._thunk = thunk;
          }
          api.addLocalReference = wrapper;

          vm.perform(env => {
            enumerateInstances(this, env);
          });

          return 'stop';
        },
        onError (reason) {},
        onComplete () {
          if (api.addLocalReference === null) {
            callbacks.onComplete();
          }
        }
      });
    } else {
      enumerateInstances(this, callerEnv);
    }

    function enumerateInstances (factory, env) {
      const { DVM_JNI_ENV_OFFSET_SELF } = android;
      const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

      let ptrClassObject;
      const h = classWrapper.$borrowClassHandle(env);
      try {
        ptrClassObject = api.dvmDecodeIndirectRef(thread, h.value);
      } finally {
        h.unref(env);
      }

      const pattern = ptrClassObject.toMatchPattern();
      const heapSourceBase = api.dvmHeapSourceGetBase();
      const heapSourceLimit = api.dvmHeapSourceGetLimit();
      const size = heapSourceLimit.sub(heapSourceBase).toInt32();

      Memory.scan(heapSourceBase, size, pattern, {
        onMatch: (address, size) => {
          if (api.dvmIsValidObject(address)) {
            vm.perform(env => {
              const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

              let instance;
              const localReference = api.addLocalReference(thread, address);
              try {
                instance = factory.cast(localReference, classWrapper);
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
    }
  }

  openClassFile (filePath) {
    return new DexFile(filePath, null, this);
  }

  _getType (typeName, unbox = true) {
    return getType(typeName, unbox, this);
  }
}

function makeClassWrapperConstructor () {
  return function (handle, strategy, env, owned) {
    return Wrapper.call(this, handle, strategy, env, owned);
  };
}

function Wrapper (handle, strategy, env, owned = true) {
  if (handle !== null) {
    if (owned) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = Script.bindWeak(this, vm.makeHandleDestructor(h));
    } else {
      this.$h = handle;
      this.$r = null;
    }
  } else {
    this.$h = null;
    this.$r = null;
  }

  this.$t = strategy;

  return new Proxy(this, wrapperHandler);
}

wrapperHandler = {
  has (target, property) {
    if (property in target) {
      return true;
    }

    return target.$has(property);
  },
  get (target, property, receiver) {
    if (typeof property !== 'string' || property.startsWith('$') || property === 'class') {
      return target[property];
    }

    const unwrap = target.$find(property);
    if (unwrap !== null) {
      return unwrap(receiver);
    }

    return target[property];
  },
  set (target, property, value, receiver) {
    target[property] = value;
    return true;
  },
  ownKeys (target) {
    return target.$list();
  },
  getOwnPropertyDescriptor (target, property) {
    if (Object.prototype.hasOwnProperty.call(target, property)) {
      return Object.getOwnPropertyDescriptor(target, property);
    }

    return {
      writable: false,
      configurable: true,
      enumerable: true
    };
  }
};

Object.defineProperties(Wrapper.prototype, {
  [Symbol.for('new')]: {
    enumerable: false,
    get () {
      return this.$getCtor('allocAndInit');
    }
  },
  $new: {
    enumerable: true,
    get () {
      return this[Symbol.for('new')];
    }
  },
  [Symbol.for('alloc')]: {
    enumerable: false,
    value () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const obj = env.allocObject(h.value);
        const factory = this.$f;
        return factory.cast(obj, this);
      } finally {
        h.unref(env);
      }
    }
  },
  $alloc: {
    enumerable: true,
    get () {
      return this[Symbol.for('alloc')];
    }
  },
  [Symbol.for('init')]: {
    enumerable: false,
    get () {
      return this.$getCtor('initOnly');
    }
  },
  $init: {
    enumerable: true,
    get () {
      return this[Symbol.for('init')];
    }
  },
  [Symbol.for('dispose')]: {
    enumerable: false,
    value () {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }

      if (this.$h !== null) {
        this.$h = undefined;
      }
    }
  },
  $dispose: {
    enumerable: true,
    get () {
      return this[Symbol.for('dispose')];
    }
  },
  [Symbol.for('clone')]: {
    enumerable: false,
    value (env) {
      const C = this.$C;
      return new C(this.$h, this.$t, env);
    }
  },
  $clone: {
    value (env) {
      return this[Symbol.for('clone')](env);
    }
  },
  [Symbol.for('class')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const factory = this.$f;
        return factory.cast(h.value, factory.use('java.lang.Class'));
      } finally {
        h.unref(env);
      }
    }
  },
  class: {
    enumerable: true,
    get () {
      return this[Symbol.for('class')];
    }
  },
  [Symbol.for('className')]: {
    enumerable: false,
    get () {
      const handle = this.$h;
      if (handle === null) {
        return this.$n;
      }

      return vm.getEnv().getObjectClassName(handle);
    }
  },
  $className: {
    enumerable: true,
    get () {
      return this[Symbol.for('className')];
    }
  },
  [Symbol.for('ownMembers')]: {
    enumerable: false,
    get () {
      const model = this.$l;
      return model.list();
    }
  },
  $ownMembers: {
    enumerable: true,
    get () {
      return this[Symbol.for('ownMembers')];
    }
  },
  [Symbol.for('super')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const C = this.$s.$C;
      return new C(this.$h, STRATEGY_DIRECT, env);
    }
  },
  $super: {
    enumerable: true,
    get () {
      return this[Symbol.for('super')];
    }
  },
  [Symbol.for('s')]: {
    enumerable: false,
    get () {
      const proto = Object.getPrototypeOf(this);

      let superWrapper = proto.$_s;
      if (superWrapper === undefined) {
        const env = vm.getEnv();

        const h = this.$borrowClassHandle(env);
        try {
          const superHandle = env.getSuperclass(h.value);
          if (!superHandle.isNull()) {
            try {
              const superClassName = env.getClassName(superHandle);
              const factory = proto.$f;
              superWrapper = factory._getUsedClass(superClassName);
              if (superWrapper === undefined) {
                try {
                  const getSuperClassHandle = makeSuperHandleGetter(this);
                  superWrapper = factory._make(superClassName, getSuperClassHandle, env);
                } finally {
                  factory._setUsedClass(superClassName, superWrapper);
                }
              }
            } finally {
              env.deleteLocalRef(superHandle);
            }
          } else {
            superWrapper = null;
          }
        } finally {
          h.unref(env);
        }

        proto.$_s = superWrapper;
      }

      return superWrapper;
    }
  },
  $s: {
    get () {
      return this[Symbol.for('s')];
    }
  },
  [Symbol.for('isSameObject')]: {
    enumerable: false,
    value (obj) {
      const env = vm.getEnv();
      return env.isSameObject(obj.$h, this.$h);
    }
  },
  $isSameObject: {
    value (obj) {
      return this[Symbol.for('isSameObject')](obj);
    }
  },
  [Symbol.for('getCtor')]: {
    enumerable: false,
    value (type) {
      const slot = this.$c;

      let ctor = slot[0];
      if (ctor === null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          ctor = makeConstructor(h.value, this.$w, env);
          slot[0] = ctor;
        } finally {
          h.unref(env);
        }
      }

      return ctor[type];
    }
  },
  $getCtor: {
    value (type) {
      return this[Symbol.for('getCtor')](type);
    }
  },
  [Symbol.for('borrowClassHandle')]: {
    enumerable: false,
    value (env) {
      const className = this.$n;
      const classHandles = this.$f._classHandles;

      let handle = classHandles.get(className);
      if (handle === undefined) {
        handle = new ClassHandle(this.$gch(env), env);
        classHandles.set(className, handle, env);
      }

      return handle.ref();
    }
  },
  $borrowClassHandle: {
    value (env) {
      return this[Symbol.for('borrowClassHandle')](env);
    }
  },
  [Symbol.for('copyClassHandle')]: {
    enumerable: false,
    value (env) {
      const h = this.$borrowClassHandle(env);
      try {
        return env.newLocalRef(h.value);
      } finally {
        h.unref(env);
      }
    }
  },
  $copyClassHandle: {
    value (env) {
      return this[Symbol.for('copyClassHandle')](env);
    }
  },
  [Symbol.for('getHandle')]: {
    enumerable: false,
    value (env) {
      const handle = this.$h;

      const isDisposed = handle === undefined;
      if (isDisposed) {
        throw new Error('Wrapper is disposed; perhaps it was borrowed from a hook ' +
            'instead of calling Java.retain() to make a long-lived wrapper?');
      }

      return handle;
    }
  },
  $getHandle: {
    value (env) {
      return this[Symbol.for('getHandle')](env);
    }
  },
  [Symbol.for('list')]: {
    enumerable: false,
    value () {
      const superWrapper = this.$s;
      const superMembers = (superWrapper !== null) ? superWrapper.$list() : [];

      const model = this.$l;
      return Array.from(new Set(superMembers.concat(model.list())));
    }
  },
  $list: {
    get () {
      return this[Symbol.for('list')];
    }
  },
  [Symbol.for('has')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;
      if (members.has(member)) {
        return true;
      }

      const model = this.$l;
      if (model.has(member)) {
        return true;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null && superWrapper.$has(member)) {
        return true;
      }

      return false;
    }
  },
  $has: {
    value (member) {
      return this[Symbol.for('has')](member);
    }
  },
  [Symbol.for('find')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;

      let value = members.get(member);
      if (value !== undefined) {
        return value;
      }

      const model = this.$l;
      const spec = model.find(member);
      if (spec !== null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          value = makeMember(member, spec, h.value, this.$w, env);
        } finally {
          h.unref(env);
        }
        members.set(member, value);
        return value;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null) {
        return superWrapper.$find(member);
      }

      return null;
    }
  },
  $find: {
    value (member) {
      return this[Symbol.for('find')](member);
    }
  },
  [Symbol.for('toJSON')]: {
    enumerable: false,
    value () {
      const wrapperName = this.$n;

      const handle = this.$h;
      if (handle === null) {
        return `<class: ${wrapperName}>`;
      }

      const actualName = this.$className;
      if (wrapperName === actualName) {
        return `<instance: ${wrapperName}>`;
      }

      return `<instance: ${wrapperName}, $className: ${actualName}>`;
    }
  },
  toJSON: {
    get () {
      return this[Symbol.for('toJSON')];
    }
  }
});

function ClassHandle (value, env) {
  this.value = env.newGlobalRef(value);
  env.deleteLocalRef(value);

  this.refs = 1;
}

ClassHandle.prototype.ref = function () {
  this.refs++;
  return this;
};

ClassHandle.prototype.unref = function (env) {
  if (--this.refs === 0) {
    env.deleteGlobalRef(this.value);
  }
};

function releaseClassHandle (handle, env) {
  handle.unref(env);
}

function makeBasicClassHandleGetter (className) {
  const canonicalClassName = className.replace(/\./g, '/');

  return function (env) {
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      return env.findClass(canonicalClassName);
    } finally {
      unignore(tid);
    }
  };
}

function makeLoaderClassHandleGetter (className, usedLoader, callerEnv) {
  if (cachedLoaderMethod === null) {
    cachedLoaderInvoke = callerEnv.vaMethod('pointer', ['pointer']);
    cachedLoaderMethod = usedLoader.loadClass.overload('java.lang.String').handle;
  }

  callerEnv = null;

  return function (env) {
    const classNameValue = env.newStringUtf(className);

    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      env.throwIfExceptionPending();
      return result;
    } finally {
      unignore(tid);
      env.deleteLocalRef(classNameValue);
    }
  };
}

function makeSuperHandleGetter (classWrapper) {
  return function (env) {
    const h = classWrapper.$borrowClassHandle(env);
    try {
      return env.getSuperclass(h.value);
    } finally {
      h.unref(env);
    }
  };
}

function makeConstructor (classHandle, classWrapper, env) {
  const { $n: className, $f: factory } = classWrapper;
  const methodName = basename(className);
  const Class = env.javaLangClass();
  const Constructor = env.javaLangReflectConstructor();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const jsCtorMethods = [];
  const jsInitMethods = [];
  const jsRetType = factory._getType(className, false);
  const jsVoidType = factory._getType('void', false);

  const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
  try {
    const n = env.getArrayLength(constructors);

    if (n !== 0) {
      for (let i = 0; i !== n; i++) {
        let methodId, types;
        const constructor = env.getObjectArrayElement(constructors, i);
        try {
          methodId = env.fromReflectedMethod(constructor);
          types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
        } finally {
          env.deleteLocalRef(constructor);
        }

        let jsArgTypes;
        try {
          jsArgTypes = readTypeNames(env, types).map(name => factory._getType(name));
        } finally {
          env.deleteLocalRef(types);
        }

        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
      }
    } else {
      const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
      if (isInterface) {
        throw new Error('cannot instantiate an interface');
      }

      const defaultClass = env.javaLangObject();
      const defaultConstructor = env.getMethodId(defaultClass, '<init>', '()V');

      jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
      jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
    }
  } finally {
    env.deleteLocalRef(constructors);
  }

  if (jsInitMethods.length === 0) {
    throw new Error('no supported overloads');
  }

  return {
    allocAndInit: makeMethodDispatcher(jsCtorMethods),
    initOnly: makeMethodDispatcher(jsInitMethods)
  };
}

function makeMember (name, spec, classHandle, classWrapper, env) {
  if (spec.startsWith('m')) {
    return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
  }

  return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
}

function makeMethodFromSpec (name, spec, classHandle, classWrapper, env) {
  const { $f: factory } = classWrapper;
  const overloads = spec.split(':').slice(1);

  const Method = env.javaLangReflectMethod();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const methods = overloads.map(params => {
    const type = (params[0] === 's') ? STATIC_METHOD : INSTANCE_METHOD;
    const methodId = ptr(params.substr(1));

    let jsRetType;
    const jsArgTypes = [];
    const handle = env.toReflectedMethod(classHandle, methodId, (type === STATIC_METHOD) ? 1 : 0);
    try {
      const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

      const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
      env.throwIfExceptionPending();
      try {
        jsRetType = factory._getType(env.getTypeName(retType));
      } finally {
        env.deleteLocalRef(retType);
      }

      const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
      try {
        const n = env.getArrayLength(argTypes);

        for (let i = 0; i !== n; i++) {
          const t = env.getObjectArrayElement(argTypes, i);

          let argClassName;
          try {
            argClassName = (isVarArgs && i === n - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
          } finally {
            env.deleteLocalRef(t);
          }

          const argType = factory._getType(argClassName);
          jsArgTypes.push(argType);
        }
      } finally {
        env.deleteLocalRef(argTypes);
      }
    } catch (e) {
      return null;
    } finally {
      env.deleteLocalRef(handle);
    }

    return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
  })
    .filter(m => m !== null);

  if (methods.length === 0) {
    throw new Error('No supported overloads');
  }

  if (name === 'valueOf') {
    ensureDefaultValueOfImplemented(methods);
  }

  const result = makeMethodDispatcher(methods);

  return function (receiver) {
    return result;
  };
}

function makeMethodDispatcher (overloads) {
  const m = makeMethodDispatcherCallable();
  Object.setPrototypeOf(m, dispatcherPrototype);
  m._o = overloads;
  return m;
}

function makeMethodDispatcherCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

dispatcherPrototype = Object.create(Function.prototype, {
  overloads: {
    enumerable: true,
    get () {
      return this._o;
    }
  },
  overload: {
    value (...args) {
      const overloads = this._o;

      const numArgs = args.length;
      const signature = args.join(':');

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        const { argumentTypes } = method;

        if (argumentTypes.length !== numArgs) {
          continue;
        }

        const s = argumentTypes.map(t => t.className).join(':');
        if (s === signature) {
          return method;
        }
      }

      throwOverloadError(this.methodName, this.overloads, 'specified argument types do not match any of:');
    }
  },
  methodName: {
    enumerable: true,
    get () {
      return this._o[0].methodName;
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._o[0].holder;
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._o[0].type;
    }
  },
  handle: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].handle;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].implementation;
    },
    set (fn) {
      throwIfDispatcherAmbiguous(this);
      this._o[0].implementation = fn;
    }
  },
  returnType: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].returnType;
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].argumentTypes;
    }
  },
  canInvokeWith: {
    enumerable: true,
    get (args) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].canInvokeWith;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].clone(options);
    }
  },
  invoke: {
    value (receiver, args) {
      const overloads = this._o;

      const isInstance = receiver.$h !== null;

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];

        if (!method.canInvokeWith(args)) {
          continue;
        }

        if (method.type === INSTANCE_METHOD && !isInstance) {
          const name = this.methodName;

          if (name === 'toString') {
            return `<class: ${receiver.$n}>`;
          }

          throw new Error(name + ': cannot call instance method without an instance');
        }

        return method.apply(receiver, args);
      }

      if (this.methodName === 'toString') {
        return `<class: ${receiver.$n}>`;
      }

      throwOverloadError(this.methodName, this.overloads, 'argument types do not match any of:');
    }
  }
});

function makeOverloadId (name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map(t => t.className).join(', ')})`;
}

function throwIfDispatcherAmbiguous (dispatcher) {
  const methods = dispatcher._o;
  if (methods.length > 1) {
    throwOverloadError(methods[0].methodName, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
  }
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

function makeMethod (methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
  const rawRetType = retType.type;
  const rawArgTypes = argTypes.map((t) => t.type);

  if (env === null) {
    env = vm.getEnv();
  }

  let callVirtually, callDirectly;
  if (type === INSTANCE_METHOD) {
    callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
  } else if (type === STATIC_METHOD) {
    callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  } else {
    callVirtually = env.constructor(rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  }

  return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
}

function makeMethodInstance (params) {
  const m = makeMethodCallable();
  Object.setPrototypeOf(m, methodPrototype);
  m._p = params;
  return m;
}

function makeMethodCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

methodPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return this._p[3];
    }
  },
  implementation: {
    enumerable: true,
    get () {
      const replacement = this._r;
      return (replacement !== undefined) ? replacement : null;
    },
    set (fn) {
      const params = this._p;
      const holder = params[1];
      const type = params[2];

      if (type === CONSTRUCTOR_METHOD) {
        throw new Error('Reimplementing $new is not possible; replace implementation of $init instead');
      }

      const existingReplacement = this._r;
      if (existingReplacement !== undefined) {
        holder.$f._patchedMethods.delete(this);

        const mangler = existingReplacement._m;
        mangler.revert(vm);

        this._r = undefined;
      }

      if (fn !== null) {
        const [methodName, classWrapper, type, methodId, retType, argTypes] = params;

        const replacement = implement(methodName, classWrapper, type, retType, argTypes, fn, this);
        const mangler = makeMethodMangler(methodId);
        replacement._m = mangler;
        this._r = replacement;

        mangler.replace(replacement, type === INSTANCE_METHOD, argTypes, vm, api);

        holder.$f._patchedMethods.add(this);
      }
    }
  },
  returnType: {
    enumerable: true,
    get () {
      return this._p[4];
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return this._p[5];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      const argTypes = this._p[5];

      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      const params = this._p.slice(0, 6);
      return makeMethod(...params, null, options);
    }
  },
  invoke: {
    value (receiver, args) {
      const env = vm.getEnv();

      const params = this._p;
      const type = params[2];
      const retType = params[4];
      const argTypes = params[5];

      const replacement = this._r;

      const isInstanceMethod = type === INSTANCE_METHOD;
      const numArgs = args.length;

      const frameCapacity = 2 + numArgs;
      env.pushLocalFrame(frameCapacity);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (isInstanceMethod) {
          jniThis = receiver.$getHandle();
        } else {
          borrowedHandle = receiver.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        let methodId;
        let strategy = receiver.$t;
        if (replacement === undefined) {
          methodId = params[3];
        } else {
          const mangler = replacement._m;
          methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);

          if (isArtVm) {
            const pendingCalls = replacement._c;
            if (pendingCalls.has(getCurrentThreadId())) {
              strategy = STRATEGY_DIRECT;
            }
          }
        }

        const jniArgs = [
          env.handle,
          jniThis,
          methodId
        ];
        for (let i = 0; i !== numArgs; i++) {
          jniArgs.push(argTypes[i].toJni(args[i], env));
        }

        let jniCall;
        if (strategy === STRATEGY_VIRTUAL) {
          jniCall = params[6];
        } else {
          jniCall = params[7];

          if (isInstanceMethod) {
            jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
          }
        }

        const jniRetval = jniCall.apply(null, jniArgs);
        env.throwIfExceptionPending();

        return retType.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  toString: {
    enumerable: true,
    value () {
      return `function ${this.methodName}(${this.argumentTypes.map(t => t.className).join(', ')}): ${this.returnType.className}`;
    }
  }
});

function implement (methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
  const pendingCalls = new Set();

  const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);

  const impl = new NativeCallback(f, retType.type, ['pointer', 'pointer'].concat(argTypes.map(t => t.type)));
  impl._c = pendingCalls;

  return impl;
}

function makeMethodImplementation (params) {
  return function () {
    return handleMethodInvocation(arguments, params);
  };
}

function handleMethodInvocation (jniArgs, params) {
  const env = new Env(jniArgs[0], vm);

  const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;

  const ownedObjects = [];

  let self;
  if (type === INSTANCE_METHOD) {
    const C = classWrapper.$C;
    self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
  } else {
    self = classWrapper;
  }

  const tid = getCurrentThreadId();

  env.pushLocalFrame(3);
  let haveFrame = true;

  vm.link(tid, env);

  try {
    pendingCalls.add(tid);

    let fn;
    if (fallback === null || !ignoredThreads.has(tid)) {
      fn = handler;
    } else {
      fn = fallback;
    }

    const args = [];
    const numArgs = jniArgs.length - 2;
    for (let i = 0; i !== numArgs; i++) {
      const t = argTypes[i];

      const value = t.fromJni(jniArgs[2 + i], env, false);
      args.push(value);

      ownedObjects.push(value);
    }

    const retval = fn.apply(self, args);

    if (!retType.isCompatible(retval)) {
      throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
    }

    let jniRetval = retType.toJni(retval, env);

    if (retType.type === 'pointer') {
      jniRetval = env.popLocalFrame(jniRetval);
      haveFrame = false;

      ownedObjects.push(retval);
    }

    return jniRetval;
  } catch (e) {
    const jniException = e.$h;
    if (jniException !== undefined) {
      env.throw(jniException);
    } else {
      Script.nextTick(() => { throw e; });
    }

    return retType.defaultValue;
  } finally {
    vm.unlink(tid);

    if (haveFrame) {
      env.popLocalFrame(NULL);
    }

    pendingCalls.delete(tid);

    ownedObjects.forEach(obj => {
      if (obj === null) {
        return;
      }

      const dispose = obj.$dispose;
      if (dispose !== undefined) {
        dispose.call(obj);
      }
    });
  }
}

function ensureDefaultValueOfImplemented (methods) {
  const { holder, type } = methods[0];

  const hasDefaultValueOf = methods.some(m => m.type === type && m.argumentTypes.length === 0);
  if (hasDefaultValueOf) {
    return;
  }

  methods.push(makeValueOfMethod([holder, type]));
}

function makeValueOfMethod (params) {
  const m = makeValueOfCallable();
  Object.setPrototypeOf(m, valueOfPrototype);
  m._p = params;
  return m;
}

function makeValueOfCallable () {
  const m = function () {
    return this;
  };
  return m;
}

valueOfPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return 'valueOf';
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return NULL;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      return null;
    },
    set (fn) {
    }
  },
  returnType: {
    enumerable: true,
    get () {
      const classWrapper = this.holder;
      return classWrapper.$f.use(classWrapper.$n);
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return [];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      return args.length === 0;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throw new Error('Invalid operation');
    }
  }
});

function makeFieldFromSpec (name, spec, classHandle, classWrapper, env) {
  const type = (spec[2] === 's') ? STATIC_FIELD : INSTANCE_FIELD;
  const id = ptr(spec.substr(3));
  const { $f: factory } = classWrapper;

  let fieldType;
  const field = env.toReflectedField(classHandle, id, (type === STATIC_FIELD) ? 1 : 0);
  try {
    fieldType = env.vaMethod('pointer', [])(env.handle, field, env.javaLangReflectField().getGenericType);
    env.throwIfExceptionPending();
  } finally {
    env.deleteLocalRef(field);
  }

  let rtype;
  try {
    rtype = factory._getType(env.getTypeName(fieldType));
  } finally {
    env.deleteLocalRef(fieldType);
  }

  let getValue, setValue;
  const rtypeJni = rtype.type;
  if (type === STATIC_FIELD) {
    getValue = env.getStaticField(rtypeJni);
    setValue = env.setStaticField(rtypeJni);
  } else {
    getValue = env.getField(rtypeJni);
    setValue = env.setField(rtypeJni);
  }

  return makeFieldFromParams([type, rtype, id, getValue, setValue]);
}

function makeFieldFromParams (params) {
  return function (receiver) {
    return new Field([receiver].concat(params));
  };
}

function Field (params) {
  this._p = params;
}

Object.defineProperties(Field.prototype, {
  value: {
    enumerable: true,
    get () {
      const [holder, type, rtype, id, getValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        const jniRetval = getValue(env.handle, jniThis, id);
        env.throwIfExceptionPending();

        return rtype.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    },
    set (value) {
      const [holder, type, rtype, id, , setValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        if (!rtype.isCompatible(value)) {
          throw new Error(`Expected value compatible with ${rtype.className}`);
        }
        const jniValue = rtype.toJni(value, env);

        setValue(env.handle, jniThis, id, jniValue);
        env.throwIfExceptionPending();
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  fieldType: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  fieldReturnType: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  toString: {
    enumerable: true,
    value () {
      const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
      if (inlineString.length < 200) {
        return inlineString;
      }
      const multilineString = `Java.Field{
\tholder: ${this.holder},
\tfieldType: ${this.fieldType},
\tfieldReturnType: ${this.fieldReturnType},
\tvalue: ${this.value},
}`;
      return multilineString.split('\n').map(l => l.length > 200 ? l.slice(0, l.indexOf(' ') + 1) + '...,' : l).join('\n');
    }
  }
});

class DexFile {
  static fromBuffer (buffer, factory) {
    const fileValue = createTemporaryDex(factory);
    const filePath = fileValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();
    setReadOnlyDex(filePath, factory);

    return new DexFile(filePath, fileValue, factory);
  }

  constructor (path, file, factory) {
    this.path = path;
    this.file = file;

    this._factory = factory;
  }

  load () {
    const { _factory: factory } = this;
    const { codeCacheDir } = factory;
    const DexClassLoader = factory.use('dalvik.system.DexClassLoader');
    const JFile = factory.use('java.io.File');

    let file = this.file;
    if (file === null) {
      file = factory.use('java.io.File').$new(this.path);
    }
    if (!file.exists()) {
      throw new Error('File not found');
    }

    JFile.$new(codeCacheDir).mkdirs();

    factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);

    vm.preventDetachDueToClassLoader();
  }

  getClassNames () {
    const { _factory: factory } = this;
    const DexFile = factory.use('dalvik.system.DexFile');

    const optimizedDex = createTemporaryDex(factory);
    const dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);

    const classNames = [];
    const enumeratorClassNames = dx.entries();
    while (enumeratorClassNames.hasMoreElements()) {
      classNames.push(enumeratorClassNames.nextElement().toString());
    }
    return classNames;
  }
}

function createTemporaryDex (factory) {
  const { cacheDir, tempFileNaming } = factory;
  const JFile = factory.use('java.io.File');

  const cacheDirValue = JFile.$new(cacheDir);
  cacheDirValue.mkdirs();

  return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + '.dex', cacheDirValue);
}

function setReadOnlyDex (filePath, factory) {
  const JFile = factory.use('java.io.File');
  const file = JFile.$new(filePath);
  file.setWritable(false, false);
}

function getFactoryCache () {
  switch (factoryCache.state) {
    case 'empty': {
      factoryCache.state = 'pending';

      const defaultFactory = factoryCache.factories[0];

      const HashMap = defaultFactory.use('java.util.HashMap');
      const Integer = defaultFactory.use('java.lang.Integer');

      factoryCache.loaders = HashMap.$new();
      factoryCache.Integer = Integer;

      const loader = defaultFactory.loader;
      if (loader !== null) {
        addFactoryToCache(defaultFactory, loader);
      }

      factoryCache.state = 'ready';

      return factoryCache;
    }
    case 'pending':
      do {
        Thread.sleep(0.05);
      } while (factoryCache.state === 'pending');
      return factoryCache;
    case 'ready':
      return factoryCache;
  }
}

function addFactoryToCache (factory, loader) {
  const { factories, loaders, Integer } = factoryCache;

  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);

  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }

    loaders.put(l, index);
  }
}

function ignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    count = 0;
  }
  count++;
  ignoredThreads.set(threadId, count);
}

function unignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    throw new Error(`Thread ${threadId} is not ignored`);
  }
  count--;
  if (count === 0) {
    ignoredThreads.delete(threadId);
  } else {
    ignoredThreads.set(threadId, count);
  }
}

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function readTypeNames (env, types) {
  const names = [];

  const n = env.getArrayLength(types);
  for (let i = 0; i !== n; i++) {
    const t = env.getObjectArrayElement(types, i);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}
