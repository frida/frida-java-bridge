const Env = require('./env'); // eslint-disable-line
const getApi = require('./api');
const {
  ensureClassInitialized,
  getAndroidApiLevel,
  getArtMethodSpec,
  getAndroidVersion,
  getArtThreadSpec,
  makeMethodMangler,
  revertGlobalPatches,
  withRunnableArtThread,
  HandleVector
} = require('./android');
const ClassModel = require('./class-model');
const LRU = require('./lru');
const mkdex = require('./mkdex');
const {JNI_OK} = require('./result');
const {
  getType,
  getPrimitiveType,
  getArrayType,
  makeJniObjectTypeName
} = require('./types');

const pointerSize = Process.pointerSize;

const CONSTRUCTOR_METHOD = 1;
const STATIC_METHOD = 2;
const INSTANCE_METHOD = 3;

const STATIC_FIELD = 1;
const INSTANCE_FIELD = 2;

const STRATEGY_VIRTUAL = 1;
const STRATEGY_DIRECT = 2;

const factoryCache = {
  state: 'empty',
  factories: [],
  loaders: null,
  Integer: null,
  vm: null
};

let cachedLoaderInvoke = null;
let cachedLoaderMethod = null;

const ignoredThreads = {};

function ClassFactory (vm) {
  const factory = this;
  let api = null;
  let classes = {};
  const classHandles = new LRU(10, releaseClassHandle);
  let wrapperHandler;
  const patchedMethods = new Set();
  let loader = null;
  let cacheDir = '/data/local/tmp';
  let tempFileNaming = {
    prefix: 'frida',
    suffix: 'dat'
  };
  const PENDING_USE = Symbol('PENDING_USE');
  const PENDING_CALLS = Symbol('PENDING_CALLS');

  function initialize () {
    api = getApi();

    factoryCache.factories.push(this);
    if (factoryCache.vm === null) {
      factoryCache.vm = vm;
    }
  }

  this.dispose = function (env) {
    Array.from(patchedMethods).forEach(method => {
      method.implementation = null;
    });
    patchedMethods.clear();

    revertGlobalPatches();

    classHandles.dispose(env);

    classes = {};
  };

  Object.defineProperty(this, 'loader', {
    get: function () {
      return loader;
    },
    set: function (value) {
      const isInitial = loader === null && value !== null;

      loader = value;

      if (isInitial && factoryCache.state === 'ready' && this === factoryCache.factories[0]) {
        addFactoryToCache(this, value);
      }
    }
  });

  Object.defineProperty(this, 'cacheDir', {
    get: function () {
      return cacheDir;
    },
    set: function (value) {
      cacheDir = value;
    }
  });

  Object.defineProperty(this, 'tempFileNaming', {
    get: function () {
      return tempFileNaming;
    },
    set: function (value) {
      tempFileNaming = value;
    }
  });

  this.use = function (className, options = {}) {
    const allowCached = options.cache !== 'skip';

    let C = allowCached ? getUsedClass(className) : undefined;
    if (C === undefined) {
      const env = vm.getEnv();

      const getClassHandle = (loader !== null)
          ? makeLoaderClassHandleGetter(className, loader, env)
          : makeBasicClassHandleGetter(className);

      try {
        C = ensureClass(getClassHandle, className, env);
      } finally {
        if (allowCached) {
          setUsedClass(className, C);
        }
      }
    }

    return C;
  };

  function makeBasicClassHandleGetter (className) {
    const canonicalClassName = className.replace(/\./g, '/');

    return function (env) {
      const tid = Process.getCurrentThreadId();
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

      const tid = Process.getCurrentThreadId();
      ignore(tid);
      try {
        return cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      } finally {
        unignore(tid);
        env.deleteLocalRef(classNameValue);
      }
    };
  }

  function getUsedClass (className) {
    let kclass;
    while ((kclass = classes[className]) === PENDING_USE) {
      Thread.sleep(0.05);
    }
    if (kclass === undefined) {
      classes[className] = PENDING_USE;
    }
    return kclass;
  }

  function setUsedClass (className, kclass) {
    if (kclass !== undefined) {
      classes[className] = kclass;
    } else {
      delete classes[className];
    }
  }

  this.retain = function (obj) {
    const C = obj.$C;
    return new C(obj.$h);
  };

  this.cast = function (obj, klass) {
    const env = vm.getEnv();

    let handle = obj.$h;
    if (handle === undefined) {
      handle = obj;
    }

    const h = klass.$borrowClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, h.value);
      if (!isValidCast) {
        throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$className}' isn't possible`);
      }
    } finally {
      h.unref(env);
    }

    const C = klass.$C;
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

  function ensureClass (getClassHandle, name, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      $className: {
        enumerable: true,
        value: name
      },
      $C: {
        value: C
      },
      $w: {
        value: null,
        writable: true
      },
      $_s: {
        writable: true
      },
      $c: {
        value: [null]
      },
      $m: {
        value: new Map()
      },
      $l: {
        value: null,
        writable: true
      },
      $gch: {
        value: getClassHandle
      },
    });
    C.prototype = proto;

    const classWrapper = new C(null);
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

  function makeClassWrapperConstructor () {
    return function (handle, strategy = STRATEGY_VIRTUAL) {
      return Wrapper.call(this, handle, strategy);
    };
  }

  function Wrapper (handle, strategy) {
    const env = vm.getEnv();

    if (handle !== null) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = WeakRef.bind(this, vm.makeHandleDestructor(h));
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
      if (property.startsWith('$') || property === 'class') {
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
      const keys = target.$list();

      if (Script.runtime === 'DUK') {
        // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
        keys.forEach(key => { target[key] = true; });
      }

      return keys;
    },
    getOwnPropertyDescriptor (target, property) {
      if (target.hasOwnProperty(property)) {
        return Object.getOwnPropertyDescriptor(target, property);
      }

      return {
        writable: false,
        configurable: true,
        enumerable: true
      };
    },
  };

  Object.defineProperties(Wrapper.prototype, {
    $new: {
      enumerable: true,
      get () {
        return this.$getCtor('allocAndInit');
      }
    },
    $alloc: {
      enumerable: true,
      value () {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          const obj = env.allocObject(h.value);
          return factory.cast(obj, this);
        } finally {
          h.unref(env);
        }
      }
    },
    $init: {
      enumerable: true,
      get () {
        return this.$getCtor('initOnly');
      }
    },
    $dispose: {
      enumerable: true,
      value () {
        const ref = this.$r;
        if (ref !== null) {
          this.$r = null;
          WeakRef.unbind(ref);
        }
      }
    },
    class: {
      enumerable: true,
      get () {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          return factory.cast(h.value, factory.use('java.lang.Class'));
        } finally {
          h.unref(env);
        }
      }
    },
    $super: {
      enumerable: true,
      get () {
        const C = this.$s.$C;
        return new C(this.$h, STRATEGY_DIRECT);
      }
    },
    $s: {
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
                superWrapper = getUsedClass(superClassName);
                if (superWrapper === undefined) {
                  try {
                    const getSuperClassHandle = makeSuperHandleGetter(this);
                    superWrapper = ensureClass(getSuperClassHandle, superClassName, env);
                  } finally {
                    setUsedClass(superClassName, superWrapper);
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
    $isSameObject: {
      value (obj) {
        const env = vm.getEnv();
        return env.isSameObject(obj.$h, this.$h);
      }
    },
    $getCtor: {
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
    $borrowClassHandle: {
      value (env) {
        const className = this.$className;

        let handle = classHandles.get(className);
        if (handle === undefined) {
          handle = new ClassHandle(this.$gch(env), env);
          classHandles.set(className, handle, env);
        }

        return handle.ref();
      }
    },
    $copyClassHandle: {
      value (env) {
        const h = this.$borrowClassHandle(env);
        try {
          return env.newLocalRef(h.value);
        } finally {
          h.unref(env);
        }
      }
    },
    $list: {
      value () {
        const superWrapper = this.$s;
        const superMembers = (superWrapper !== null) ? superWrapper.$list() : [];

        const model = this.$l;
        return superMembers.concat(model.list());
      }
    },
    $has: {
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
        if (superWrapper !== null && superWrapper.has(member)) {
          return true;
        }

        return false;
      }
    },
    $find: {
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
    toJSON: {
      value () {
        return {
          $className: this.$className,
        };
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
    const className = classWrapper.$className;
    const methodName = basename(className);
    const Constructor = env.javaLangReflectConstructor();
    const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

    const jsCtorMethods = [];
    const jsInitMethods = [];
    const jsRetType = getTypeFromJniTypeName(className, false);
    const jsVoidType = getTypeFromJniTypeName('void', false);
    const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredConstructors);
    try {
      const n = env.getArrayLength(constructors);
      if (n > 0) {
        env.pushLocalFrame(1 + n * 2);
        try {
          for (let i = 0; i !== n; i++) {
            const constructor = env.getObjectArrayElement(constructors, i);
            const methodId = env.fromReflectedMethod(constructor);

            const types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
            const jsArgTypes = readTypeNames(env, types).map(name => getTypeFromJniTypeName(name));

            jsCtorMethods.push(makeMethod(methodName, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, classWrapper, env));
            jsInitMethods.push(makeMethod(methodName, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, classWrapper, env));
          }
        } finally {
          env.popLocalFrame(NULL);
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

  function makeMember (name, spec, classHandle, classWrapper, env) {
    if (spec.startsWith('m')) {
      return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
    }

    return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
  }

  function makeMethodFromSpec (name, spec, classHandle, classWrapper, env) {
    const overloads = spec.split(':').slice(1);

    const Method = env.javaLangReflectMethod();
    const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
    const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

    let methods;
    env.pushLocalFrame(1 + overloads.length * 3);
    try {
      methods = overloads.map(params => {
        const jsType = (params[0] === 's') ? STATIC_METHOD : INSTANCE_METHOD;
        const methodId = ptr(params.substr(1));

        let jsRetType;
        const jsArgTypes = [];
        const handle = env.toReflectedMethod(classHandle, methodId, (jsType === STATIC_METHOD) ? 1 : 0);
        try {
          const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

          const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
          env.checkForExceptionAndThrowIt();
          jsRetType = getTypeFromJniTypeName(env.getTypeName(retType));

          const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
          env.checkForExceptionAndThrowIt();
          const n = env.getArrayLength(argTypes);
          if (n > 0) {
            env.pushLocalFrame(1 + n);
            try {
              for (let i = 0; i !== n; i++) {
                const t = env.getObjectArrayElement(argTypes, i);
                const argClassName = (isVarArgs && i === n - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
                const argType = getTypeFromJniTypeName(argClassName);
                jsArgTypes.push(argType);
              }
            } finally {
              env.popLocalFrame(NULL);
            }
          }
        } catch (e) {
          return null;
        }

        return makeMethod(name, jsType, methodId, jsRetType, jsArgTypes, classWrapper, env);
      })
      .filter(m => m !== null);
    } finally {
      env.popLocalFrame(NULL);
    }

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

        defaultValueOf.methodName = name;

        defaultValueOf.holder = classWrapper;

        defaultValueOf.type = INSTANCE_METHOD;

        defaultValueOf.handle = NULL;

        defaultValueOf.implementation = null;

        defaultValueOf.returnType = getTypeFromJniTypeName('int');

        defaultValueOf.argumentTypes = [];

        defaultValueOf.canInvokeWith = (args) => args.length === 0;

        defaultValueOf.clone = options => {
          throw new Error('Invalid operation');
        };

        methods.push(defaultValueOf);
      }
    }

    const result = makeMethodDispatcher(name, methods);

    return function (receiver) {
      return result;
    };
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
      const isInstance = this.$h !== null;
      const group = candidates[args.length];
      if (!group) {
        throwOverloadError(name, methods, `argument count of ${args.length} does not match any of:`);
      }
      for (let i = 0; i !== group.length; i++) {
        const method = group[i];
        if (method.canInvokeWith(args)) {
          if (method.type === INSTANCE_METHOD && !isInstance) {
            if (name === 'toString') {
              return '<' + this.$className + '>';
            }
            throw new Error(name + ': cannot call instance method without an instance');
          }
          return method.apply(this, args);
        }
      }
      throwOverloadError(name, methods, 'argument types do not match any of:');
    }

    f.overloads = methods;

    f.overload = (...args) => {
      const group = candidates[args.length];
      if (!group) {
        throwOverloadError(name, methods, `argument count of ${args.length} does not match any of:`);
      }

      const signature = args.join(':');
      for (let i = 0; i !== group.length; i++) {
        const method = group[i];
        const s = method.argumentTypes.map(t => t.className).join(':');
        if (s === signature) {
          return method;
        }
      }

      throwOverloadError(name, methods, 'specified argument types do not match any of:');
    };

    f.methodName = name;

    f.holder = methods[0].holder;

    f.type = methods[0].type;

    if (methods.length === 1) {
      f.handle = methods[0].handle;

      Object.defineProperty(f, 'implementation', {
        get() {
          return methods[0].implementation;
        },
        set(imp) {
          methods[0].implementation = imp;
        }
      });

      f.returnType = methods[0].returnType;

      f.argumentTypes = methods[0].argumentTypes;

      f.canInvokeWith = methods[0].canInvokeWith;

      f.clone = options => {
        return methods[0].clone(options);
      };
    } else {
      Object.defineProperty(f, 'handle', {
        get: throwAmbiguousError
      });

      Object.defineProperty(f, 'implementation', {
        get: throwAmbiguousError,
        set: throwAmbiguousError
      });

      Object.defineProperty(f, 'returnType', {
        get: throwAmbiguousError
      });

      Object.defineProperty(f, 'argumentTypes', {
        get: throwAmbiguousError
      });

      f.canInvokeWith = throwAmbiguousError;

      f.clone = throwAmbiguousError;

      function throwAmbiguousError () {
        throwOverloadError(name, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
      }
    }

    return f;
  }

  function makeMethod (methodName, type, methodId, retType, argTypes, classWrapper, env, invocationOptions) {
    let intermediates = (function () {
      const rawRetType = retType.type;
      const rawArgTypes = argTypes.map((t) => t.type);

      if (env === null) {
        env = vm.getEnv();
      }

      let invokeTargetVirtually, invokeTargetDirectly; // eslint-disable-line
      if (type === CONSTRUCTOR_METHOD) {
        invokeTargetVirtually = env.constructor(rawArgTypes, invocationOptions);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === STATIC_METHOD) {
        invokeTargetVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === INSTANCE_METHOD) {
        invokeTargetVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
        invokeTargetDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
      }

      env = null;

      let frameCapacity = 2;
      const argVariableNames = argTypes.map((t, i) => ('a' + (i + 1)));
      const callArgsVirtual = [
        'env.handle',
        (type === INSTANCE_METHOD) ? 'this.$h' : 'this.$copyClassHandle(env)',
        'mangler.resolveTarget(vm)',
      ].concat(argTypes.map((t, i) => {
        if (t.toJni !== undefined) {
          frameCapacity++;
          return ['argTypes[', i, '].toJni.call(this, ', argVariableNames[i], ', env)'].join('');
        } else {
          return argVariableNames[i];
        }
      }));
      let callArgsDirect;
      if (type === INSTANCE_METHOD) {
        callArgsDirect = callArgsVirtual.slice();
        callArgsDirect.splice(2, 0, 'this.$copyClassHandle(env)');
      } else {
        callArgsDirect = callArgsVirtual;
      }

      let returnCapture, returnStatements;
      if (rawRetType === 'void') {
        returnCapture = '';
        returnStatements = 'env.popLocalFrame(NULL);';
      } else {
        if (retType.fromJni !== undefined) {
          frameCapacity++;
          returnCapture = 'rawResult = ';
          returnStatements = `try {
    result = retType.fromJni.call(this, rawResult, env);
  } finally {
    env.popLocalFrame(NULL);
  }
  return result;`;
        } else {
          returnCapture = 'result = ';
          returnStatements = `env.popLocalFrame(NULL);
  return result;`;
        }
      }

      const directCode = [returnCapture, 'invokeTargetDirectly(', callArgsDirect.join(', '), ');'].join('');
      const virtualCode = [returnCapture, 'invokeTargetVirtually(', callArgsVirtual.join(', '), ');'].join('');

      let invokeCode;
      if (api.flavor === 'dalvik') {
        invokeCode = `if (this.$t === STRATEGY_DIRECT) {
      ${directCode}
    } else {
      mangler.synchronizeVtable(this, type === INSTANCE_METHOD, env, api);
      ${virtualCode}
    }`;
      } else {
        invokeCode = `if (this.$t === STRATEGY_DIRECT || pendingCalls.has(Process.getCurrentThreadId())) {
      ${directCode}
    } else {
      ${virtualCode}
    }`;
      }

      const code = `f = function (${argVariableNames.join(', ')}) {
  var env = vm.getEnv();
  if (env.pushLocalFrame(${frameCapacity}) !== JNI_OK) {
    env.exceptionClear();
    throw new Error('Out of memory');
  }

  var result, rawResult;
  try {
    ${invokeCode}
  } catch (e) {
    env.popLocalFrame(NULL);
    throw e;
  }

  try {
    env.checkForExceptionAndThrowIt();
  } catch (e) {
    env.popLocalFrame(NULL);
    throw e;
  }

  ${returnStatements}
};
`
      return [invokeTargetVirtually, invokeTargetDirectly, code];
    })();

    let implementation = null;
    const mangler = makeMethodMangler(methodId);
    const pendingCalls = new Set();

    const [invokeTargetVirtually, invokeTargetDirectly] = intermediates;

    let f;
    eval(intermediates[2]);

    intermediates = null;

    f.methodName = methodName;

    f.holder = classWrapper;

    f.type = type;

    f.handle = methodId;

    Object.defineProperty(f, 'implementation', {
      get() {
        return implementation;
      },
      set: (type === CONSTRUCTOR_METHOD) ? throwCannotReplaceNewError : function (fn) {
        if (fn !== null) {
          implementation = implement(f, fn);
          mangler.replace(implementation, type === INSTANCE_METHOD, argTypes, vm, api);
          patchedMethods.add(f);
        } else {
          patchedMethods.delete(f);
          mangler.revert(vm);
          implementation = null;
        }
      }
    });

    f.returnType = retType;

    f.argumentTypes = argTypes;

    f.canInvokeWith = args => {
      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    };

    f.clone = options => {
      return makeMethod(methodName, type, methodId, retType, argTypes, classWrapper, null, options);
    };

    f[PENDING_CALLS] = pendingCalls;

    return f;
  }

  function makeFieldFromSpec (name, spec, classHandle, classWrapper, env) {
    let intermediates = (function () {
      const type = (spec[2] === 's') ? STATIC_FIELD : INSTANCE_FIELD;
      const id = ptr(spec.substr(3));

      let rtype;
      env.pushLocalFrame(3);
      try {
        const handle = env.toReflectedField(classHandle, id, (type === STATIC_FIELD) ? 1 : 0);
        const fieldType = env.vaMethod('pointer', [])(env.handle, handle, env.javaLangReflectField().getGenericType);
        rtype = getTypeFromJniTypeName(env.getTypeName(fieldType));
      } catch (e) {
        return null;
      } finally {
        env.popLocalFrame(NULL);
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

      let frameCapacity = 3;
      const callArgs = [
        'env.handle',
        (type === INSTANCE_FIELD) ? 'this.$h' : 'this.$copyClassHandle(env)',
        'id'
      ];

      let returnCapture, returnStatements;
      if (rtype.fromJni !== undefined) {
        frameCapacity++;
        returnCapture = 'rawResult = ';
        returnStatements = 'try {' +
          'result = rtype.fromJni.call(this, rawResult, env);' +
          '} finally {' +
          'env.popLocalFrame(NULL);' +
          '} ' +
          'return result;';
      } else {
        returnCapture = 'result = ';
        returnStatements = 'env.popLocalFrame(NULL);' +
          'return result;';
      }

      let instanceCheck;
      if (type === INSTANCE_FIELD) {
        instanceCheck = `
  var isInstance = this.$h !== null;
  if (!isInstance) {
    throw new Error('${name}: cannot access an instance field without an instance');
  }
`;
      } else {
        instanceCheck = '';
      }

      const getterCode = `getter = function () {${instanceCheck}
  var env = vm.getEnv();

  if (env.pushLocalFrame(${frameCapacity}) !== JNI_OK) {
    env.exceptionClear();
    throw new Error('Out of memory');
  }

  var result, rawResult;
  try {
    ${returnCapture}getValue(${callArgs.join(', ')});
  } catch (e) {
    env.popLocalFrame(NULL);
    throw e;
  }

  try {
    env.checkForExceptionAndThrowIt();
  } catch (e) {
    env.popLocalFrame(NULL);
    throw e;
  }

  ${returnStatements}
}`;

      let inputStatement;
      if (rtype.toJni !== undefined) {
        inputStatement = 'var input = rtype.toJni.call(this, value, env);';
      } else {
        inputStatement = 'var input = value;';
      }

      const setterCode = `setter = function (value) {${instanceCheck}
  if (!rtype.isCompatible(value)) {
    throw new Error('Field "' + name + '" expected value compatible with ${rtype.className}');
  }

  var env = vm.getEnv();

  if (env.pushLocalFrame(${frameCapacity}) !== JNI_OK) {
    env.exceptionClear();
    throw new Error('Out of memory');
  }

  try {
    ${inputStatement}
    setValue(${callArgs.join(', ')}, input);
  } catch (e) {
    throw e;
  } finally {
    env.popLocalFrame(NULL);
  }

  env.checkForExceptionAndThrowIt();
}`;

      return [id, type, rtype, getValue, setValue, getterCode, setterCode];
    })();

    const [id, type, rtype, getValue, setValue] = intermediates;

    let getter, setter;
    eval(intermediates[5]);
    eval(intermediates[6]);

    intermediates = null;

    return function (receiver) {
      const f = {
        holder: classWrapper,
        fieldType: type,
        fieldReturnType: rtype,
      };

      Object.defineProperty(f, 'value', {
        get () {
          return getter.call(receiver);
        },
        set (value) {
          setter.call(receiver, value);
        }
      });

      return f;
    };
  }

  function registerClass (spec) {
    const env = vm.getEnv();

    const tempHandles = [];
    try {
      const Class = factory.use('java.lang.Class');
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const className = spec.name;
      const interfaces = (spec.implements || []);
      const superClass = (spec.superClass || factory.use('java.lang.Object'));

      const dexFields = [];
      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: makeJniObjectTypeName(superClass.$className),
        interfaces: interfaces.map(iface => makeJniObjectTypeName(iface.$className)),
        fields: dexFields,
        methods: dexMethods
      };

      const allInterfaces = interfaces.slice();
      interfaces.forEach(iface => {
        Array.prototype.slice.call(iface.class.getInterfaces())
          .forEach(baseIface => {
            const baseIfaceName = factory.cast(baseIface, Class).getCanonicalName();
            allInterfaces.push(factory.use(baseIfaceName));
          });
      });

      const fields = spec.fields || {};
      Object.getOwnPropertyNames(fields).forEach(name => {
        const fieldType = getTypeFromJniTypeName(fields[name]);
        dexFields.push([name, fieldType.name]);
      });

      const baseMethods = {};
      const pendingOverloads = {};
      allInterfaces.forEach(iface => {
        const h = iface.$borrowClassHandle(env);
        tempHandles.push(h);
        const ifaceHandle = h.value;

        Object.keys(iface)
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
        let method = null;
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

            method = Object.assign({}, overload, { holder: null });
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

            method = Object.assign({}, overload, { holder: null });

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
          }
        }

        if (method === null) {
          method = {
            methodName: name,
            holder: null,
            type: INSTANCE_METHOD,
            returnType: returnType,
            argumentTypes: argumentTypes,
          };
          method[PENDING_CALLS] = new Set();
        }

        const returnTypeName = returnType.name;
        const argumentTypeNames = argumentTypes.map(t => t.name);
        const signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;

        dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames]);
        implMethods.push([method, impl, signature]);
      });

      const unimplementedMethodIds = Object.keys(pendingOverloads);
      if (unimplementedMethodIds.length > 0) {
        throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
      }

      const dex = DexFile.fromBuffer(mkdex(dexSpec));
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }

      const classWrapper = factory.use(spec.name);

      const numMethods = methodEntries.length;
      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize;
        const methodElements = Memory.alloc(numMethods * methodElementSize);

        const nativeMethods = [];
        const temporaryHandles = [];

        implMethods.forEach(([method, impl, signature], index) => {
          method.holder = classWrapper;

          const rawName = Memory.allocUtf8String(method.methodName);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(method, impl);

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
        env.checkForExceptionAndThrowIt();

        classWrapper.$nativeMethods = nativeMethods;
      }

      return classWrapper;
    } finally {
      tempHandles.forEach(h => { h.unref(env); });
    }
  }

  function implement (method, fn) {
    if (method.overloads !== undefined) {
      throw new Error('Only re-implementing a concrete (specific) method is possible, not a method "dispatcher"');
    }

    let intermediates = (function () {
      const {methodName, type, returnType: retType, argumentTypes: argTypes} = method;

      const rawRetType = retType.type;
      const rawArgTypes = argTypes.map((t) => (t.type));

      let frameCapacity = 2;
      const argVariableNames = argTypes.map((t, i) => ('a' + (i + 1)));
      const callArgs = argTypes.map((t, i) => {
        if (t.fromJni !== undefined) {
          frameCapacity++;
          return ['argTypes[', i, '].fromJni.call(self, ', argVariableNames[i], ', env)'].join('');
        } else {
          return argVariableNames[i];
        }
      });
      let returnCapture, returnStatements, returnNothing;
      if (rawRetType === 'void') {
        returnCapture = '';
        returnStatements = ['env.popLocalFrame(NULL);'];
        returnNothing = 'return;';
      } else {
        if (retType.toJni !== undefined) {
          frameCapacity++;
          returnCapture = 'result = ';
          returnStatements = [`var rawResult;
  try {
    if (retType.isCompatible.call(this, result)) {
      rawResult = retType.toJni.call(this, result, env);
    } else {
      throw new Error('Implementation for ${methodName} expected return value compatible with ${retType.className}');
    }`];
          if (retType.type === 'pointer') {
            returnStatements.push(`  } catch (e) {
    env.popLocalFrame(NULL);
    throw e;
  }
  return env.popLocalFrame(rawResult);`);
            returnNothing = 'return NULL;';
          } else {
            returnStatements.push(`  } finally {
    env.popLocalFrame(NULL);
    }
    return rawResult;`);
            returnNothing = 'return 0;';
          }
        } else {
          returnCapture = 'result = ';
          returnStatements = [`env.popLocalFrame(NULL);
  return result;`];
          returnNothing = 'return 0;';
        }
      }

      const code = `f = function (${['envHandle', 'thisHandle'].concat(argVariableNames).join(', ')}) {
  var env = new Env(envHandle, vm);

  if (env.pushLocalFrame(${frameCapacity}) !== JNI_OK) {
    return;
  }

  var self = ${((type === INSTANCE_METHOD) ? 'new C(thisHandle)' : 'holder')};

  var result;
  var tid = Process.getCurrentThreadId();

  try {
    pendingCalls.add(tid);

    var handler = (ignoredThreads[tid] === undefined) ? fn : method;
    ${returnCapture}handler.call(${['self'].concat(callArgs).join(', ')});
  } catch (e) {
    env.popLocalFrame(NULL);

    if ('$h' in e) {
      env.throw(e.$h);
      ${returnNothing}
    } else {
      throw e;
    }
  } finally {
    pendingCalls.delete(tid);

    self.$dispose();
  }

  ${returnStatements.join('\n')}
};
`;

      return [methodName, type, retType, argTypes, rawRetType, rawArgTypes, code];
    })();

    const holder = method.holder;
    const C = holder.$C;
    const pendingCalls = method[PENDING_CALLS];

    const [methodName, type, retType, argTypes, rawRetType, rawArgTypes] = intermediates;

    let f;
    eval(intermediates[6]);

    intermediates = null;

    f.methodName = methodName;

    f.type = type;

    f.returnType = retType;

    f.argumentTypes = argTypes;

    f.canInvokeWith = args => {
      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => (t.isCompatible(args[i])));
    };

    return new NativeCallback(f, rawRetType, ['pointer', 'pointer'].concat(rawArgTypes));
  }

  function getTypeFromJniTypeName (typeName, unbox = true) {
    return getType(typeName, unbox, factory);
  }

  this._types = [{}, {}];

  this.openClassFile = function (filePath) {
    return new DexFile(filePath);
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

  function createTemporaryDex () {
    const JFile = factory.use('java.io.File');

    const cacheDirValue = JFile.$new(cacheDir);
    cacheDirValue.mkdirs();

    return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix, cacheDirValue);
  }

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
    const classWrapper = factory.use(className);

    const scope = VariableSizedHandleScope.$new(thread);

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, h.value);
      needle = scope.newHandle(object);
    } finally {
      h.unref(env);
    }

    const maxCount = 0;

    const instances = HandleVector.$new();

    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);

    const instanceHandles = instances.handles.map(handle => env.newGlobalRef(handle));

    instances.$delete();
    scope.$delete();

    try {
      for (let handle of instanceHandles) {
        const instance = factory.cast(handle, classWrapper);
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
      this.dispose();
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

    dispose () {
    }

    get link () {
      return new BaseHandleScope(this._link.readPointer());
    }
    set link (value) {
      this._link.writePointer(value);
    }

    get numberOfReferences () {
      return this._numberOfReferences.readS32();
    }
    set numberOfReferences (value) {
      this._numberOfReferences.writeS32(value);
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

      super.init(topHandleScopePtr.readPointer(), kNumReferencesVariableSized);

      this.self = thread;
      this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);

      topHandleScopePtr.writePointer(this);
    }

    dispose () {
      this._topHandleScopePtr.writePointer(this.link);

      let scope;
      while ((scope = this.currentScope) !== null) {
        const next = scope.link;
        scope.$delete();
        this.currentScope = next;
      }
    }

    get self () {
      return this._self.readPointer();
    }
    set self (value) {
      this._self.writePointer(value);
    }

    get currentScope () {
      const storage = this._currentScope.readPointer();
      if (storage.isNull()) {
        return null;
      }
      return new FixedSizeHandleScope(storage, this._scopeLayout);
    }
    set currentScope (value) {
      this._currentScope.writePointer(value);
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
      return this._pos.readU32();
    }
    set pos (value) {
      this._pos.writeU32(value);
    }

    newHandle (object) {
      const pos = this.pos;
      const handle = this._refsStorage.add(pos * 4);
      handle.writeS32(object.toInt32());
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

  function chooseObjectsArtLegacy (env, thread, className, callbacks) {
    const classWrapper = factory.use(className);

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

    const collectMatchingInstanceHandles = makeObjectVisitorPredicate(needle, object => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });

    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (let handle of instanceHandles) {
        const instance = factory.cast(handle, classWrapper);
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
          address.add(index * 2).writeU16(instruction);
        });
        address.add(needleOffset).writeS32(needle);
        address.add(onMatchOffset).writePointer(onMatchCallback);
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
          address.add(index * 4).writeU32(instruction);
        });
        address.add(needleOffset).writeS32(needle);
        address.add(onMatchOffset).writePointer(onMatchCallback);
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
      const klass = object.readS32();
      if (klass === needle) {
        onMatch(object);
      }
    }, 'void', ['pointer', 'pointer']);
  }

  function chooseObjectsDalvik (className, callbacks) {
    const classWrapper = factory.use(className);

    let enumerateInstances = function (className, callbacks) {
      const env = vm.getEnv();

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
        onMatch (address, size) {
          if (api.dvmIsValidObject(address)) {
            vm.perform(() => {
              const env = vm.getEnv();
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

  initialize.call(this);
}

ClassFactory._disposeAll = function (env) {
  factoryCache.factories.forEach(factory => {
    factory.dispose(env);
  });
};

ClassFactory.get = function (classLoader) {
  const cache = getFactoryCache();

  const defaultFactory = cache.factories[0];

  const indexObj = cache.loaders.get(classLoader);
  if (indexObj !== null) {
    const index = defaultFactory.cast(indexObj, cache.Integer);
    return cache.factories[index.intValue()];
  }

  const factory = new ClassFactory(cache.vm);
  factory.loader = classLoader;
  factory.cacheDir = defaultFactory.cacheDir;
  addFactoryToCache(factory, classLoader);

  return factory;
};

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
    case 'ready':
      return factoryCache;
  }
}

function addFactoryToCache (factory, loader) {
  const {factories, loaders, Integer} = factoryCache;

  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);

  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }

    loaders.put(l, index);
  }
}

function releaseClassHandle (handle, env) {
  handle.unref(env);
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

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function readTypeNames (env, types) {
  const names = [];

  const n = env.getArrayLength(types);
  if (n > 0) {
    env.pushLocalFrame(1 + n);

    for (let i = 0; i !== n; i++) {
      const t = env.getObjectArrayElement(types, i);
      names.push(env.getTypeName(t));
    }

    env.popLocalFrame(NULL);
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

function throwCannotReplaceNewError () {
  throw new Error('Reimplementing $new is not possible. Please replace implementation of $init instead.');
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

function alignPointerOffset (offset) {
  const remainder = offset % pointerSize;
  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }
  return offset;
}

module.exports = ClassFactory;

/* global Int64, Memory, NativeCallback, NativeFunction, NULL, Process, WeakRef */
