const getApi = require('./lib/api');
const {
  getAndroidVersion,
  withAllArtThreadsSuspended,
  withRunnableArtThread,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor,
  deoptimizeEverything
} = require('./lib/android');
const ClassFactory = require('./lib/class-factory');
const Env = require('./lib/env');
const VM = require('./lib/vm');
const {
  JNI_OK,
  checkJniResult
} = require('./lib/result');

const pointerSize = Process.pointerSize;

class Runtime {
  constructor () {
    this.classFactory = null;
    this.ClassFactory = ClassFactory;
    this.vm = null;
    this.api = null;

    this._initialized = false;
    this._apiError = null;
    this._pending = [];
    this._cachedIsAppProcess = null;

    this._tryInitialize();
  }

  _tryInitialize () {
    if (this._initialized) {
      return true;
    }

    if (this._apiError !== null) {
      throw this._apiError;
    }

    let api;
    try {
      api = getApi();
      this.api = api;
    } catch (e) {
      this._apiError = e;
      throw e;
    }
    if (api === null) {
      return false;
    }

    const vm = new VM(api);
    this.vm = vm;

    ClassFactory._initialize(vm, api);
    this.classFactory = new ClassFactory();

    this._initialized = true;

    return true;
  }

  _dispose () {
    if (this.api === null) {
      return;
    }

    const {vm} = this;
    vm.perform(() => {
      const env = vm.getEnv();
      ClassFactory._disposeAll(env);
      Env.dispose(env);
    });
  }

  get available () {
    return this._tryInitialize();
  }

  get androidVersion () {
    return getAndroidVersion();
  }

  synchronized (obj, fn) {
    let objHandle = obj.hasOwnProperty('$h') ? obj.$h : obj;
    if (!(objHandle instanceof NativePointer)) {
      throw new Error('Java.synchronized: the first argument `obj` must be either a pointer or a Java instance');
    }

    const env = this.vm.getEnv();
    checkJniResult('VM::MonitorEnter', env.monitorEnter(objHandle));
    try {
      fn();
    } finally {
      env.monitorExit(objHandle);
    }
  }

  enumerateLoadedClasses (callbacks) {
    this._checkAvailable();

    if (this.api.flavor === 'art') {
      this._enumerateLoadedClassesArt(callbacks);
    } else {
      this._enumerateLoadedClassesDalvik(callbacks);
    }
  }

  enumerateLoadedClassesSync () {
    const classes = [];
    this.enumerateLoadedClasses({
      onMatch (c) {
        classes.push(c);
      },
      onComplete () {
      }
    });
    return classes;
  }

  enumerateClassLoaders (callbacks) {
    this._checkAvailable();

    if (this.api.flavor === 'art') {
      this._enumerateClassLoadersArt(callbacks);
    } else {
      throw new Error('Enumerating class loaders is only supported on ART');
    }
  }

  enumerateClassLoadersSync () {
    const loaders = [];
    this.enumerateClassLoaders({
      onMatch (c) {
        loaders.push(c);
      },
      onComplete () {
      }
    });
    return loaders;
  }

  _enumerateLoadedClassesArt (callbacks) {
    const {vm, api} = this;
    const env = vm.getEnv();

    const classHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const {vm: vmHandle} = api;
    withRunnableArtThread(vm, env, thread => {
      const collectClassHandles = makeArtClassVisitor(klass => {
        classHandles.push(addGlobalReference(vmHandle, thread, klass));
        return true;
      });

      api['art::ClassLinker::VisitClasses'](api.artClassLinker, collectClassHandles);
    });

    try {
      classHandles.forEach(handle => {
        const className = env.getClassName(handle);
        callbacks.onMatch(className, handle);
      });
    } finally {
      classHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  _enumerateClassLoadersArt (callbacks) {
    const {classFactory: factory, vm, api} = this;
    const env = vm.getEnv();

    const visitClassLoaders = api['art::ClassLinker::VisitClassLoaders'];
    if (visitClassLoaders === undefined) {
      throw new Error('This API is only available on Nougat and above');
    }

    const ClassLoader = factory.use('java.lang.ClassLoader');

    const loaderHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const {vm: vmHandle} = api;
    withRunnableArtThread(vm, env, thread => {
      const collectLoaderHandles = makeArtClassLoaderVisitor(loader => {
        loaderHandles.push(addGlobalReference(vmHandle, thread, loader));
        return true;
      });
      withAllArtThreadsSuspended(() => {
        visitClassLoaders(api.artClassLinker, collectLoaderHandles);
      });
    });

    try {
      loaderHandles.forEach(handle => {
        const loader = factory.cast(handle, ClassLoader);
        callbacks.onMatch(loader);
      });
    } finally {
      loaderHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  _enumerateLoadedClassesDalvik (callbacks) {
    const {api} = this;

    const HASH_TOMBSTONE = ptr('0xcbcacccd');
    const loadedClassesOffset = 172;
    const hashEntrySize = 8;
    const ptrLoadedClassesHashtable = api.gDvm.add(loadedClassesOffset);
    const hashTable = ptrLoadedClassesHashtable.readPointer();
    const tableSize = hashTable.readS32();
    const ptrpEntries = hashTable.add(12);
    const pEntries = ptrpEntries.readPointer();
    const end = tableSize * hashEntrySize;

    for (let offset = 0; offset < end; offset += hashEntrySize) {
      const pEntryPtr = pEntries.add(offset);
      const dataPtr = pEntryPtr.add(4).readPointer();
      if (!(HASH_TOMBSTONE.equals(dataPtr) || dataPtr.isNull())) {
        const descriptionPtr = dataPtr.add(24).readPointer();
        const description = descriptionPtr.readCString();
        callbacks.onMatch(description);
      }
    }
    callbacks.onComplete();
  }

  scheduleOnMainThread (fn) {
    const {classFactory: factory} = this;
    const ActivityThread = factory.use('android.app.ActivityThread');
    const Handler = factory.use('android.os.Handler');
    const Looper = factory.use('android.os.Looper');

    const looper = Looper.getMainLooper();
    const handler = Handler.$new.overload('android.os.Looper').call(Handler, looper);
    const message = handler.obtainMessage();
    Handler.dispatchMessage.implementation = function (msg) {
      const sameHandler = this.$isSameObject(handler);
      if (sameHandler) {
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          Handler.dispatchMessage.implementation = null;
          fn();
        }
      } else {
        this.dispatchMessage(msg);
      }
    };
    message.sendToTarget();
  }

  perform (fn) {
    this._checkAvailable();

    if (!this._isAppProcess() || this.classFactory.loader !== null) {
      try {
        this.vm.perform(fn);
      } catch (e) {
        setImmediate(() => { throw e; });
      }
    } else {
      this._pending.push(fn);
      if (this._pending.length === 1) {
        this._performPendingWhenReady();
      }
    }
  }

  performNow (fn) {
    this._checkAvailable();

    return this.vm.perform(() => {
      const {classFactory: factory} = this;

      if (isAppProcess() && factory.loader === null) {
        const ActivityThread = factory.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          initFactoryFromApplication(factory, app);
        }
      }

      return fn();
    });
  }

  _performPendingWhenReady () {
    this.vm.perform(() => {
      const {classFactory: factory} = this;

      const ActivityThread = factory.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        initFactoryFromApplication(factory, app);
        this._performPending();
        return;
      }

      const runtime = this;
      let initialized = false;
      let hookpoint = 'early';

      const handleBindApplication = ActivityThread.handleBindApplication;
      handleBindApplication.implementation = function (data) {
        if (data.instrumentationName.value !== null) {
          hookpoint = 'late';

          const LoadedApk = factory.use('android.app.LoadedApk');
          const makeApplication = LoadedApk.makeApplication;
          makeApplication.implementation = function (forceDefaultAppClass, instrumentation) {
            if (!initialized) {
              initialized = true;
              initFactoryFromLoadedApk(factory, this);
              runtime._performPending();
            }

            return makeApplication.apply(this, arguments);
          };
        }

        handleBindApplication.apply(this, arguments);
      };

      const getPackageInfoNoCheck = ActivityThread.getPackageInfoNoCheck;
      getPackageInfoNoCheck.implementation = function (appInfo) {
        const apk = getPackageInfoNoCheck.apply(this, arguments);

        if (!initialized && hookpoint === 'early') {
          initialized = true;
          initFactoryFromLoadedApk(factory, apk);
          runtime._performPending();
        }

        return apk;
      };
    });
  }

  _performPending () {
    const {vm, _pending: pending} = this;

    while (pending.length > 0) {
      const fn = pending.shift();
      try {
        vm.perform(fn);
      } catch (e) {
        setTimeout(() => { throw e; }, 0);
      }
    }
  }

  use (className, options) {
    return this.classFactory.use(className, options);
  }

  openClassFile (filePath) {
    return this.classFactory.openClassFile(filePath);
  }

  choose (specifier, callbacks) {
    this.classFactory.choose(specifier, callbacks);
  }

  retain (obj) {
    return this.classFactory.retain(obj);
  }

  cast (obj, C) {
    return this.classFactory.cast(obj, C);
  }

  array (type, elements) {
    return this.classFactory.array(type, elements);
  }

  // Reference: http://stackoverflow.com/questions/2848575/how-to-detect-ui-thread-on-android
  isMainThread () {
    const Looper = this.classFactory.use('android.os.Looper');
    const mainLooper = Looper.getMainLooper();
    const myLooper = Looper.myLooper();
    if (myLooper === null) {
      return false;
    }
    return mainLooper.$isSameObject(myLooper);
  }

  registerClass (spec) {
    return this.classFactory.registerClass(spec);
  }

  deoptimizeEverything () {
    const {vm} = this;
    return deoptimizeEverything(vm, vm.getEnv());
  }

  _checkAvailable () {
    if (!this.available) {
      throw new Error('Java API not available');
    }
  }

  _isAppProcess () {
    let result = this._cachedIsAppProcess;
    if (result === null) {
      const readlink = new NativeFunction(Module.getExportByName(null, 'readlink'), 'pointer', ['pointer', 'pointer', 'pointer'], {
        exceptions: 'propagate'
      });

      const pathname = Memory.allocUtf8String('/proc/self/exe');
      const bufferSize = 1024;
      const buffer = Memory.alloc(bufferSize);

      const size = readlink(pathname, buffer, ptr(bufferSize)).toInt32();
      if (size !== -1) {
        const exe = buffer.readUtf8String(size);
        result = /^\/system\/bin\/app_process/.test(exe);
      } else {
        result = true;
      }

      this._cachedIsAppProcess = result;
    }

    return result;
  }
}

function initFactoryFromApplication (factory, app) {
  const Process = factory.use('android.os.Process');

  factory.loader = app.getClassLoader();

  if (Process.myUid() === Process.SYSTEM_UID.value) {
    factory.cacheDir = '/data/system';
    factory.codeCacheDir = '/data/dalvik-cache';
  } else {
    if ('getCodeCacheDir' in app) {
      factory.cacheDir = app.getCacheDir().getCanonicalPath();
      factory.codeCacheDir = app.getCodeCacheDir().getCanonicalPath();
    } else {
      factory.cacheDir = app.getDataDir().getCanonicalPath();
      factory.codeCacheDir = app.getCacheDir().getCanonicalPath();
    }
  }
}

function initFactoryFromLoadedApk (factory, apk) {
  const JFile = factory.use('java.io.File');

  factory.loader = apk.getClassLoader();

  const dataDir = JFile.$new(apk.getDataDir()).getCanonicalPath();
  factory.cacheDir = dataDir;
  factory.codeCacheDir = dataDir + '/cache';
}

const runtime = new Runtime();
WeakRef.bind(runtime, () => { runtime._dispose(); });

module.exports = runtime;
