import getApi from './lib/api.js';
import {
  getAndroidVersion,
  withAllArtThreadsSuspended,
  withRunnableArtThread,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor,
  backtrace,
  deoptimizeEverything,
  deoptimizeBootImage,
  deoptimizeMethod
} from './lib/android.js';
import ClassFactory from './lib/class-factory.js';
import ClassModel from './lib/class-model.js';
import Env from './lib/env.js';
import { initialize } from './lib/types.js';
import VM from './lib/vm.js';
import { checkJniResult } from './lib/result.js';

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

class Runtime {
  ACC_PUBLIC       = 0x0001;
  ACC_PRIVATE      = 0x0002;
  ACC_PROTECTED    = 0x0004;
  ACC_STATIC       = 0x0008;
  ACC_FINAL        = 0x0010;
  ACC_SYNCHRONIZED = 0x0020;
  ACC_BRIDGE       = 0x0040;
  ACC_VARARGS      = 0x0080;
  ACC_NATIVE       = 0x0100;
  ACC_ABSTRACT     = 0x0400;
  ACC_STRICT       = 0x0800;
  ACC_SYNTHETIC    = 0x1000;

  constructor () {
    this.classFactory = null;
    this.ClassFactory = ClassFactory;
    this.vm = null;
    this.api = null;

    this._initialized = false;
    this._apiError = null;
    this._wakeupHandler = null;
    this._pollListener = null;
    this._pendingMainOps = [];
    this._pendingVmOps = [];
    this._cachedIsAppProcess = null;

    try {
      this._tryInitialize();
    } catch (e) {
    }
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

    initialize(vm);
    ClassFactory._initialize(vm, api);
    this.classFactory = new ClassFactory();

    this._initialized = true;

    return true;
  }

  _dispose () {
    if (this.api === null) {
      return;
    }

    const { vm } = this;
    vm.perform(env => {
      ClassFactory._disposeAll(env);
      Env.dispose(env);
    });
    Script.nextTick(() => {
      VM.dispose(vm);
    });
  }

  get available () {
    return this._tryInitialize();
  }

  get androidVersion () {
    return getAndroidVersion();
  }

  synchronized (obj, fn) {
    const { $h: objHandle = obj } = obj;
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

    const { flavor } = this.api;
    if (flavor === 'jvm') {
      this._enumerateLoadedClassesJvm(callbacks);
    } else if (flavor === 'art') {
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

    const { flavor } = this.api;
    if (flavor === 'jvm') {
      this._enumerateClassLoadersJvm(callbacks);
    } else if (flavor === 'art') {
      this._enumerateClassLoadersArt(callbacks);
    } else {
      throw new Error('Enumerating class loaders is not supported on Dalvik');
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

  _enumerateLoadedClassesJvm (callbacks) {
    const { api, vm } = this;
    const { jvmti } = api;
    const env = vm.getEnv();

    const countPtr = Memory.alloc(jsizeSize);
    const classesPtr = Memory.alloc(pointerSize);
    jvmti.getLoadedClasses(countPtr, classesPtr);

    const count = countPtr.readS32();
    const classes = classesPtr.readPointer();
    const handles = [];
    for (let i = 0; i !== count; i++) {
      handles.push(classes.add(i * pointerSize).readPointer());
    }
    jvmti.deallocate(classes);

    try {
      for (const handle of handles) {
        const className = env.getClassName(handle);
        callbacks.onMatch(className, handle);
      }

      callbacks.onComplete();
    } finally {
      handles.forEach(handle => {
        env.deleteLocalRef(handle);
      });
    }
  }

  _enumerateClassLoadersJvm (callbacks) {
    this.choose('java.lang.ClassLoader', callbacks);
  }

  _enumerateLoadedClassesArt (callbacks) {
    const { vm, api } = this;
    const env = vm.getEnv();

    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const { vm: vmHandle } = api;
    withRunnableArtThread(vm, env, thread => {
      const collectClassHandles = makeArtClassVisitor(klass => {
        const handle = addGlobalReference(vmHandle, thread, klass);
        try {
          const className = env.getClassName(handle);
          callbacks.onMatch(className, handle);
        } finally {
          env.deleteGlobalRef(handle);
        }
        return true;
      });

      api['art::ClassLinker::VisitClasses'](api.artClassLinker.address, collectClassHandles);
    });

    callbacks.onComplete();
  }

  _enumerateClassLoadersArt (callbacks) {
    const { classFactory: factory, vm, api } = this;
    const env = vm.getEnv();

    const visitClassLoaders = api['art::ClassLinker::VisitClassLoaders'];
    if (visitClassLoaders === undefined) {
      throw new Error('This API is only available on Android >= 7.0');
    }

    const ClassLoader = factory.use('java.lang.ClassLoader');

    const loaderHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const { vm: vmHandle } = api;
    withRunnableArtThread(vm, env, thread => {
      const collectLoaderHandles = makeArtClassLoaderVisitor(loader => {
        loaderHandles.push(addGlobalReference(vmHandle, thread, loader));
        return true;
      });
      withAllArtThreadsSuspended(() => {
        visitClassLoaders(api.artClassLinker.address, collectLoaderHandles);
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
    const { api } = this;

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

      if (dataPtr.isNull() || dataPtr.equals(HASH_TOMBSTONE)) {
        continue;
      }

      const descriptionPtr = dataPtr.add(24).readPointer();
      const description = descriptionPtr.readUtf8String();
      if (description.startsWith('L')) {
        const name = description.substring(1, description.length - 1).replace(/\//g, '.');
        callbacks.onMatch(name);
      }
    }

    callbacks.onComplete();
  }

  enumerateMethods (query) {
    const { classFactory: factory } = this;
    const env = this.vm.getEnv();
    const ClassLoader = factory.use('java.lang.ClassLoader');

    return ClassModel.enumerateMethods(query, this.api, env)
      .map(group => {
        const handle = group.loader;
        group.loader = (handle !== null) ? factory.wrap(handle, ClassLoader, env) : null;
        return group;
      });
  }

  scheduleOnMainThread (fn) {
    this.performNow(() => {
      this._pendingMainOps.push(fn);

      let { _wakeupHandler: wakeupHandler } = this;
      if (wakeupHandler === null) {
        const { classFactory: factory } = this;
        const Handler = factory.use('android.os.Handler');
        const Looper = factory.use('android.os.Looper');

        wakeupHandler = Handler.$new(Looper.getMainLooper());
        this._wakeupHandler = wakeupHandler;
      }

      if (this._pollListener === null) {
        this._pollListener = Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('epoll_wait'), this._makePollHook());
        Interceptor.flush();
      }

      wakeupHandler.sendEmptyMessage(1);
    });
  }

  _makePollHook () {
    const mainThreadId = Process.id;
    const { _pendingMainOps: pending } = this;

    return function () {
      if (this.threadId !== mainThreadId) {
        return;
      }

      let fn;
      while ((fn = pending.shift()) !== undefined) {
        try {
          fn();
        } catch (e) {
          Script.nextTick(() => { throw e; });
        }
      }
    };
  }

  perform (fn) {
    this._checkAvailable();

    if (!this._isAppProcess() || this.classFactory.loader !== null) {
      try {
        this.vm.perform(fn);
      } catch (e) {
        Script.nextTick(() => { throw e; });
      }
    } else {
      this._pendingVmOps.push(fn);
      if (this._pendingVmOps.length === 1) {
        this._performPendingVmOpsWhenReady();
      }
    }
  }

  performNow (fn) {
    this._checkAvailable();

    return this.vm.perform(() => {
      const { classFactory: factory } = this;

      if (this._isAppProcess() && factory.loader === null) {
        const ActivityThread = factory.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          initFactoryFromApplication(factory, app);
        }
      }

      return fn();
    });
  }

  _performPendingVmOpsWhenReady () {
    this.vm.perform(() => {
      const { classFactory: factory } = this;

      const ActivityThread = factory.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        initFactoryFromApplication(factory, app);
        this._performPendingVmOps();
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
              runtime._performPendingVmOps();
            }

            return makeApplication.apply(this, arguments);
          };
        }

        handleBindApplication.apply(this, arguments);
      };

      const getPackageInfoCandidates = ActivityThread.getPackageInfo.overloads
        .map(m => [m.argumentTypes.length, m])
        .sort(([arityA,], [arityB,]) => arityB - arityA)
        .map(([_, method]) => method);
      const getPackageInfo = getPackageInfoCandidates[0];
      getPackageInfo.implementation = function (...args) {
        const apk = getPackageInfo.call(this, ...args);

        if (!initialized && hookpoint === 'early') {
          initialized = true;
          initFactoryFromLoadedApk(factory, apk);
          runtime._performPendingVmOps();
        }

        return apk;
      };
    });
  }

  _performPendingVmOps () {
    const { vm, _pendingVmOps: pending } = this;

    let fn;
    while ((fn = pending.shift()) !== undefined) {
      try {
        vm.perform(fn);
      } catch (e) {
        Script.nextTick(() => { throw e; });
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

  backtrace (options) {
    return backtrace(this.vm, options);
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
    const { vm } = this;
    return deoptimizeEverything(vm, vm.getEnv());
  }

  deoptimizeBootImage () {
    const { vm } = this;
    return deoptimizeBootImage(vm, vm.getEnv());
  }

  deoptimizeMethod (method) {
    const { vm } = this;
    return deoptimizeMethod(vm, vm.getEnv(), method);
  }

  _checkAvailable () {
    if (!this.available) {
      throw new Error('Java API not available');
    }
  }

  _isAppProcess () {
    let result = this._cachedIsAppProcess;
    if (result === null) {
      if (this.api.flavor === 'jvm') {
        result = false;
        this._cachedIsAppProcess = result;
        return result;
      }

      const readlink = new NativeFunction(Module.getGlobalExportByName('readlink'), 'pointer', ['pointer', 'pointer', 'pointer'], {
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
      factory.cacheDir = app.getFilesDir().getCanonicalPath();
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
Script.bindWeak(runtime, () => { runtime._dispose(); });

export default runtime;
