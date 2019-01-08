'use strict';

const getApi = require('./lib/api');
const {
  getAndroidVersion,
  withAllArtThreadsSuspended,
  withRunnableArtThread,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor
} = require('./lib/android');
const ClassFactory = require('./lib/class-factory');
const Env = require('./lib/env');
const VM = require('./lib/vm');
const {
  JNI_OK, // eslint-disable-line
  checkJniResult
} = require('./lib/result');

const pointerSize = Process.pointerSize;

function Runtime () {
  let initialized = false;
  let api = null;
  let apiError = null;
  let vm = null;
  let classFactory = null;
  let pending = [];
  let cachedIsAppProcess = null;

  function tryInitialize () {
    if (initialized) {
      return true;
    }

    if (apiError !== null) {
      throw apiError;
    }

    try {
      api = getApi();
    } catch (e) {
      apiError = e;
      throw e;
    }

    if (api === null) {
      return false;
    }

    vm = new VM(api);
    classFactory = new ClassFactory(vm);

    initialized = true;

    return true;
  }

  WeakRef.bind(Runtime, function dispose () {
    if (api !== null) {
      vm.perform(() => {
        const env = vm.getEnv();
        classFactory.dispose(env);
        Env.dispose(env);
      });
    }
  });

  Object.defineProperty(this, 'available', {
    enumerable: true,
    get: function () {
      return tryInitialize();
    }
  });

  Object.defineProperty(this, 'androidVersion', {
    enumerable: true,
    get: function () {
      return getAndroidVersion(classFactory);
    }
  });

  const assertJavaApiIsAvailable = () => {
    if (!this.available) {
      throw new Error('Java API not available');
    }
  };

  this.synchronized = function (obj, fn) {
    const objHandle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;
    if (!(objHandle instanceof NativePointer)) {
      throw new Error('Java.synchronized: the first argument `obj` must be either a pointer or a Java instance');
    }

    const env = vm.getEnv();
    checkJniResult('VM::MonitorEnter', env.monitorEnter(objHandle));
    try {
      fn();
    } finally {
      env.monitorExit(objHandle);
    }
  };

  Object.defineProperty(this, 'enumerateLoadedClasses', {
    enumerable: true,
    value: function (callbacks) {
      assertJavaApiIsAvailable();

      if (api.flavor === 'art') {
        enumerateLoadedClassesArt(callbacks);
      } else {
        enumerateLoadedClassesDalvik(callbacks);
      }
    }
  });

  Object.defineProperty(this, 'enumerateLoadedClassesSync', {
    enumerable: true,
    value: function () {
      assertJavaApiIsAvailable();

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
  });

  Object.defineProperty(this, 'enumerateClassLoaders', {
    enumerable: true,
    value: function (callbacks) {
      assertJavaApiIsAvailable();

      if (api.flavor === 'art') {
        enumerateClassLoadersArt(callbacks);
      } else {
        throw new Error('Enumerating class loaders is only supported on ART');
      }
    }
  });

  Object.defineProperty(this, 'enumerateClassLoadersSync', {
    enumerable: true,
    value: function () {
      assertJavaApiIsAvailable();

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
  });

  function enumerateLoadedClassesArt (callbacks) {
    const env = vm.getEnv();

    const classHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;
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
        callbacks.onMatch(className);
      });
    } finally {
      classHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  function enumerateClassLoadersArt (callbacks) {
    const visitClassLoaders = api['art::ClassLinker::VisitClassLoaders'];
    if (visitClassLoaders === undefined) {
      throw new Error('This API is only available on Nougat and above');
    }

    const env = vm.getEnv();

    const ClassLoader = classFactory.use('java.lang.ClassLoader');

    const loaderHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;
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
        const loader = classFactory.cast(handle, ClassLoader);
        callbacks.onMatch(loader);
      });
    } finally {
      loaderHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  function enumerateLoadedClassesDalvik (callbacks) {
    const HASH_TOMBSTONE = ptr('0xcbcacccd');
    const loadedClassesOffset = 172;
    const hashEntrySize = 8;
    const ptrLoadedClassesHashtable = api.gDvm.add(loadedClassesOffset);
    const hashTable = Memory.readPointer(ptrLoadedClassesHashtable);
    const tableSize = Memory.readS32(hashTable);
    const ptrpEntries = hashTable.add(12);
    const pEntries = Memory.readPointer(ptrpEntries);
    const end = tableSize * hashEntrySize;

    for (let offset = 0; offset < end; offset += hashEntrySize) {
      const pEntryPtr = pEntries.add(offset);
      const dataPtr = Memory.readPointer(pEntryPtr.add(4));
      if (!(HASH_TOMBSTONE.equals(dataPtr) || dataPtr.isNull())) {
        const descriptionPtr = Memory.readPointer(dataPtr.add(24));
        const description = Memory.readCString(descriptionPtr);
        callbacks.onMatch(description);
      }
    }
    callbacks.onComplete();
  }

  this.scheduleOnMainThread = function (fn) {
    const ActivityThread = classFactory.use('android.app.ActivityThread');
    const Handler = classFactory.use('android.os.Handler');
    const Looper = classFactory.use('android.os.Looper');

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
  };

  this.perform = function (fn) {
    assertJavaApiIsAvailable();

    if (!isAppProcess() || classFactory.loader !== null) {
      try {
        vm.perform(fn);
      } catch (e) {
        setTimeout(() => { throw e; }, 0);
      }
    } else {
      pending.push(fn);
      if (pending.length === 1) {
        vm.perform(() => {
          const ActivityThread = classFactory.use('android.app.ActivityThread');
          const app = ActivityThread.currentApplication();
          if (app !== null) {
            const Process = classFactory.use('android.os.Process');
            classFactory.loader = app.getClassLoader();

            if (Process.myUid() === Process.SYSTEM_UID.value) {
              classFactory.cacheDir = '/data/system';
            } else {
              classFactory.cacheDir = app.getCacheDir().getCanonicalPath();
            }
            performPending(); // already initialized, continue
          } else {
            let initialized = false;
            let hookpoint = 'early';

            const handleBindApplication = ActivityThread.handleBindApplication;
            handleBindApplication.implementation = function (data) {
              if (data.instrumentationName.value !== null) {
                hookpoint = 'late';

                const LoadedApk = classFactory.use('android.app.LoadedApk');
                const makeApplication = LoadedApk.makeApplication;
                makeApplication.implementation = function (forceDefaultAppClass, instrumentation) {
                  if (!initialized) {
                    initialized = true;
                    classFactory.loader = this.getClassLoader();
                    classFactory.cacheDir = classFactory.use('java.io.File').$new(this.getDataDir() + '/cache').getCanonicalPath();
                    performPending();
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
                classFactory.loader = apk.getClassLoader();
                classFactory.cacheDir = classFactory.use('java.io.File').$new(appInfo.dataDir.value + '/cache').getCanonicalPath();
                performPending();
              }
              return apk;
            };
          }
        });
      }
    }
  };

  function performPending () {
    while (pending.length > 0) {
      const fn = pending.shift();
      try {
        vm.perform(fn);
      } catch (e) {
        setTimeout(() => { throw e; }, 0);
      }
    }
  }

  this.performNow = function (fn) {
    assertJavaApiIsAvailable();

    if (isAppProcess() && classFactory.loader === null) {
      vm.perform(() => {
        const ActivityThread = classFactory.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          classFactory.loader = app.getClassLoader();
        }
      });
    }

    vm.perform(fn);
  };

  this.use = function (className) {
    return classFactory.use(className);
  };

  this.openClassFile = function (filePath) {
    return classFactory.openClassFile(filePath);
  };

  this.choose = function (specifier, callbacks) {
    classFactory.choose(specifier, callbacks);
  };

  this.cast = function (obj, C) {
    return classFactory.cast(obj, C);
  };

  this.array = function (type, elements) {
    return classFactory.array(type, elements);
  };

  // Reference: http://stackoverflow.com/questions/2848575/how-to-detect-ui-thread-on-android
  this.isMainThread = function () {
    const Looper = classFactory.use('android.os.Looper');
    const mainLooper = Looper.getMainLooper();
    const myLooper = Looper.myLooper();
    if (myLooper === null) {
      return false;
    }
    return mainLooper.$isSameObject(myLooper);
  };

  this.registerClass = function (spec) {
    return classFactory.registerClass(spec);
  };

  Object.defineProperty(this, 'vm', {
    enumerable: false,
    get: function () {
      return vm;
    }
  });

  Object.defineProperty(this, 'classFactory', {
    enumerable: false,
    get: function () {
      return classFactory;
    }
  });

  function isAppProcess () {
    if (cachedIsAppProcess === null) {
      const readlink = new NativeFunction(Module.findExportByName(null, 'readlink'), 'pointer', ['pointer', 'pointer', 'pointer'], {
        exceptions: 'propagate'
      });
      const pathname = Memory.allocUtf8String('/proc/self/exe');
      const bufferSize = 1024;
      const buffer = Memory.alloc(bufferSize);
      const size = readlink(pathname, buffer, ptr(bufferSize)).toInt32();
      if (size !== -1) {
        const exe = Memory.readUtf8String(buffer, size);
        cachedIsAppProcess = [/^\/system\/bin\/app_process/.test(exe)];
      } else {
        cachedIsAppProcess = [true];
      }
    }

    return cachedIsAppProcess[0];
  }

  tryInitialize();
}

module.exports = new Runtime();

/* global console, Memory, Module, NativePointer, NativeFunction, ptr, Process, WeakRef */
