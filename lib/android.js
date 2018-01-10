'use strict';

const {checkJniResult} = require('./result');
const VM = require('./vm');

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;

const STD_STRING_SIZE = (pointerSize === 4) ? 12 : 24;

const getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
const getArtClassLinkerSpec = memoize(_getArtClassLinkerSpec);
const getArtMethodSpec = memoize(_getArtMethodSpec);
const getArtThreadSpec = memoize(_getArtThreadSpec);
const getAndroidVersion = memoize(_getAndroidVersion);
const getAndroidApiLevel = memoize(_getAndroidApiLevel);

let cachedApi = null;

function getApi () {
  if (cachedApi !== null) {
    return cachedApi;
  }

  const vmModules = Process.enumerateModulesSync()
    .filter(m => /^lib(art|dvm).so$/.test(m.name))
    .filter(m => !/\/system\/fake-libs/.test(m.path));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];

  const flavor = (vmModule.name.indexOf('art') !== -1) ? 'art' : 'dalvik';
  const isArt = flavor === 'art';

  const temporaryApi = {
    addLocalReference: null,
    flavor: flavor
  };

  const pending = isArt ? [{
    module: vmModule.path,
    functions: {
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

      // Android < 7
      'artInterpreterToCompiledCodeBridge': function (address) {
        this.artInterpreterToCompiledCodeBridge = address;
      },

      // Android >= 8
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE': ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android >= 6
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE': ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
      '_ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE': ['art::ReaderWriterMutex::ExclusiveLock', 'void', ['pointer', 'pointer']],
      '_ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE': ['art::ReaderWriterMutex::ExclusiveUnlock', 'void', ['pointer', 'pointer']],

      // Android <= 7
      '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE' : function (address) {
        this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer']);
      },
      // Android > 7
      '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE' : function (address) {
        this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer']);
      },

      // Android >= 7
      '_ZN3art9JavaVMExt12DecodeGlobalEPv': function (address) {
        const decodeGlobal = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
        this['art::JavaVMExt::DecodeGlobal'] = function (vm, thread, ref) {
          return decodeGlobal(vm, ref);
        };
      },
      // Android >= 6
      '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv': ['art::JavaVMExt::DecodeGlobal', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android < 6: makeDecodeGlobalFallbackForAndroid5() fallback uses:
      '_ZNK3art6Thread13DecodeJObjectEP8_jobject': ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],

      // Android >= 6
      '_ZN3art10ThreadList10SuspendAllEPKcb': ['art::ThreadList::SuspendAll', 'void', ['pointer', 'pointer', 'bool']],
      // or fallback:
      '_ZN3art10ThreadList10SuspendAllEv': function (address) {
        const suspendAll = new NativeFunction(address, 'void', ['pointer']);
        this['art::ThreadList::SuspendAll'] = function (threadList, cause, longSuspend) {
          return suspendAll(threadList);
        };
      },

      '_ZN3art10ThreadList9ResumeAllEv': ['art::ThreadList::ResumeAll', 'void', ['pointer']],

      // Android >= 7
      '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE': ['art::ClassLinker::VisitClasses', 'void', ['pointer', 'pointer']],
      // Android < 7
      '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_': function (address) {
        const visitClasses = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer']);
        this['art::ClassLinker::VisitClasses'] = function (classLinker, visitor) {
          visitClasses(classLinker, visitor, NULL);
        };
      },

      '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE': ['art::ClassLinker::VisitClassLoaders', 'void', ['pointer', 'pointer']],

      '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_': ['art::gc::Heap::VisitObjects', 'void', ['pointer', 'pointer', 'pointer']],
      '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE': ['art::gc::Heap::GetInstances', 'void', ['pointer', 'pointer', 'pointer', 'int', 'pointer']],

      // Android < 6 for cloneArtMethod()
      '_ZN3art6Thread14CurrentFromGdbEv': ['art::Thread::CurrentFromGdb', 'pointer', []],
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadE': function (address) {
        this['art::mirror::Object::Clone'] = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
      },
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm': function (address) {
        const nativeFn = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer']);
        this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
          const numTargetBytes = NULL;
          return nativeFn(thisPtr, threadPtr, numTargetBytes);
        };
      },
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj': function (address) {
        const nativeFn = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'uint']);
        this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
          const numTargetBytes = 0;
          return nativeFn(thisPtr, threadPtr, numTargetBytes);
        };
      }
    },
    optionals: [
      'artInterpreterToCompiledCodeBridge',
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE',
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE',
      '_ZN3art9JavaVMExt12DecodeGlobalEPv',
      '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv',
      '_ZN3art10ThreadList10SuspendAllEPKcb',
      '_ZN3art10ThreadList10SuspendAllEv',
      '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE',
      '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_',
      '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE',
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadE',
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm',
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj',
      '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE',
      '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE',
      '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_',
      '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE'
    ]
  }] : [{
    module: vmModule.path,
    functions: {
      /*
       * Converts an indirect reference to to an object reference.
       */
      '_Z20dvmDecodeIndirectRefP6ThreadP8_jobject': ['dvmDecodeIndirectRef', 'pointer', ['pointer', 'pointer']],

      '_Z15dvmUseJNIBridgeP6MethodPv': ['dvmUseJNIBridge', 'void', ['pointer', 'pointer']],

      /*
       * Returns the base of the HeapSource.
       */
      '_Z20dvmHeapSourceGetBasev': ['dvmHeapSourceGetBase', 'pointer', []],

      /*
       * Returns the limit of the HeapSource.
       */
      '_Z21dvmHeapSourceGetLimitv': ['dvmHeapSourceGetLimit', 'pointer', []],

      /*
       *  Returns true if the pointer points to a valid object.
       */
      '_Z16dvmIsValidObjectPK6Object': ['dvmIsValidObject', 'uint8', ['pointer']],
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']]
    },
    variables: {
      'gDvmJni': function (address) {
        this.gDvmJni = address;
      },
      'gDvm': function (address) {
        this.gDvm = address;
      }
    }
  }
  ];

  const missing = [];
  let total = 0;

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    total += Object.keys(functions).length + Object.keys(variables).length;

    const exportByName = Module
      .enumerateExportsSync(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});

    Object.keys(functions)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined && exp.type === 'function') {
          const signature = functions[name];
          if (typeof signature === 'function') {
            signature.call(temporaryApi, exp.address);
          } else {
            temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2]);
          }
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });

    Object.keys(variables)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined && exp.type === 'variable') {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
        } else {
          missing.push(name);
        }
      });
  });

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (Memory.readInt(vmCount) === 0) {
    return null;
  }
  temporaryApi.vm = Memory.readPointer(vms);

  cachedApi = temporaryApi;

  if (isArt) {
    const artRuntime = Memory.readPointer(temporaryApi.vm.add(pointerSize));
    temporaryApi.artRuntime = artRuntime;

    const runtimeSpec = getArtRuntimeSpec(temporaryApi);

    temporaryApi.artHeap = Memory.readPointer(artRuntime.add(runtimeSpec.offset.heap));
    temporaryApi.artThreadList = Memory.readPointer(artRuntime.add(runtimeSpec.offset.threadList));

    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */
    const classLinker = Memory.readPointer(artRuntime.add(runtimeSpec.offset.classLinker));
    temporaryApi.artClassLinker = classLinker;
    temporaryApi.artQuickGenericJniTrampoline = Memory.readPointer(classLinker.add(getArtClassLinkerSpec(temporaryApi).offset.quickGenericJniTrampoline));

    if (temporaryApi['art::JavaVMExt::AddGlobalRef'] === undefined) {
      temporaryApi['art::JavaVMExt::AddGlobalRef'] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }
    if (temporaryApi['art::JavaVMExt::DecodeGlobal'] === undefined) {
      temporaryApi['art::JavaVMExt::DecodeGlobal'] = makeDecodeGlobalFallbackForAndroid5(temporaryApi);
    }

    addArtThreadStateTransitionFunctions(temporaryApi);
  }

  return cachedApi;
}

function ensureClassInitialized (env, classRef) {
  const api = getApi();

  if (api.flavor !== 'art') {
    return;
  }

  env.getFieldId(classRef, 'x', 'Z');
  env.exceptionClear();
}

function getArtVMSpec (api) {
  return {
    offset: (pointerSize === 4) ? {
      globalsLock: 32,
      globals: 72
    } : {
      globalsLock: 64,
      globals: 112
    }
  };
}

function _getArtRuntimeSpec (api) {
  /*
   * class Runtime {
   * ...
   * gc::Heap* heap_;                <-- we need to find this
   * std::unique_ptr<ArenaPool> jit_arena_pool_;     <----- API level >= 24
   * std::unique_ptr<ArenaPool> arena_pool_;             __
   * std::unique_ptr<ArenaPool> low_4gb_arena_pool_; <--|__ API level >= 23
   * std::unique_ptr<LinearAlloc> linear_alloc_;         \_
   * size_t max_spins_before_thin_lock_inflation_;
   * MonitorList* monitor_list_;
   * MonitorPool* monitor_pool_;
   * ThreadList* thread_list_;        <--- and these
   * InternTable* intern_table_;      <--/
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * bool use_tombstoned_traces_;     <-------------------- API level >= 27
   * std::string stack_trace_file_;
   * JavaVMExt* java_vm_;             <-- so we find this then calculate our way backwards
   * ...
   * }
   */

  const vm = api.vm;
  const runtime = api.artRuntime;

  const startOffset = (pointerSize === 4) ? 200 : 384;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = Memory.readPointer(runtime.add(offset));
    if (value.equals(vm)) {
      let classLinkerOffset = offset - STD_STRING_SIZE - (2 * pointerSize);
      if (apiLevel >= 27) {
        classLinkerOffset -= pointerSize;
      }
      const internTableOffset = classLinkerOffset - pointerSize;
      const threadListOffset = internTableOffset - pointerSize;

      let heapOffset = threadListOffset - (4 * pointerSize);
      if (apiLevel >= 23) {
        heapOffset -= 3 * pointerSize;
      }
      if (apiLevel >= 24) {
        heapOffset -= pointerSize;
      }

      spec = {
        offset: {
          heap: heapOffset,
          threadList: threadListOffset,
          internTable: internTableOffset,
          classLinker: classLinkerOffset
        }
      };
      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine Runtime field offsets');
  }

  return spec;
}

function _getArtClassLinkerSpec (api) {
  /*
   * On Android 5.x:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* portable_resolution_trampoline_;
   * const void* quick_resolution_trampoline_;
   * const void* portable_imt_conflict_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   *
   * On Android 6.x and above:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* quick_resolution_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   */

  const runtime = api.artRuntime;
  const runtimeSpec = getArtRuntimeSpec(api);

  const classLinker = Memory.readPointer(runtime.add(runtimeSpec.offset.classLinker));
  const internTable = Memory.readPointer(runtime.add(runtimeSpec.offset.internTable));

  const startOffset = (pointerSize === 4) ? 100 : 200;
  const endOffset = startOffset + (100 * pointerSize);

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = Memory.readPointer(classLinker.add(offset));
    if (value.equals(internTable)) {
      const delta = (getAndroidApiLevel() >= 23) ? 3 : 5;

      spec = {
        offset: {
          quickGenericJniTrampoline: offset + (delta * pointerSize)
        }
      };

      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine ClassLinker field offsets');
  }

  return spec;
}

function _getArtMethodSpec (vm) {
  const api = getApi();
  let spec;

  vm.perform(() => {
    const env = vm.getEnv();
    const process = env.findClass('android/os/Process');
    const setArgV0 = env.getStaticMethodId(process, 'setArgV0', '(Ljava/lang/String;)V');

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const apiLevel = getAndroidApiLevel();

    const entrypointFieldSize = (apiLevel <= 21) ? 8 : pointerSize;

    const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;

    let jniCodeOffset = null;
    let accessFlagsOffset = null;
    let remaining = 2;
    for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      const field = setArgV0.add(offset);

      if (jniCodeOffset === null) {
        const address = Memory.readPointer(field);
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }

      if (accessFlagsOffset === null) {
        const flags = Memory.readU32(field);
        if (flags === expectedAccessFlags) {
          accessFlagsOffset = offset;
          remaining--;
        }
      }
    }

    if (remaining !== 0) {
      throw new Error('Unable to determine ArtMethod field offsets');
    }

    const quickCodeOffset = jniCodeOffset + entrypointFieldSize;

    const size = (apiLevel <= 21) ? (quickCodeOffset + 32) : (quickCodeOffset + pointerSize);

    spec = {
      size: size,
      offset: {
        jniCode: jniCodeOffset,
        quickCode: quickCodeOffset,
        accessFlags: accessFlagsOffset
      }
    };

    if ('artInterpreterToCompiledCodeBridge' in api) {
      spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
    }
  });

  return spec;
}

function _getArtThreadSpec (vm) {
  /*
   * mirror::Throwable* exception;                    <-- ...to this
   * uint8_t* stack_end;
   * ManagedStack managed_stack;
   * uintptr_t* suspend_trigger;
   * JNIEnvExt* jni_env;                              <-- We find this then calculate our way backwards/forwards
   * JNIEnvExt* tmp_jni_env;
   * Thread* self;
   * mirror::Object* opeer;
   * jobject jpeer;
   * uint8_t* stack_begin;
   * size_t stack_size;
   * union DepsOrStackTraceSample {
   *   DepsOrStackTraceSample() {
   *     verifier_deps = nullptr;
   *     stack_trace_sample = nullptr;
   *   }
   *   std::vector<ArtMethod*>* stack_trace_sample;
   *   verifier::VerifierDeps* verifier_deps;
   * } deps_or_stack_trace_sample;
   * Thread* wait_next;
   * mirror::Object* monitor_enter_object;
   * BaseHandleScope* top_handle_scope;               <-- ...and to this
   */

  const api = getApi();
  let spec;

  vm.perform(() => {
    const env = vm.getEnv();

    const threadHandle = getArtThreadFromEnv(env);
    const envHandle = env.handle;

    let exceptionOffset = null;
    let topHandleScopeOffset = null;

    for (let offset = 144; offset !== 256; offset += pointerSize) {
      const field = threadHandle.add(offset);

      const value = Memory.readPointer(field);
      if (value.equals(envHandle)) {
        exceptionOffset = offset - (6 * pointerSize);
        topHandleScopeOffset = offset + (10 * pointerSize);
        break;
      }
    }

    if (topHandleScopeOffset === null) {
      throw new Error('Unable to determine ArtThread field offsets');
    }

    spec = {
      offset: {
        exception: exceptionOffset,
        topHandleScope: topHandleScopeOffset
      }
    };
  });

  return spec;
}

function getArtThreadFromEnv (env) {
  return Memory.readPointer(env.handle.add(pointerSize));
}

function _getAndroidVersion () {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidApiLevel () {
  return parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

let systemPropertyGet = null;
const PROP_VALUE_MAX = 92;

function getAndroidSystemProperty (name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(Module.findExportByName('libc.so', '__system_property_get'), 'int', ['pointer', 'pointer']);
  }
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return Memory.readUtf8String(buf);
}

function withRunnableArtThread (env, fn) {
}

function withAllArtThreadsSuspended (fn) {
  const api = getApi();

  const threadList = api.artThreadList;
  const longSuspend = false;
  api['art::ThreadList::SuspendAll'](threadList, Memory.allocUtf8String('frida'), longSuspend ? 1 : 0);
  try {
    fn();
  } finally {
    api['art::ThreadList::ResumeAll'](threadList);
  }
}

class ArtClassVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    Memory.writePointer(visitor, vtable);

    const onVisit = new NativeCallback((self, klass) => {
      return visit(klass) === true ? 1 : 0;
    }, 'bool', ['pointer', 'pointer']);
    Memory.writePointer(vtable.add(2 * pointerSize), onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

function makeArtClassVisitor (visit) {
  const api = getApi();

  if (api['art::ClassLinker::VisitClasses'] instanceof NativeFunction) {
    return new ArtClassVisitor(visit);
  }

  return new NativeCallback(klass => {
    return visit(klass) === true ? 1 : 0;
  }, 'bool', ['pointer', 'pointer']);
}

class ArtClassLoaderVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    Memory.writePointer(visitor, vtable);

    const onVisit = new NativeCallback((self, klass) => {
      visit(klass);
    }, 'void', ['pointer', 'pointer']);
    Memory.writePointer(vtable.add(2 * pointerSize), onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

function makeArtClassLoaderVisitor (visit) {
  return new ArtClassLoaderVisitor(visit);
}

function cloneArtMethod (method) {
  const api = getApi();

  if (getAndroidApiLevel() < 23) {
    const thread = api['art::Thread::CurrentFromGdb']();
    return api['art::mirror::Object::Clone'](method, thread);
  }

  return Memory.dup(method, getArtMethodSpec(api.vm).size);
}

function makeAddGlobalRefFallbackForAndroid5 (api) {
  const offset = getArtVMSpec().offset;
  const lock = api.vm.add(offset.globalsLock);
  const table = api.vm.add(offset.globals);

  const add = api['art::IndirectReferenceTable::Add'];
  const acquire = api['art::ReaderWriterMutex::ExclusiveLock'];
  const release = api['art::ReaderWriterMutex::ExclusiveUnlock'];

  const IRT_FIRST_SEGMENT = 0;

  return function (vm, thread, obj) {
    acquire(lock, thread);
    try {
      return add(table, IRT_FIRST_SEGMENT, obj);
    } finally {
      release(lock, thread);
    }
  };
}

function makeDecodeGlobalFallbackForAndroid5 (api) {
  const decode = api['art::Thread::DecodeJObject'];

  return function (vm, thread, ref) {
    return decode(thread, ref);
  };
}

const threadStateTransitionRecompilers = {
  arm64: function (buffer, pc, exceptionClearImpl, exceptionOffset) {
    const pending = [exceptionClearImpl];
    const targets = new Set();

    const writer = new Arm64Writer(buffer, { pc });

    do {
      const block = pending.shift();

      console.log('BLOCK AT ' + block);

      const relocator = new Arm64Relocator(block, writer);

      let offset;
      while ((offset = relocator.readOne()) !== 0) {
        const insn = relocator.input;
        const {mnemonic} = insn;
        console.log('insn: ' + insn);

        const id = insn.address.toString();
        targets.add(id);
        console.log('adding id=' + id);
        writer.putLabel(id);

        let branchTarget = null;
        switch (mnemonic) {
          case 'cbz': {
            const ops = insn.operands;
            branchTarget = ptr(ops[1].value);
            writer.putCbzRegLabel(ops[0].value, branchTarget.toString());
            relocator.skipOne();
            break;
          }
          case 'b.eq':
          case 'b.ne':
            branchTarget = ptr(insn.operands[0].value);
            writer.putBCondLabel(mnemonic.substr(2), branchTarget.toString());
            relocator.skipOne();
            break;
          case 'b':
            branchTarget = ptr(insn.operands[0].value);
            writer.putBLabel(branchTarget.toString());
            relocator.skipOne();
            break;
          case 'str': {
            const ops = insn.operands;
            if (ops[0].value === 'xzr' && ops[1].value.disp === exceptionOffset) {
              console.log('PROBABLY FOUND IT: ops=' + JSON.stringify(ops));
            }
          }
          default:
            relocator.writeOne();
        }

        if (branchTarget !== null) {
          const targetId = branchTarget.toString();
          if (!targets.has(targetId)) {
            pending.push(branchTarget);
          }
        }
      }

      relocator.dispose();
    } while (pending.length > 0);

    writer.flush();
    console.log(`Generated ${writer.offset} bytes of machine code`);
    writer.dispose();

    const enter = function () {};
    const leave = function () {};

    return [enter, leave];
  }
};

function addArtThreadStateTransitionFunctions (api) {
  console.log('entering A');
  const vm = new VM(api);
  vm.perform(() => {
    const env = vm.getEnv();
    const envVtable = Memory.readPointer(env.handle);
    const exceptionClearImpl = Memory.readPointer(envVtable.add(17 * pointerSize));

    const recompile = threadStateTransitionRecompilers[Process.arch];
    if (recompile === undefined) {
      throw new Error('Not yet implemented for ' + Process.arch);
    }

    const exceptionOffset = getArtThreadSpec(vm).offset.exception;
    console.log('exceptionOffset=0x' + exceptionOffset.toString(16));

    const codeSize = Process.pageSize;
    const code = Memory.alloc(codeSize);
    Memory.patchCode(code, codeSize, buffer => {
      const [enter, leave] = recompile(buffer, code, exceptionClearImpl, exceptionOffset);
      api.enterRunnableState = enter;
      api.leaveRunnableState = leave;
    });

    api._runnableStateCode = code;
  });
}

function memoize (compute) {
  let value = null;
  let computed = false;

  return function (...args) {
    if (!computed) {
      value = compute(...args);
      computed = true;
    }

    return value;
  };
}

module.exports = {
  getApi,
  ensureClassInitialized,
  getAndroidVersion,
  getAndroidApiLevel,
  getArtMethodSpec,
  getArtThreadSpec,
  getArtThreadFromEnv,
  withRunnableArtThread,
  withAllArtThreadsSuspended,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor,
  cloneArtMethod
};

/* global Memory, Module, NativeCallback, NativeFunction, NULL, Process */
