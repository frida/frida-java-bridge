import makeCodeAllocator from './alloc.js';
import {
  jvmtiVersion,
  jvmtiCapabilities,
  EnvJvmti
} from './jvmti.js';
import { parseInstructionsAt } from './machine-code.js';
import memoize from './memoize.js';
import { checkJniResult, JNI_OK } from './result.js';
import VM from './vm.js';

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const {
  readU32,
  readPointer,
  writeU32,
  writePointer
} = NativePointer.prototype;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;
const kAccFastNative = 0x00080000;
const kAccCriticalNative = 0x00200000;
const kAccFastInterpreterToInterpreterInvoke = 0x40000000;
const kAccSkipAccessChecks = 0x00080000;
const kAccSingleImplementation = 0x08000000;
const kAccNterpEntryPointFastPathFlag = 0x00100000;
const kAccNterpInvokeFastPathFlag = 0x00200000;
const kAccPublicApi = 0x10000000;
const kAccXposedHookedMethod = 0x10000000;

const kPointer = 0x0;

const kFullDeoptimization = 3;
const kSelectiveDeoptimization = 5;

const THUMB_BIT_REMOVAL_MASK = ptr(1).not();

const X86_JMP_MAX_DISTANCE = 0x7fffbfff;
const ARM64_ADRP_MAX_DISTANCE = 0xfffff000;

const ENV_VTABLE_OFFSET_EXCEPTION_CLEAR = 17 * pointerSize;
const ENV_VTABLE_OFFSET_FATAL_ERROR = 18 * pointerSize;

export const DVM_JNI_ENV_OFFSET_SELF = 12;

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
const DALVIK_JNI_RETURN_SHIFT = 28;

const STD_STRING_SIZE = 3 * pointerSize;
const STD_VECTOR_SIZE = 3 * pointerSize;

const AF_UNIX = 1;
const SOCK_STREAM = 1;

const getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
const getArtInstrumentationSpec = memoize(_getArtInstrumentationSpec);
export const getArtMethodSpec = memoize(_getArtMethodSpec);
export const getArtThreadSpec = memoize(_getArtThreadSpec);
const getArtManagedStackSpec = memoize(_getArtManagedStackSpec);
const getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
export const getAndroidVersion = memoize(_getAndroidVersion);
const getAndroidCodename = memoize(_getAndroidCodename);
export const getAndroidApiLevel = memoize(_getAndroidApiLevel);
const getArtQuickFrameInfoGetterThunk = memoize(_getArtQuickFrameInfoGetterThunk);

const makeCxxMethodWrapperReturningPointerByValue =
    (Process.arch === 'ia32')
      ? makeCxxMethodWrapperReturningPointerByValueInFirstArg
      : makeCxxMethodWrapperReturningPointerByValueGeneric;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const artThreadStateTransitions = {};

let cachedApi = null;
let cachedArtClassLinkerSpec = null;
let MethodMangler = null;
let artController = null;
const inlineHooks = [];
const patchedClasses = new Map();
const artQuickInterceptors = [];
let thunkPage = null;
let thunkOffset = 0;
let taughtArtAboutReplacementMethods = false;
let taughtArtAboutMethodInstrumentation = false;
let backtraceModule = null;
const jdwpSessions = [];
let socketpair = null;

let trampolineAllocator = null;

export function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /^lib(art|dvm).so$/.test(m.name))
    .filter(m => !/\/system\/fake-libs/.test(m.path));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];

  const flavor = (vmModule.name.indexOf('art') !== -1) ? 'art' : 'dalvik';
  const isArt = flavor === 'art';

  const temporaryApi = {
    module: vmModule,
    find (name) {
      const { module } = this;
      let address = module.findExportByName(name);
      if (address === null) {
        address = module.findSymbolByName(name);
      }
      return address;
    },
    flavor,
    addLocalReference: null
  };

  temporaryApi.isApiLevel34OrApexEquivalent = isArt && (
    temporaryApi.find('_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv') !== null ||
    temporaryApi.find('_ZN3art6Thread15RunFlipFunctionEPS0_') !== null
  );

  const pending = isArt
    ? {
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

          // Android < 7
          artInterpreterToCompiledCodeBridge: function (address) {
            this.artInterpreterToCompiledCodeBridge = address;
          },

          // Android >= 8
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android >= 6
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
          _ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveLock', 'void', ['pointer', 'pointer']],
          _ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveUnlock', 'void', ['pointer', 'pointer']],

          // Android <= 7
          _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },
          // Android > 7
          _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },

          // Android >= 7
          _ZN3art9JavaVMExt12DecodeGlobalEPv: function (address) {
            let decodeGlobal;
            if (getAndroidApiLevel() >= 26) {
              // Returns ObjPtr<mirror::Object>
              decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ['pointer', 'pointer']);
            } else {
              // Returns mirror::Object *
              decodeGlobal = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
            }
            this['art::JavaVMExt::DecodeGlobal'] = function (vm, thread, ref) {
              return decodeGlobal(vm, ref);
            };
          },
          // Android >= 6
          _ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv: ['art::JavaVMExt::DecodeGlobal', 'pointer', ['pointer', 'pointer', 'pointer']],

          // makeDecodeGlobalFallback() uses:
          // Android >= 15
          _ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],
          // Android < 6
          _ZNK3art6Thread13DecodeJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],

          // Android >= 6
          _ZN3art10ThreadList10SuspendAllEPKcb: ['art::ThreadList::SuspendAll', 'void', ['pointer', 'pointer', 'bool']],
          // or fallback:
          _ZN3art10ThreadList10SuspendAllEv: function (address) {
            const suspendAll = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::ThreadList::SuspendAll'] = function (threadList, cause, longSuspend) {
              return suspendAll(threadList);
            };
          },

          _ZN3art10ThreadList9ResumeAllEv: ['art::ThreadList::ResumeAll', 'void', ['pointer']],

          // Android >= 7
          _ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE: ['art::ClassLinker::VisitClasses', 'void', ['pointer', 'pointer']],
          // Android < 7
          _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_: function (address) {
            const visitClasses = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::ClassLinker::VisitClasses'] = function (classLinker, visitor) {
              visitClasses(classLinker, visitor, NULL);
            };
          },

          _ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE: ['art::ClassLinker::VisitClassLoaders', 'void', ['pointer', 'pointer']],

          _ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_: ['art::gc::Heap::VisitObjects', 'void', ['pointer', 'pointer', 'pointer']],
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: ['art::gc::Heap::GetInstances', 'void', ['pointer', 'pointer', 'pointer', 'int', 'pointer']],

          // Android >= 9
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: function (address) {
            const getInstances = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer', 'bool', 'int', 'pointer'], nativeFunctionOptions);
            this['art::gc::Heap::GetInstances'] = function (instance, scope, hClass, maxCount, instances) {
              const useIsAssignableFrom = 0;
              getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
            };
          },

          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'bool']],
          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'size_t', 'bool']],
          _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb: ['art::StackVisitor::WalkStack', 'void', ['pointer', 'bool']],
          _ZNK3art12StackVisitor9GetMethodEv: ['art::StackVisitor::GetMethod', 'pointer', ['pointer']],
          _ZNK3art12StackVisitor16DescribeLocationEv: function (address) {
            this['art::StackVisitor::DescribeLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },
          _ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv: function (address) {
            this['art::StackVisitor::GetCurrentQuickFrameInfo'] = makeArtQuickFrameInfoGetter(address);
          },

          _ZN3art6Thread18GetLongJumpContextEv: ['art::Thread::GetLongJumpContext', 'pointer', ['pointer']],

          _ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE: function (address) {
            this['art::mirror::Class::GetDescriptor'] = address;
          },
          _ZN3art6mirror5Class11GetLocationEv: function (address) {
            this['art::mirror::Class::GetLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },

          _ZN3art9ArtMethod12PrettyMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethod'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },
          _ZN3art12PrettyMethodEPNS_9ArtMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethodNullSafe'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },

          // Android < 6 for cloneArtMethod()
          _ZN3art6Thread14CurrentFromGdbEv: ['art::Thread::CurrentFromGdb', 'pointer', []],
          _ZN3art6mirror6Object5CloneEPNS_6ThreadE: function (address) {
            this['art::mirror::Object::Clone'] = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEm: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = NULL;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEj: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'uint'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = 0;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },

          _ZN3art3Dbg14SetJdwpAllowedEb: ['art::Dbg::SetJdwpAllowed', 'void', ['bool']],
          _ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE: ['art::Dbg::ConfigureJdwp', 'void', ['pointer']],
          _ZN3art31InternalDebuggerControlCallback13StartDebuggerEv: ['art::InternalDebuggerControlCallback::StartDebugger', 'void', ['pointer']],
          _ZN3art3Dbg9StartJdwpEv: ['art::Dbg::StartJdwp', 'void', []],
          _ZN3art3Dbg8GoActiveEv: ['art::Dbg::GoActive', 'void', []],
          _ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE: ['art::Dbg::RequestDeoptimization', 'void', ['pointer']],
          _ZN3art3Dbg20ManageDeoptimizationEv: ['art::Dbg::ManageDeoptimization', 'void', []],

          _ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv: ['art::Instrumentation::EnableDeoptimization', 'void', ['pointer']],
          // Android >= 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc: ['art::Instrumentation::DeoptimizeEverything', 'void', ['pointer', 'pointer']],
          // Android < 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv: function (address) {
            const deoptimize = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::Instrumentation::DeoptimizeEverything'] = function (instrumentation, key) {
              deoptimize(instrumentation);
            };
          },
          _ZN3art7Runtime19DeoptimizeBootImageEv: ['art::Runtime::DeoptimizeBootImage', 'void', ['pointer']],
          _ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE: ['art::Instrumentation::Deoptimize', 'void', ['pointer', 'pointer']],

          // Android >= 11
          _ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID: ['art::jni::JniIdManager::DecodeMethodId', 'pointer', ['pointer', 'pointer']],
          _ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID: ['art::jni::JniIdManager::DecodeFieldId', 'pointer', ['pointer', 'pointer']],
          _ZN3art11interpreter18GetNterpEntryPointEv: ['art::interpreter::GetNterpEntryPoint', 'pointer', []],

          _ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi: ['art::Monitor::TranslateLocation', 'void', ['pointer', 'uint32', 'pointer', 'pointer']]
        },
        variables: {
          _ZN3art3Dbg9gRegistryE: function (address) {
            this.isJdwpStarted = () => !address.readPointer().isNull();
          },
          _ZN3art3Dbg15gDebuggerActiveE: function (address) {
            this.isDebuggerActive = () => !!address.readU8();
          }
        },
        optionals: new Set([
          'artInterpreterToCompiledCodeBridge',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE',
          '_ZN3art9JavaVMExt12DecodeGlobalEPv',
          '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv',
          '_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject',
          '_ZNK3art6Thread13DecodeJObjectEP8_jobject',
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
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb',
          '_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb',
          '_ZNK3art12StackVisitor9GetMethodEv',
          '_ZNK3art12StackVisitor16DescribeLocationEv',
          '_ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv',
          '_ZN3art6Thread18GetLongJumpContextEv',
          '_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE',
          '_ZN3art6mirror5Class11GetLocationEv',
          '_ZN3art9ArtMethod12PrettyMethodEb',
          '_ZN3art12PrettyMethodEPNS_9ArtMethodEb',
          '_ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE',
          '_ZN3art31InternalDebuggerControlCallback13StartDebuggerEv',
          '_ZN3art3Dbg15gDebuggerActiveE',
          '_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv',
          '_ZN3art7Runtime19DeoptimizeBootImageEv',
          '_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE',
          '_ZN3art3Dbg9StartJdwpEv',
          '_ZN3art3Dbg8GoActiveEv',
          '_ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE',
          '_ZN3art3Dbg20ManageDeoptimizationEv',
          '_ZN3art3Dbg9gRegistryE',
          '_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID',
          '_ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID',
          '_ZN3art11interpreter18GetNterpEntryPointEv',
          '_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi'
        ])
      }
    : {
        functions: {
          _Z20dvmDecodeIndirectRefP6ThreadP8_jobject: ['dvmDecodeIndirectRef', 'pointer', ['pointer', 'pointer']],
          _Z15dvmUseJNIBridgeP6MethodPv: ['dvmUseJNIBridge', 'void', ['pointer', 'pointer']],
          _Z20dvmHeapSourceGetBasev: ['dvmHeapSourceGetBase', 'pointer', []],
          _Z21dvmHeapSourceGetLimitv: ['dvmHeapSourceGetLimit', 'pointer', []],
          _Z16dvmIsValidObjectPK6Object: ['dvmIsValidObject', 'uint8', ['pointer']],
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']]
        },
        variables: {
          gDvmJni: function (address) {
            this.gDvmJni = address;
          },
          gDvm: function (address) {
            this.gDvm = address;
          }
        }
      };

  const {
    functions = {},
    variables = {},
    optionals = new Set()
  } = pending;

  const missing = [];

  for (const [name, signature] of Object.entries(functions)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      if (typeof signature === 'function') {
        signature.call(temporaryApi, address);
      } else {
        temporaryApi[signature[0]] = new NativeFunction(address, signature[1], signature[2], nativeFunctionOptions);
      }
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }

  for (const [name, handler] of Object.entries(variables)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      handler.call(temporaryApi, address);
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();

  if (isArt) {
    const apiLevel = getAndroidApiLevel();

    let kAccCompileDontBother;
    if (apiLevel >= 27) {
      kAccCompileDontBother = 0x02000000;
    } else if (apiLevel >= 24) {
      kAccCompileDontBother = 0x01000000;
    } else {
      kAccCompileDontBother = 0;
    }
    temporaryApi.kAccCompileDontBother = kAccCompileDontBother;

    const artRuntime = temporaryApi.vm.add(pointerSize).readPointer();
    temporaryApi.artRuntime = artRuntime;
    const runtimeSpec = getArtRuntimeSpec(temporaryApi);
    const runtimeOffset = runtimeSpec.offset;
    const instrumentationOffset = runtimeOffset.instrumentation;
    temporaryApi.artInstrumentation = (instrumentationOffset !== null) ? artRuntime.add(instrumentationOffset) : null;

    temporaryApi.artHeap = artRuntime.add(runtimeOffset.heap).readPointer();
    temporaryApi.artThreadList = artRuntime.add(runtimeOffset.threadList).readPointer();

    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */
    const classLinker = artRuntime.add(runtimeOffset.classLinker).readPointer();

    const classLinkerOffsets = getArtClassLinkerSpec(artRuntime, runtimeSpec).offset;
    const quickResolutionTrampoline = classLinker.add(classLinkerOffsets.quickResolutionTrampoline).readPointer();
    const quickImtConflictTrampoline = classLinker.add(classLinkerOffsets.quickImtConflictTrampoline).readPointer();
    const quickGenericJniTrampoline = classLinker.add(classLinkerOffsets.quickGenericJniTrampoline).readPointer();
    const quickToInterpreterBridgeTrampoline = classLinker.add(classLinkerOffsets.quickToInterpreterBridgeTrampoline).readPointer();

    temporaryApi.artClassLinker = {
      address: classLinker,
      quickResolutionTrampoline,
      quickImtConflictTrampoline,
      quickGenericJniTrampoline,
      quickToInterpreterBridgeTrampoline
    };

    const vm = new VM(temporaryApi);

    temporaryApi.artQuickGenericJniTrampoline = getArtQuickEntrypointFromTrampoline(quickGenericJniTrampoline, vm);
    temporaryApi.artQuickToInterpreterBridge = getArtQuickEntrypointFromTrampoline(quickToInterpreterBridgeTrampoline, vm);
    temporaryApi.artQuickResolutionTrampoline = getArtQuickEntrypointFromTrampoline(quickResolutionTrampoline, vm);

    if (temporaryApi['art::JavaVMExt::AddGlobalRef'] === undefined) {
      temporaryApi['art::JavaVMExt::AddGlobalRef'] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }
    if (temporaryApi['art::JavaVMExt::DecodeGlobal'] === undefined) {
      temporaryApi['art::JavaVMExt::DecodeGlobal'] = makeDecodeGlobalFallback(temporaryApi);
    }
    if (temporaryApi['art::ArtMethod::PrettyMethod'] === undefined) {
      temporaryApi['art::ArtMethod::PrettyMethod'] = temporaryApi['art::ArtMethod::PrettyMethodNullSafe'];
    }
    if (temporaryApi['art::interpreter::GetNterpEntryPoint'] !== undefined) {
      temporaryApi.artNterpEntryPoint = temporaryApi['art::interpreter::GetNterpEntryPoint']();
    } else {
      temporaryApi.artNterpEntryPoint = temporaryApi.find('ExecuteNterpImpl');
    }

    artController = makeArtController(temporaryApi, vm);

    fixupArtQuickDeliverExceptionBug(temporaryApi);

    let cachedJvmti = null;
    Object.defineProperty(temporaryApi, 'jvmti', {
      get () {
        if (cachedJvmti === null) {
          cachedJvmti = [tryGetEnvJvmti(vm, this.artRuntime)];
        }
        return cachedJvmti[0];
      }
    });
  }

  const cxxImports = vmModule.enumerateImports()
    .filter(imp => imp.name.indexOf('_Z') === 0)
    .reduce((result, imp) => {
      result[imp.name] = imp.address;
      return result;
    }, {});
  temporaryApi.$new = new NativeFunction(cxxImports._Znwm || cxxImports._Znwj, 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi.$delete = new NativeFunction(cxxImports._ZdlPv, 'void', ['pointer'], nativeFunctionOptions);

  MethodMangler = isArt ? ArtMethodMangler : DalvikMethodMangler;

  return temporaryApi;
}

function tryGetEnvJvmti (vm, runtime) {
  let env = null;

  vm.perform(() => {
    const ensurePluginLoadedAddr = getApi().find('_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE');
    if (ensurePluginLoadedAddr === null) {
      return;
    }
    const ensurePluginLoaded = new NativeFunction(ensurePluginLoadedAddr,
      'bool',
      ['pointer', 'pointer', 'pointer']);
    const errorPtr = Memory.alloc(pointerSize);
    const success = ensurePluginLoaded(runtime, Memory.allocUtf8String('libopenjdkjvmti.so'), errorPtr);
    if (!success) {
      // FIXME: Avoid leaking error
      return;
    }

    const kArtTiVersion = jvmtiVersion.v1_2 | 0x40000000;
    const handle = vm.tryGetEnvHandle(kArtTiVersion);
    if (handle === null) {
      return;
    }
    env = new EnvJvmti(handle, vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    if (result !== JNI_OK) {
      env = null;
    }
  });

  return env;
}

export function ensureClassInitialized (env, classRef) {
  const api = getApi();
  if (api.flavor !== 'art') {
    return;
  }

  env.getFieldId(classRef, 'x', 'Z');
  env.exceptionClear();
}

function getArtVMSpec (api) {
  return {
    offset: (pointerSize === 4)
      ? {
          globalsLock: 32,
          globals: 72
        }
      : {
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
   * std::unique_ptr<ArenaPool> low_4gb_arena_pool_/linear_alloc_arena_pool_; <--|__ API level >= 23
   * std::unique_ptr<LinearAlloc> linear_alloc_;         \_
   * std::atomic<LinearAlloc*> startup_linear_alloc_;<----- API level >= 34
   * size_t max_spins_before_thin_lock_inflation_;
   * MonitorList* monitor_list_;
   * MonitorPool* monitor_pool_;
   * ThreadList* thread_list_;        <--- and these
   * InternTable* intern_table_;      <--/
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * SmallIrtAllocator* small_irt_allocator_; <------------ API level >= 33 or Android Tiramisu Developer Preview
   * std::unique_ptr<jni::JniIdManager> jni_id_manager_; <- API level >= 30 or Android R Developer Preview
   * bool use_tombstoned_traces_;     <-------------------- API level 27/28
   * std::string stack_trace_file_;   <-------------------- API level <= 28
   * JavaVMExt* java_vm_;             <-- so we find this then calculate our way backwards
   * ...
   * }
   */

  const vm = api.vm;
  const runtime = api.artRuntime;

  const startOffset = (pointerSize === 4) ? 200 : 384;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();
  const codename = getAndroidCodename();
  const { isApiLevel34OrApexEquivalent } = api;

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = runtime.add(offset).readPointer();
    if (value.equals(vm)) {
      let classLinkerOffsets;
      let jniIdManagerOffset = null;
      if (apiLevel >= 33 || codename === 'Tiramisu' || isApiLevel34OrApexEquivalent) {
        classLinkerOffsets = [offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 30 || codename === 'R') {
        classLinkerOffsets = [offset - (3 * pointerSize), offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 29) {
        classLinkerOffsets = [offset - (2 * pointerSize)];
      } else if (apiLevel >= 27) {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (3 * pointerSize)];
      } else {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (2 * pointerSize)];
      }

      for (const classLinkerOffset of classLinkerOffsets) {
        const internTableOffset = classLinkerOffset - pointerSize;
        const threadListOffset = internTableOffset - pointerSize;

        let heapOffset;
        if (isApiLevel34OrApexEquivalent) {
          heapOffset = threadListOffset - (9 * pointerSize);
        } else if (apiLevel >= 24) {
          heapOffset = threadListOffset - (8 * pointerSize);
        } else if (apiLevel >= 23) {
          heapOffset = threadListOffset - (7 * pointerSize);
        } else {
          heapOffset = threadListOffset - (4 * pointerSize);
        }

        const candidate = {
          offset: {
            heap: heapOffset,
            threadList: threadListOffset,
            internTable: internTableOffset,
            classLinker: classLinkerOffset,
            jniIdManager: jniIdManagerOffset
          }
        };
        if (tryGetArtClassLinkerSpec(runtime, candidate) !== null) {
          spec = candidate;
          break;
        }
      }

      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine Runtime field offsets');
  }

  spec.offset.instrumentation = tryDetectInstrumentationOffset(api);
  spec.offset.jniIdsIndirection = tryDetectJniIdsIndirectionOffset(api);

  return spec;
}

const instrumentationOffsetParsers = {
  ia32: parsex86InstrumentationOffset,
  x64: parsex86InstrumentationOffset,
  arm: parseArmInstrumentationOffset,
  arm64: parseArm64InstrumentationOffset
};

function tryDetectInstrumentationOffset (api) {
  const impl = api['art::Runtime::DeoptimizeBootImage'];
  if (impl === undefined) {
    return null;
  }

  return parseInstructionsAt(impl, instrumentationOffsetParsers[Process.arch], { limit: 30 });
}

function parsex86InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'lea') {
    return null;
  }

  const offset = insn.operands[1].value.disp;
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

function parseArmInstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add.w') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  return op2.value;
}

function parseArm64InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  if (ops[0].value === 'sp' || ops[1].value === 'sp') {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  const offset = op2.value.valueOf();
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

const jniIdsIndirectionOffsetParsers = {
  ia32: parsex86JniIdsIndirectionOffset,
  x64: parsex86JniIdsIndirectionOffset,
  arm: parseArmJniIdsIndirectionOffset,
  arm64: parseArm64JniIdsIndirectionOffset
};

function tryDetectJniIdsIndirectionOffset (api) {
  const impl = api.find('_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE');
  if (impl === null) {
    return null;
  }

  const offset = parseInstructionsAt(impl, jniIdsIndirectionOffsetParsers[Process.arch], { limit: 20 });
  if (offset === null) {
    throw new Error('Unable to determine Runtime.jni_ids_indirection_ offset');
  }

  return offset;
}

function parsex86JniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'cmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArmJniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArm64JniIdsIndirectionOffset (insn, prevInsn) {
  if (prevInsn === null) {
    return null;
  }

  const { mnemonic } = insn;
  const { mnemonic: prevMnemonic } = prevInsn;

  if ((mnemonic === 'cmp' && prevMnemonic === 'ldr') || (mnemonic === 'bl' && prevMnemonic === 'str')) {
    return prevInsn.operands[1].value.disp;
  }

  return null;
}

function _getArtInstrumentationSpec () {
  const deoptimizationEnabledOffsets = {
    '4-21': 136,
    '4-22': 136,
    '4-23': 172,
    '4-24': 196,
    '4-25': 196,
    '4-26': 196,
    '4-27': 196,
    '4-28': 212,
    '4-29': 172,
    '4-30': 180,
    '4-31': 180,
    '8-21': 224,
    '8-22': 224,
    '8-23': 296,
    '8-24': 344,
    '8-25': 344,
    '8-26': 352,
    '8-27': 352,
    '8-28': 392,
    '8-29': 328,
    '8-30': 336,
    '8-31': 336
  };

  const deoptEnabledOffset = deoptimizationEnabledOffsets[`${pointerSize}-${getAndroidApiLevel()}`];
  if (deoptEnabledOffset === undefined) {
    throw new Error('Unable to determine Instrumentation field offsets');
  }

  return {
    offset: {
      forcedInterpretOnly: 4,
      deoptimizationEnabled: deoptEnabledOffset
    }
  };
}

function getArtClassLinkerSpec (runtime, runtimeSpec) {
  const spec = tryGetArtClassLinkerSpec(runtime, runtimeSpec);
  if (spec === null) {
    throw new Error('Unable to determine ClassLinker field offsets');
  }
  return spec;
}

function tryGetArtClassLinkerSpec (runtime, runtimeSpec) {
  if (cachedArtClassLinkerSpec !== null) {
    return cachedArtClassLinkerSpec;
  }

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

  const { classLinker: classLinkerOffset, internTable: internTableOffset } = runtimeSpec.offset;
  const classLinker = runtime.add(classLinkerOffset).readPointer();
  const internTable = runtime.add(internTableOffset).readPointer();

  const startOffset = (pointerSize === 4) ? 100 : 200;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = classLinker.add(offset).readPointer();
    if (value.equals(internTable)) {
      let delta;
      if (apiLevel >= 30 || getAndroidCodename() === 'R') {
        delta = 6;
      } else if (apiLevel >= 29) {
        delta = 4;
      } else if (apiLevel >= 23) {
        delta = 3;
      } else {
        delta = 5;
      }

      const quickGenericJniTrampolineOffset = offset + (delta * pointerSize);

      let quickResolutionTrampolineOffset;
      if (apiLevel >= 23) {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (2 * pointerSize);
      } else {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (3 * pointerSize);
      }

      spec = {
        offset: {
          quickResolutionTrampoline: quickResolutionTrampolineOffset,
          quickImtConflictTrampoline: quickGenericJniTrampolineOffset - pointerSize,
          quickGenericJniTrampoline: quickGenericJniTrampolineOffset,
          quickToInterpreterBridgeTrampoline: quickGenericJniTrampolineOffset + pointerSize
        }
      };

      break;
    }
  }

  if (spec !== null) {
    cachedArtClassLinkerSpec = spec;
  }

  return spec;
}

export function getArtClassSpec (vm) {
  const MAX_OFFSET = 0x100;

  let spec = null;

  vm.perform(env => {
    const fieldSpec = getArtFieldSpec(vm);
    const methodSpec = getArtMethodSpec(vm);

    const fInfo = {
      artArrayLengthSize: 4,
      artArrayEntrySize: fieldSpec.size,
      // java/lang/Thread has 36 fields on Android 16.
      artArrayMax: 50
    };

    const mInfo = {
      artArrayLengthSize: pointerSize,
      artArrayEntrySize: methodSpec.size,
      // java/lang/Thread has 79 methods on Android 16.
      artArrayMax: 100
    };

    const readArtArray = (objectBase, fieldOffset, lengthSize) => {
      const header = objectBase.add(fieldOffset).readPointer();
      if (header.isNull()) {
        return null;
      }

      const length = (lengthSize === 4) ? header.readU32() : header.readU64().valueOf();
      if (length <= 0) {
        return null;
      }

      return {
        length,
        data: header.add(lengthSize)
      };
    };

    const hasEntry = (objectBase, offset, needle, info) => {
      try {
        const artArray = readArtArray(objectBase, offset, info.artArrayLengthSize);
        if (artArray === null) {
          return false;
        }

        const artArrayEnd = Math.min(artArray.length, info.artArrayMax);
        for (let i = 0; i !== artArrayEnd; i++) {
          const fieldPtr = artArray.data.add(i * info.artArrayEntrySize);
          if (fieldPtr.equals(needle)) {
            return true;
          }
        }
      } catch {
      }

      return false;
    };

    const clazz = env.findClass('java/lang/Thread');
    const clazzRef = env.newGlobalRef(clazz);

    try {
      let object;
      withRunnableArtThread(vm, env, thread => {
        object = getApi()['art::JavaVMExt::DecodeGlobal'](vm, thread, clazzRef);
      });

      const fieldInstance = unwrapFieldId(env.getFieldId(clazzRef, 'name', 'Ljava/lang/String;'));
      const fieldStatic = unwrapFieldId(env.getStaticFieldId(clazzRef, 'MAX_PRIORITY', 'I'));

      let offsetStatic = -1;
      let offsetInstance = -1;
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetStatic === -1 && hasEntry(object, offset, fieldStatic, fInfo)) {
          offsetStatic = offset;
        }
        if (offsetInstance === -1 && hasEntry(object, offset, fieldInstance, fInfo)) {
          offsetInstance = offset;
        }
      }
      if (offsetInstance === -1 || offsetStatic === -1) {
        throw new Error('Unable to find fields in java/lang/Thread; please file a bug');
      }
      const sfieldOffset = (offsetInstance !== offsetStatic) ? offsetStatic : 0;
      const ifieldOffset = offsetInstance;

      let offsetMethods = -1;
      const methodInstance = unwrapMethodId(env.getMethodId(clazzRef, 'getName', '()Ljava/lang/String;'));
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetMethods === -1 && hasEntry(object, offset, methodInstance, mInfo)) {
          offsetMethods = offset;
        }
      }
      if (offsetMethods === -1) {
        throw new Error('Unable to find methods in java/lang/Thread; please file a bug');
      }

      let offsetCopiedMethods = -1;
      const methodsArray = readArtArray(object, offsetMethods, mInfo.artArrayLengthSize);
      const methodsArraySize = methodsArray.length;
      for (let offset = offsetMethods; offset !== MAX_OFFSET; offset += 4) {
        if (object.add(offset).readU16() === methodsArraySize) {
          offsetCopiedMethods = offset;
          break;
        }
      }
      if (offsetCopiedMethods === -1) {
        throw new Error('Unable to find copied methods in java/lang/Thread; please file a bug');
      }

      spec = {
        offset: {
          ifields: ifieldOffset,
          methods: offsetMethods,
          sfields: sfieldOffset,
          copiedMethodsOffset: offsetCopiedMethods,
        }
      };
    } finally {
      env.deleteLocalRef(clazz);
      env.deleteGlobalRef(clazzRef);
    }
  });

  return spec;
}

function _getArtMethodSpec (vm) {
  const api = getApi();
  let spec;

  vm.perform(env => {
    const process = env.findClass('android/os/Process');
    const getElapsedCpuTime = unwrapMethodId(env.getStaticMethodId(process, 'getElapsedCpuTime', '()J'));
    env.deleteLocalRef(process);

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const apiLevel = getAndroidApiLevel();

    const entrypointFieldSize = (apiLevel <= 21) ? 8 : pointerSize;

    const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
    const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag) >>> 0;

    let jniCodeOffset = null;
    let accessFlagsOffset = null;
    let remaining = 2;
    for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      const field = getElapsedCpuTime.add(offset);

      if (jniCodeOffset === null) {
        const address = field.readPointer();
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }

      if (accessFlagsOffset === null) {
        const flags = field.readU32();
        if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
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
      size,
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

export function getArtFieldSpec (vm) {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      size: 16,
      offset: {
        accessFlags: 4
      }
    };
  }

  if (apiLevel >= 21) {
    return {
      size: 24,
      offset: {
        accessFlags: 12
      }
    };
  }

  return null;
}

function _getArtThreadSpec (vm) {
  /*
   * bool32_t is_exception_reported_to_instrumentation_; <-- We need this on API level <= 22
   * ...
   * mirror::Throwable* exception;                       <-- ...and this on all versions
   * uint8_t* stack_end;
   * ManagedStack managed_stack;
   * uintptr_t* suspend_trigger;
   * JNIEnvExt* jni_env;                                 <-- We find this then calculate our way backwards/forwards
   * JNIEnvExt* tmp_jni_env;                             <-- API level >= 23
   * Thread* self;
   * mirror::Object* opeer;
   * jobject jpeer;
   * uint8_t* stack_begin;
   * size_t stack_size;
   * ThrowLocation throw_location;                       <-- ...and this on API level <= 22
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
   * BaseHandleScope* top_handle_scope;                  <-- ...and to this on all versions
   */

  const apiLevel = getAndroidApiLevel();

  let spec;

  vm.perform(env => {
    const threadHandle = getArtThreadFromEnv(env);
    const envHandle = env.handle;

    let isExceptionReportedOffset = null;
    let exceptionOffset = null;
    let throwLocationOffset = null;
    let topHandleScopeOffset = null;
    let managedStackOffset = null;
    let selfOffset = null;

    for (let offset = 144; offset !== 256; offset += pointerSize) {
      const field = threadHandle.add(offset);

      const value = field.readPointer();
      if (value.equals(envHandle)) {
        exceptionOffset = offset - (6 * pointerSize);
        managedStackOffset = offset - (4 * pointerSize);
        selfOffset = offset + (2 * pointerSize);
        if (apiLevel <= 22) {
          exceptionOffset -= pointerSize;

          isExceptionReportedOffset = exceptionOffset - pointerSize - (9 * 8) - (3 * 4);

          throwLocationOffset = offset + (6 * pointerSize);

          managedStackOffset -= pointerSize;

          selfOffset -= pointerSize;
        }

        topHandleScopeOffset = offset + (9 * pointerSize);
        if (apiLevel <= 22) {
          topHandleScopeOffset += (2 * pointerSize) + 4;
          if (pointerSize === 8) {
            topHandleScopeOffset += 4;
          }
        }
        if (apiLevel >= 23) {
          topHandleScopeOffset += pointerSize;
        }

        break;
      }
    }

    if (topHandleScopeOffset === null) {
      throw new Error('Unable to determine ArtThread field offsets');
    }

    spec = {
      offset: {
        isExceptionReportedToInstrumentation: isExceptionReportedOffset,
        exception: exceptionOffset,
        throwLocation: throwLocationOffset,
        topHandleScope: topHandleScopeOffset,
        managedStack: managedStackOffset,
        self: selfOffset
      }
    };
  });

  return spec;
}

function _getArtManagedStackSpec () {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      offset: {
        topQuickFrame: 0,
        link: pointerSize
      }
    };
  } else {
    return {
      offset: {
        topQuickFrame: 2 * pointerSize,
        link: 0
      }
    };
  }
}

const artQuickTrampolineParsers = {
  ia32: parseArtQuickTrampolineX86,
  x64: parseArtQuickTrampolineX86,
  arm: parseArtQuickTrampolineArm,
  arm64: parseArtQuickTrampolineArm64
};

function getArtQuickEntrypointFromTrampoline (trampoline, vm) {
  let address;

  vm.perform(env => {
    const thread = getArtThreadFromEnv(env);

    const tryParse = artQuickTrampolineParsers[Process.arch];

    const insn = Instruction.parse(trampoline);

    const offset = tryParse(insn);
    if (offset !== null) {
      address = thread.add(offset).readPointer();
    } else {
      address = trampoline;
    }
  });

  return address;
}

function parseArtQuickTrampolineX86 (insn) {
  if (insn.mnemonic === 'jmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm64 (insn) {
  if (insn.mnemonic === 'ldr') {
    return insn.operands[1].value.disp;
  }

  return null;
}

export function getArtThreadFromEnv (env) {
  return env.handle.add(pointerSize).readPointer();
}

function _getAndroidVersion () {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidCodename () {
  return getAndroidSystemProperty('ro.build.version.codename');
}

function _getAndroidApiLevel () {
  return parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

let systemPropertyGet = null;
const PROP_VALUE_MAX = 92;

function getAndroidSystemProperty (name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(
      Process.getModuleByName('libc.so').getExportByName('__system_property_get'),
      'int',
      ['pointer', 'pointer'],
      nativeFunctionOptions);
  }
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return buf.readUtf8String();
}

export function withRunnableArtThread (vm, env, fn) {
  const perform = getArtThreadStateTransitionImpl(vm, env);

  const id = getArtThreadFromEnv(env).toString();
  artThreadStateTransitions[id] = fn;

  perform(env.handle);

  if (artThreadStateTransitions[id] !== undefined) {
    delete artThreadStateTransitions[id];
    throw new Error('Unable to perform state transition; please file a bug');
  }
}

function _getArtThreadStateTransitionImpl (vm, env) {
  const callback = new NativeCallback(onThreadStateTransitionComplete, 'void', ['pointer']);
  return makeArtThreadStateTransitionImpl(vm, env, callback);
}

function onThreadStateTransitionComplete (thread) {
  const id = thread.toString();

  const fn = artThreadStateTransitions[id];
  delete artThreadStateTransitions[id];
  fn(thread);
}

export function withAllArtThreadsSuspended (fn) {
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
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      return visit(klass) === true ? 1 : 0;
    }, 'bool', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

export function makeArtClassVisitor (visit) {
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
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      visit(klass);
    }, 'void', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

export function makeArtClassLoaderVisitor (visit) {
  return new ArtClassLoaderVisitor(visit);
}

const WalkKind = {
  'include-inlined-frames': 0,
  'skip-inlined-frames': 1
};

export class ArtStackVisitor {
  constructor (thread, context, walkKind, numFrames = 0, checkSuspended = true) {
    const api = getApi();

    const baseSize = 512; /* Up to 488 bytes on 64-bit Android Q. */
    const vtableSize = 3 * pointerSize;

    const visitor = Memory.alloc(baseSize + vtableSize);

    api['art::StackVisitor::StackVisitor'](visitor, thread, context, WalkKind[walkKind], numFrames,
      checkSuspended ? 1 : 0);

    const vtable = visitor.add(baseSize);
    visitor.writePointer(vtable);

    const onVisitFrame = new NativeCallback(this._visitFrame.bind(this), 'bool', ['pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisitFrame);

    this.handle = visitor;
    this._onVisitFrame = onVisitFrame;

    const curShadowFrame = visitor.add((pointerSize === 4) ? 12 : 24);
    this._curShadowFrame = curShadowFrame;
    this._curQuickFrame = curShadowFrame.add(pointerSize);
    this._curQuickFramePc = curShadowFrame.add(2 * pointerSize);
    this._curOatQuickMethodHeader = curShadowFrame.add(3 * pointerSize);

    this._getMethodImpl = api['art::StackVisitor::GetMethod'];
    this._descLocImpl = api['art::StackVisitor::DescribeLocation'];
    this._getCQFIImpl = api['art::StackVisitor::GetCurrentQuickFrameInfo'];
  }

  walkStack (includeTransitions = false) {
    getApi()['art::StackVisitor::WalkStack'](this.handle, includeTransitions ? 1 : 0);
  }

  _visitFrame () {
    return this.visitFrame() ? 1 : 0;
  }

  visitFrame () {
    throw new Error('Subclass must implement visitFrame');
  }

  getMethod () {
    const methodHandle = this._getMethodImpl(this.handle);
    if (methodHandle.isNull()) {
      return null;
    }
    return new ArtMethod(methodHandle);
  }

  getCurrentQuickFramePc () {
    return this._curQuickFramePc.readPointer();
  }

  getCurrentQuickFrame () {
    return this._curQuickFrame.readPointer();
  }

  getCurrentShadowFrame () {
    return this._curShadowFrame.readPointer();
  }

  describeLocation () {
    const result = new StdString();
    this._descLocImpl(result, this.handle);
    return result.disposeToString();
  }

  getCurrentOatQuickMethodHeader () {
    return this._curOatQuickMethodHeader.readPointer();
  }

  getCurrentQuickFrameInfo () {
    return this._getCQFIImpl(this.handle);
  }
}

export class ArtMethod {
  constructor (handle) {
    this.handle = handle;
  }

  prettyMethod (withSignature = true) {
    const result = new StdString();
    getApi()['art::ArtMethod::PrettyMethod'](result, this.handle, withSignature ? 1 : 0);
    return result.disposeToString();
  }

  toString () {
    return `ArtMethod(handle=${this.handle})`;
  }
}

function makeArtQuickFrameInfoGetter (impl) {
  return function (self) {
    const result = Memory.alloc(12);

    getArtQuickFrameInfoGetterThunk(impl)(result, self);

    return {
      frameSizeInBytes: result.readU32(),
      coreSpillMask: result.add(4).readU32(),
      fpSpillMask: result.add(8).readU32()
    };
  };
}

function _getArtQuickFrameInfoGetterThunk (impl) {
  let thunk = NULL;
  switch (Process.arch) {
    case 'ia32':
      thunk = makeThunk(32, writer => {
        writer.putMovRegRegOffsetPtr('ecx', 'esp', 4); // result
        writer.putMovRegRegOffsetPtr('edx', 'esp', 8); // self
        writer.putCallAddressWithArguments(impl, ['ecx', 'edx']);

        // Restore callee's stack frame
        writer.putMovRegReg('esp', 'ebp');
        writer.putPopReg('ebp');

        writer.putRet();
      });
      break;
    case 'x64':
      thunk = makeThunk(32, writer => {
        writer.putPushReg('rdi'); // preserve result buffer pointer
        writer.putCallAddressWithArguments(impl, ['rsi']); // self
        writer.putPopReg('rdi');

        // Struct is stored by value in the rax and edx registers
        // Write struct to result buffer
        writer.putMovRegPtrReg('rdi', 'rax');
        writer.putMovRegOffsetPtrReg('rdi', 8, 'edx');

        writer.putRet();
      });
      break;
    case 'arm':
      thunk = makeThunk(16, writer => {
        // By calling convention, we pass a pointer for the result struct
        writer.putCallAddressWithArguments(impl, ['r0', 'r1']);
        writer.putPopRegs(['r0', 'lr']);
        writer.putMovRegReg('pc', 'lr');
      });
      break;
    case 'arm64':
      thunk = makeThunk(64, writer => {
        writer.putPushRegReg('x0', 'lr');
        writer.putCallAddressWithArguments(impl, ['x1']);
        writer.putPopRegReg('x2', 'lr');
        writer.putStrRegRegOffset('x0', 'x2', 0);
        writer.putStrRegRegOffset('w1', 'x2', 8);
        writer.putRet();
      });
      break;
  }
  return new NativeFunction(thunk, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
}

const thunkRelocators = {
  ia32: globalThis.X86Relocator,
  x64: globalThis.X86Relocator,
  arm: globalThis.ThumbRelocator,
  arm64: globalThis.Arm64Relocator
};

const thunkWriters = {
  ia32: globalThis.X86Writer,
  x64: globalThis.X86Writer,
  arm: globalThis.ThumbWriter,
  arm64: globalThis.Arm64Writer
};

function makeThunk (size, write) {
  if (thunkPage === null) {
    thunkPage = Memory.alloc(Process.pageSize);
  }

  const thunk = thunkPage.add(thunkOffset);

  const arch = Process.arch;

  const Writer = thunkWriters[arch];
  Memory.patchCode(thunk, size, code => {
    const writer = new Writer(code, { pc: thunk });
    write(writer);
    writer.flush();
    if (writer.offset > size) {
      throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
    }
  });

  thunkOffset += size;

  return (arch === 'arm') ? thunk.or(1) : thunk;
}

function notifyArtMethodHooked (method, vm) {
  ensureArtKnowsHowToHandleMethodInstrumentation(vm);
  ensureArtKnowsHowToHandleReplacementMethods(vm);
}

function makeArtController (api, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const managedStackOffsets = getArtManagedStackSpec().offset;

  const code = `
#include <gum/guminterceptor.h>

extern GMutex lock;
extern GHashTable * methods;
extern GHashTable * replacements;
extern gpointer last_seen_art_method;

extern gpointer get_oat_quick_method_header_impl (gpointer method, gpointer pc);

void
init (void)
{
  g_mutex_init (&lock);
  methods = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  replacements = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

void
finalize (void)
{
  g_hash_table_unref (replacements);
  g_hash_table_unref (methods);
  g_mutex_clear (&lock);
}

gboolean
is_replacement_method (gpointer method)
{
  gboolean is_replacement;

  g_mutex_lock (&lock);

  is_replacement = g_hash_table_contains (replacements, method);

  g_mutex_unlock (&lock);

  return is_replacement;
}

gpointer
get_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);

  g_mutex_unlock (&lock);

  return replacement_method;
}

void
set_replacement_method (gpointer original_method,
                        gpointer replacement_method)
{
  g_mutex_lock (&lock);

  g_hash_table_insert (methods, original_method, replacement_method);
  g_hash_table_insert (replacements, replacement_method, original_method);

  g_mutex_unlock (&lock);
}

void
delete_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);
  if (replacement_method != NULL)
  {
    g_hash_table_remove (methods, original_method);
    g_hash_table_remove (replacements, replacement_method);
  }

  g_mutex_unlock (&lock);
}

gpointer
translate_method (gpointer method)
{
  gpointer translated_method;

  g_mutex_lock (&lock);

  translated_method = g_hash_table_lookup (replacements, method);

  g_mutex_unlock (&lock);

  return (translated_method != NULL) ? translated_method : method;
}

gpointer
find_replacement_method_from_quick_code (gpointer method,
                                         gpointer thread)
{
  gpointer replacement_method;
  gpointer managed_stack;
  gpointer top_quick_frame;
  gpointer link_managed_stack;
  gpointer * link_top_quick_frame;

  replacement_method = get_replacement_method (method);
  if (replacement_method == NULL)
    return NULL;

  /*
   * Stack check.
   *
   * Return NULL to indicate that the original method should be invoked, otherwise
   * return a pointer to the replacement ArtMethod.
   *
   * If the caller is our own JNI replacement stub, then a stack transition must
   * have been pushed onto the current thread's linked list.
   *
   * Therefore, we invoke the original method if the following conditions are met:
   *   1- The current managed stack is empty.
   *   2- The ArtMethod * inside the linked managed stack's top quick frame is the
   *      same as our replacement.
   */
  managed_stack = thread + ${threadOffsets.managedStack};
  top_quick_frame = *((gpointer *) (managed_stack + ${managedStackOffsets.topQuickFrame}));
  if (top_quick_frame != NULL)
    return replacement_method;

  link_managed_stack = *((gpointer *) (managed_stack + ${managedStackOffsets.link}));
  if (link_managed_stack == NULL)
    return replacement_method;

  link_top_quick_frame = GSIZE_TO_POINTER (*((gsize *) (link_managed_stack + ${managedStackOffsets.topQuickFrame})) & ~((gsize) 1));
  if (link_top_quick_frame == NULL || *link_top_quick_frame != replacement_method)
    return replacement_method;

  return NULL;
}

void
on_interpreter_do_call (GumInvocationContext * ic)
{
  gpointer method, replacement_method;

  method = gum_invocation_context_get_nth_argument (ic, 0);

  replacement_method = get_replacement_method (method);
  if (replacement_method != NULL)
    gum_invocation_context_replace_nth_argument (ic, 0, replacement_method);
}

gpointer
on_art_method_get_oat_quick_method_header (gpointer method,
                                           gpointer pc)
{
  if (is_replacement_method (method))
    return NULL;

  return get_oat_quick_method_header_impl (method, pc);
}

void
on_art_method_pretty_method (GumInvocationContext * ic)
{
  const guint this_arg_index = ${(Process.arch === 'arm64') ? 0 : 1};
  gpointer method;

  method = gum_invocation_context_get_nth_argument (ic, this_arg_index);
  if (method == NULL)
    gum_invocation_context_replace_nth_argument (ic, this_arg_index, last_seen_art_method);
  else
    last_seen_art_method = method;
}

void
on_leave_gc_concurrent_copying_copying_phase (GumInvocationContext * ic)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

  g_mutex_unlock (&lock);
}
`;

  const lockSize = 8;
  const methodsSize = pointerSize;
  const replacementsSize = pointerSize;
  const lastSeenArtMethodSize = pointerSize;

  const data = Memory.alloc(lockSize + methodsSize + replacementsSize + lastSeenArtMethodSize);

  const lock = data;
  const methods = lock.add(lockSize);
  const replacements = methods.add(methodsSize);
  const lastSeenArtMethod = replacements.add(replacementsSize);

  const getOatQuickMethodHeaderImpl = api.find((pointerSize === 4)
    ? '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj'
    : '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm');

  const cm = new CModule(code, {
    lock,
    methods,
    replacements,
    last_seen_art_method: lastSeenArtMethod,
    get_oat_quick_method_header_impl: getOatQuickMethodHeaderImpl ?? ptr('0xdeadbeef')
  });

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    replacedMethods: {
      isReplacement: new NativeFunction(cm.is_replacement_method, 'bool', ['pointer'], fastOptions),
      get: new NativeFunction(cm.get_replacement_method, 'pointer', ['pointer'], fastOptions),
      set: new NativeFunction(cm.set_replacement_method, 'void', ['pointer', 'pointer'], fastOptions),
      delete: new NativeFunction(cm.delete_replacement_method, 'void', ['pointer'], fastOptions),
      translate: new NativeFunction(cm.translate_method, 'pointer', ['pointer'], fastOptions),
      findReplacementFromQuickCode: cm.find_replacement_method_from_quick_code
    },
    getOatQuickMethodHeaderImpl,
    hooks: {
      Interpreter: {
        doCall: cm.on_interpreter_do_call
      },
      ArtMethod: {
        getOatQuickMethodHeader: cm.on_art_method_get_oat_quick_method_header,
        prettyMethod: cm.on_art_method_pretty_method
      },
      Gc: {
        copyingPhase: {
          onLeave: cm.on_leave_gc_concurrent_copying_copying_phase
        },
        runFlip: {
          onEnter: cm.on_leave_gc_concurrent_copying_copying_phase
        }
      }
    }
  };
}

function ensureArtKnowsHowToHandleMethodInstrumentation (vm) {
  if (taughtArtAboutMethodInstrumentation) {
    return;
  }
  taughtArtAboutMethodInstrumentation = true;

  instrumentArtQuickEntrypoints(vm);
  instrumentArtMethodInvocationFromInterpreter();
}

function instrumentArtQuickEntrypoints (vm) {
  const api = getApi();

  // Entrypoints that dispatch method invocation from the quick ABI.
  const quickEntrypoints = [
    api.artQuickGenericJniTrampoline,
    api.artQuickToInterpreterBridge,
    api.artQuickResolutionTrampoline
  ];

  quickEntrypoints.forEach(entrypoint => {
    Memory.protect(entrypoint, 32, 'rwx');

    const interceptor = new ArtQuickCodeInterceptor(entrypoint);
    interceptor.activate(vm);

    artQuickInterceptors.push(interceptor);
  });
}

function instrumentArtMethodInvocationFromInterpreter () {
  const api = getApi();

  const apiLevel = getAndroidApiLevel();
  const { isApiLevel34OrApexEquivalent } = api;

  let artInterpreterDoCallExportRegex;
  if (apiLevel <= 22) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (apiLevel <= 33 && !isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE$/;
  } else {
    throw new Error('Unable to find method invocation in ART; please file a bug');
  }

  const art = api.module;
  const entries = [...art.enumerateExports(), ...art.enumerateSymbols()].filter(entry => artInterpreterDoCallExportRegex.test(entry.name));

  if (entries.length === 0) {
    throw new Error('Unable to find method invocation in ART; please file a bug');
  }

  for (const entry of entries) {
    Interceptor.attach(entry.address, artController.hooks.Interpreter.doCall);
  }
}

function ensureArtKnowsHowToHandleReplacementMethods (vm) {
  if (taughtArtAboutReplacementMethods) {
    return;
  }
  taughtArtAboutReplacementMethods = true;

  if (!maybeInstrumentGetOatQuickMethodHeaderInlineCopies()) {
    const { getOatQuickMethodHeaderImpl } = artController;
    if (getOatQuickMethodHeaderImpl === null) {
      return;
    }

    try {
      Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);
    } catch (e) {
      /*
       * Already replaced by another script. For now we don't support replacing methods from multiple scripts,
       * but we'll allow users to try it if they're feeling adventurous.
       */
    }
  }

  const apiLevel = getAndroidApiLevel();

  let copyingPhase = null;
  const api = getApi();
  if (apiLevel > 28) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv');
  } else if (apiLevel > 22) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv');
  }
  if (copyingPhase !== null) {
    Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
  }

  let runFlip = null;
  runFlip = api.find('_ZN3art6Thread15RunFlipFunctionEPS0_');
  if (runFlip === null) {
    runFlip = api.find('_ZN3art6Thread15RunFlipFunctionEPS0_b');
  }
  if (runFlip !== null) {
    Interceptor.attach(runFlip, artController.hooks.Gc.runFlip);
  }
}

const artGetOatQuickMethodHeaderInlinedCopyHandler = {
  arm: {
    signatures: [
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'c0 ff',
          'c0 ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'd8 f8 08 00', // ldr r0, [r8, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'f0 ff ff 0f',
          'ff ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '40 f0 c3 80', // bne #0x203bf0
          '00 25', // movs r5, #0
          ':',
          'c0 ff',
          'c0 ff',
          'c0 fb 00 d0',
          'ff f8'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm
  },
  arm64: {
    signatures: [
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '40 01 00 54', // b.eq 0x2e4204
          '88 39 00 f0', // adrp x8, 0xa17000
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          '00 00 00 9f'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      },
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '01 34 00 54', // b.ne 0x3d8e50
          'e0 03 1f aa', // mov x0, xzr
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          'e0 ff ff ff'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm64
  }
};

function validateGetOatQuickMethodHeaderInlinedMatchArm ({ address, size }) {
  const ldr = Instruction.parse(address.or(1));
  const [ldrDst, ldrSrc] = ldr.operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = ldrDst.value;

  const branch = Instruction.parse(ldr.next.add(2));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = branch.address.add(branch.size);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'beq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod.or(1), tryParse, { limit: 3 });

  function tryParse (insn) {
    const { mnemonic } = insn;
    if (!(mnemonic === 'ldr' || mnemonic === 'ldr.w')) {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x14)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function validateGetOatQuickMethodHeaderInlinedMatchArm64 ({ address, size }) {
  const [ldrDst, ldrSrc] = Instruction.parse(address).operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = 'x' + ldrDst.value.substring(1);

  const branch = Instruction.parse(address.add(8));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = address.add(12);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'b.eq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod, tryParse, { limit: 3 });

  function tryParse (insn) {
    if (insn.mnemonic !== 'ldr') {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x18)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function maybeInstrumentGetOatQuickMethodHeaderInlineCopies () {
  if (getAndroidApiLevel() < 31) {
    return false;
  }

  const handler = artGetOatQuickMethodHeaderInlinedCopyHandler[Process.arch];
  if (handler === undefined) {
    // Not needed on x86 and x64, at least not for now...
    return false;
  }

  const signatures = handler.signatures.map(({ pattern, offset = 0, validateMatch = returnEmptyObject }) => {
    return {
      pattern: new MatchPattern(pattern.join('')),
      offset,
      validateMatch
    };
  });

  const impls = [];
  for (const { base, size } of getApi().module.enumerateRanges('--x')) {
    for (const { pattern, offset, validateMatch } of signatures) {
      const matches = Memory.scanSync(base, size, pattern)
        .map(({ address, size }) => {
          return { address: address.sub(offset), size: size + offset };
        })
        .filter(match => {
          const validationResult = validateMatch(match);
          if (validationResult === null) {
            return false;
          }
          match.validationResult = validationResult;
          return true;
        });
      impls.push(...matches);
    }
  }

  if (impls.length === 0) {
    return false;
  }

  impls.forEach(handler.instrument);

  return true;
}

function returnEmptyObject () {
  return {};
}

class InlineHook {
  constructor (address, size, trampoline) {
    this.address = address;
    this.size = size;
    this.originalCode = address.readByteArray(size);
    this.trampoline = trampoline;
  }

  revert () {
    Memory.patchCode(this.address, this.size, code => {
      code.writeByteArray(this.originalCode);
    });
  }
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm ({ address, size, validationResult }) {
  const { methodReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);
  let redirectCapacity = size;

  Memory.patchCode(trampoline, 256, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });

    const relocator = new ThumbRelocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    writer.putBytes(vpushFpRegs);

    const savedRegs = ['r0', 'r1', 'r2', 'r3'];
    writer.putPushRegs(savedRegs);

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegImm('r0', 0);

    writer.putPopRegs(savedRegs);

    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */
    writer.putBytes(vpopFpRegs);

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();

    const tailIsRegular = relocator.input.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    while (redirectCapacity < 10) {
      const offset = relocator.readOne();
      if (offset === 0) {
        redirectCapacity = 10;
        break;
      }
      redirectCapacity = offset;
    }
    relocator.writeAll();
    writer.putBranchAddress(address.add(redirectCapacity + 1));

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, redirectCapacity, trampoline));

  Memory.patchCode(address, redirectCapacity, code => {
    const writer = new ThumbWriter(code, { pc: address });
    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm64 ({ address, size, validationResult }) {
  const { methodReg, scratchReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);

  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });

    const relocator = new Arm64Relocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const savedRegs = [
      'd0', 'd1',
      'd2', 'd3',
      'd4', 'd5',
      'd6', 'd7',
      'x0', 'x1',
      'x2', 'x3',
      'x4', 'x5',
      'x6', 'x7',
      'x8', 'x9',
      'x10', 'x11',
      'x12', 'x13',
      'x14', 'x15',
      'x16', 'x17'
    ];
    const numSavedRegs = savedRegs.length;

    for (let i = 0; i !== numSavedRegs; i += 2) {
      writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegReg('x0', 'xzr');

    for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
      writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();
    const tailInstruction = relocator.input;

    const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    writer.putBranchAddress(tailInstruction.next);

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, size, trampoline));

  Memory.patchCode(address, size, code => {
    const writer = new Arm64Writer(code, { pc: address });
    writer.putLdrRegAddress(scratchReg, trampoline);
    writer.putBrReg(scratchReg);
    writer.flush();
  });
}

export function makeMethodMangler (methodId) {
  return new MethodMangler(methodId);
}

export function translateMethod (methodId) {
  return artController.replacedMethods.translate(methodId);
}

export function backtrace (vm, options = {}) {
  const { limit = 16 } = options;

  const env = vm.getEnv();

  if (backtraceModule === null) {
    backtraceModule = makeBacktraceModule(vm, env);
  }

  return backtraceModule.backtrace(env, limit);
}

function makeBacktraceModule (vm, env) {
  const api = getApi();

  const performImpl = Memory.alloc(Process.pointerSize);

  const cm = new CModule(`
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <gum/gumtls.h>
#include <json-glib/json-glib.h>

typedef struct _ArtBacktrace ArtBacktrace;
typedef struct _ArtStackFrame ArtStackFrame;

typedef struct _ArtStackVisitor ArtStackVisitor;
typedef struct _ArtStackVisitorVTable ArtStackVisitorVTable;

typedef struct _ArtClass ArtClass;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtThread ArtThread;
typedef struct _ArtContext ArtContext;

typedef struct _JNIEnv JNIEnv;

typedef struct _StdString StdString;
typedef struct _StdTinyString StdTinyString;
typedef struct _StdLargeString StdLargeString;

typedef enum {
  STACK_WALK_INCLUDE_INLINED_FRAMES,
  STACK_WALK_SKIP_INLINED_FRAMES,
} StackWalkKind;

struct _StdTinyString
{
  guint8 unused;
  gchar data[(3 * sizeof (gpointer)) - 1];
};

struct _StdLargeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

struct _StdString
{
  union
  {
    guint8 flags;
    StdTinyString tiny;
    StdLargeString large;
  };
};

struct _ArtBacktrace
{
  GChecksum * id;
  GArray * frames;
  gchar * frames_json;
};

struct _ArtStackFrame
{
  ArtMethod * method;
  gsize dexpc;
  StdString description;
};

struct _ArtStackVisitorVTable
{
  void (* unused1) (void);
  void (* unused2) (void);
  bool (* visit) (ArtStackVisitor * visitor);
};

struct _ArtStackVisitor
{
  ArtStackVisitorVTable * vtable;

  guint8 padding[512];

  ArtStackVisitorVTable vtable_storage;

  ArtBacktrace * backtrace;
};

struct _ArtMethod
{
  guint32 declaring_class;
  guint32 access_flags;
};

extern GumTlsKey current_backtrace;

extern void (* perform_art_thread_state_transition) (JNIEnv * env);

extern ArtContext * art_thread_get_long_jump_context (ArtThread * thread);

extern void art_stack_visitor_init (ArtStackVisitor * visitor, ArtThread * thread, void * context, StackWalkKind walk_kind,
    size_t num_frames, bool check_suspended);
extern void art_stack_visitor_walk_stack (ArtStackVisitor * visitor, bool include_transitions);
extern ArtMethod * art_stack_visitor_get_method (ArtStackVisitor * visitor);
extern void art_stack_visitor_describe_location (StdString * description, ArtStackVisitor * visitor);
extern ArtMethod * translate_method (ArtMethod * method);
extern void translate_location (ArtMethod * method, guint32 pc, const gchar ** source_file, gint32 * line_number);
extern void get_class_location (StdString * result, ArtClass * klass);
extern void cxx_delete (void * mem);
extern unsigned long strtoul (const char * str, char ** endptr, int base);

static bool visit_frame (ArtStackVisitor * visitor);
static void art_stack_frame_destroy (ArtStackFrame * frame);

static void append_jni_type_name (GString * s, const gchar * name, gsize length);

static void std_string_destroy (StdString * str);
static gchar * std_string_get_data (StdString * str);

void
init (void)
{
  current_backtrace = gum_tls_key_new ();
}

void
finalize (void)
{
  gum_tls_key_free (current_backtrace);
}

ArtBacktrace *
_create (JNIEnv * env,
         guint limit)
{
  ArtBacktrace * bt;

  bt = g_new (ArtBacktrace, 1);
  bt->id = g_checksum_new (G_CHECKSUM_SHA1);
  bt->frames = (limit != 0)
      ? g_array_sized_new (FALSE, FALSE, sizeof (ArtStackFrame), limit)
      : g_array_new (FALSE, FALSE, sizeof (ArtStackFrame));
  g_array_set_clear_func (bt->frames, (GDestroyNotify) art_stack_frame_destroy);
  bt->frames_json = NULL;

  gum_tls_key_set_value (current_backtrace, bt);

  perform_art_thread_state_transition (env);

  gum_tls_key_set_value (current_backtrace, NULL);

  return bt;
}

void
_on_thread_state_transition_complete (ArtThread * thread)
{
  ArtContext * context;
  ArtStackVisitor visitor = {
    .vtable_storage = {
      .visit = visit_frame,
    },
  };

  context = art_thread_get_long_jump_context (thread);

  art_stack_visitor_init (&visitor, thread, context, STACK_WALK_SKIP_INLINED_FRAMES, 0, true);
  visitor.vtable = &visitor.vtable_storage;
  visitor.backtrace = gum_tls_key_get_value (current_backtrace);

  art_stack_visitor_walk_stack (&visitor, false);

  cxx_delete (context);
}

static bool
visit_frame (ArtStackVisitor * visitor)
{
  ArtBacktrace * bt = visitor->backtrace;
  ArtStackFrame frame;
  const gchar * description, * dexpc_part;

  frame.method = art_stack_visitor_get_method (visitor);

  art_stack_visitor_describe_location (&frame.description, visitor);

  description = std_string_get_data (&frame.description);
  if (strstr (description, " '<") != NULL)
    goto skip;

  dexpc_part = strstr (description, " at dex PC 0x");
  if (dexpc_part == NULL)
    goto skip;
  frame.dexpc = strtoul (dexpc_part + 13, NULL, 16);

  g_array_append_val (bt->frames, frame);

  g_checksum_update (bt->id, (guchar *) &frame.method, sizeof (frame.method));
  g_checksum_update (bt->id, (guchar *) &frame.dexpc, sizeof (frame.dexpc));

  return true;

skip:
  std_string_destroy (&frame.description);
  return true;
}

static void
art_stack_frame_destroy (ArtStackFrame * frame)
{
  std_string_destroy (&frame->description);
}

void
_destroy (ArtBacktrace * backtrace)
{
  g_free (backtrace->frames_json);
  g_array_free (backtrace->frames, TRUE);
  g_checksum_free (backtrace->id);
  g_free (backtrace);
}

const gchar *
_get_id (ArtBacktrace * backtrace)
{
  return g_checksum_get_string (backtrace->id);
}

const gchar *
_get_frames (ArtBacktrace * backtrace)
{
  GArray * frames = backtrace->frames;
  JsonBuilder * b;
  guint i;
  JsonNode * root;

  if (backtrace->frames_json != NULL)
    return backtrace->frames_json;

  b = json_builder_new_immutable ();

  json_builder_begin_array (b);

  for (i = 0; i != frames->len; i++)
  {
    ArtStackFrame * frame = &g_array_index (frames, ArtStackFrame, i);
    gchar * description, * ret_type, * paren_open, * paren_close, * arg_types, * token, * method_name, * class_name;
    GString * signature;
    gchar * cursor;
    ArtMethod * translated_method;
    StdString location;
    gsize dexpc;
    const gchar * source_file;
    gint32 line_number;

    description = std_string_get_data (&frame->description);

    ret_type = strchr (description, '\\'') + 1;

    paren_open = strchr (ret_type, '(');
    paren_close = strchr (paren_open, ')');
    *paren_open = '\\0';
    *paren_close = '\\0';

    arg_types = paren_open + 1;

    token = strrchr (ret_type, '.');
    *token = '\\0';

    method_name = token + 1;

    token = strrchr (ret_type, ' ');
    *token = '\\0';

    class_name = token + 1;

    signature = g_string_sized_new (128);

    append_jni_type_name (signature, class_name, method_name - class_name - 1);
    g_string_append_c (signature, ',');
    g_string_append (signature, method_name);
    g_string_append (signature, ",(");

    if (arg_types != paren_close)
    {
      for (cursor = arg_types; cursor != NULL;)
      {
        gsize length;
        gchar * next;

        token = strstr (cursor, ", ");
        if (token != NULL)
        {
          length = token - cursor;
          next = token + 2;
        }
        else
        {
          length = paren_close - cursor;
          next = NULL;
        }

        append_jni_type_name (signature, cursor, length);

        cursor = next;
      }
    }

    g_string_append_c (signature, ')');

    append_jni_type_name (signature, ret_type, class_name - ret_type - 1);

    translated_method = translate_method (frame->method);
    dexpc = (translated_method == frame->method) ? frame->dexpc : 0;

    get_class_location (&location, GSIZE_TO_POINTER (translated_method->declaring_class));

    translate_location (translated_method, dexpc, &source_file, &line_number);

    json_builder_begin_object (b);

    json_builder_set_member_name (b, "signature");
    json_builder_add_string_value (b, signature->str);

    json_builder_set_member_name (b, "origin");
    json_builder_add_string_value (b, std_string_get_data (&location));

    json_builder_set_member_name (b, "className");
    json_builder_add_string_value (b, class_name);

    json_builder_set_member_name (b, "methodName");
    json_builder_add_string_value (b, method_name);

    json_builder_set_member_name (b, "methodFlags");
    json_builder_add_int_value (b, translated_method->access_flags);

    json_builder_set_member_name (b, "fileName");
    json_builder_add_string_value (b, source_file);

    json_builder_set_member_name (b, "lineNumber");
    json_builder_add_int_value (b, line_number);

    json_builder_end_object (b);

    std_string_destroy (&location);
    g_string_free (signature, TRUE);
  }

  json_builder_end_array (b);

  root = json_builder_get_root (b);
  backtrace->frames_json = json_to_string (root, FALSE);
  json_node_unref (root);

  return backtrace->frames_json;
}

static void
append_jni_type_name (GString * s,
                      const gchar * name,
                      gsize length)
{
  gchar shorty = '\\0';
  gsize i;

  switch (name[0])
  {
    case 'b':
      if (strncmp (name, "boolean", length) == 0)
        shorty = 'Z';
      else if (strncmp (name, "byte", length) == 0)
        shorty = 'B';
      break;
    case 'c':
      if (strncmp (name, "char", length) == 0)
        shorty = 'C';
      break;
    case 'd':
      if (strncmp (name, "double", length) == 0)
        shorty = 'D';
      break;
    case 'f':
      if (strncmp (name, "float", length) == 0)
        shorty = 'F';
      break;
    case 'i':
      if (strncmp (name, "int", length) == 0)
        shorty = 'I';
      break;
    case 'l':
      if (strncmp (name, "long", length) == 0)
        shorty = 'J';
      break;
    case 's':
      if (strncmp (name, "short", length) == 0)
        shorty = 'S';
      break;
    case 'v':
      if (strncmp (name, "void", length) == 0)
        shorty = 'V';
      break;
  }

  if (shorty != '\\0')
  {
    g_string_append_c (s, shorty);

    return;
  }

  if (length > 2 && name[length - 2] == '[' && name[length - 1] == ']')
  {
    g_string_append_c (s, '[');
    append_jni_type_name (s, name, length - 2);

    return;
  }

  g_string_append_c (s, 'L');

  for (i = 0; i != length; i++)
  {
    gchar ch = name[i];
    if (ch != '.')
      g_string_append_c (s, ch);
    else
      g_string_append_c (s, '/');
  }

  g_string_append_c (s, ';');
}

static void
std_string_destroy (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  if (is_large)
    cxx_delete (str->large.data);
}

static gchar *
std_string_get_data (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  return is_large ? str->large.data : str->tiny.data;
}
`, {
    current_backtrace: Memory.alloc(Process.pointerSize),
    perform_art_thread_state_transition: performImpl,
    art_thread_get_long_jump_context: api['art::Thread::GetLongJumpContext'],
    art_stack_visitor_init: api['art::StackVisitor::StackVisitor'],
    art_stack_visitor_walk_stack: api['art::StackVisitor::WalkStack'],
    art_stack_visitor_get_method: api['art::StackVisitor::GetMethod'],
    art_stack_visitor_describe_location: api['art::StackVisitor::DescribeLocation'],
    translate_method: artController.replacedMethods.translate,
    translate_location: api['art::Monitor::TranslateLocation'],
    get_class_location: api['art::mirror::Class::GetLocation'],
    cxx_delete: api.$delete,
    strtoul: Process.getModuleByName('libc.so').getExportByName('strtoul')
  });

  const _create = new NativeFunction(cm._create, 'pointer', ['pointer', 'uint'], nativeFunctionOptions);
  const _destroy = new NativeFunction(cm._destroy, 'void', ['pointer'], nativeFunctionOptions);

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };
  const _getId = new NativeFunction(cm._get_id, 'pointer', ['pointer'], fastOptions);
  const _getFrames = new NativeFunction(cm._get_frames, 'pointer', ['pointer'], fastOptions);

  const performThreadStateTransition = makeArtThreadStateTransitionImpl(vm, env, cm._on_thread_state_transition_complete);
  cm._performData = performThreadStateTransition;
  performImpl.writePointer(performThreadStateTransition);

  cm.backtrace = (env, limit) => {
    const handle = _create(env, limit);
    const bt = new Backtrace(handle);
    Script.bindWeak(bt, destroy.bind(null, handle));
    return bt;
  };

  function destroy (handle) {
    _destroy(handle);
  }

  cm.getId = handle => {
    return _getId(handle).readUtf8String();
  };

  cm.getFrames = handle => {
    return JSON.parse(_getFrames(handle).readUtf8String());
  };

  return cm;
}

class Backtrace {
  constructor (handle) {
    this.handle = handle;
  }

  get id () {
    return backtraceModule.getId(this.handle);
  }

  get frames () {
    return backtraceModule.getFrames(this.handle);
  }
}

export function revertGlobalPatches () {
  patchedClasses.forEach(entry => {
    entry.vtablePtr.writePointer(entry.vtable);
    entry.vtableCountPtr.writeS32(entry.vtableCount);
  });
  patchedClasses.clear();

  for (const interceptor of artQuickInterceptors.splice(0)) {
    interceptor.deactivate();
  }

  for (const hook of inlineHooks.splice(0)) {
    hook.revert();
  }
}

function unwrapMethodId (methodId) {
  return unwrapGenericId(methodId, 'art::jni::JniIdManager::DecodeMethodId');
}

function unwrapFieldId (fieldId) {
  return unwrapGenericId(fieldId, 'art::jni::JniIdManager::DecodeFieldId');
}

function unwrapGenericId (genericId, apiMethod) {
  const api = getApi();

  const runtimeOffset = getArtRuntimeSpec(api).offset;
  const jniIdManagerOffset = runtimeOffset.jniIdManager;
  const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;

  if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
    const runtime = api.artRuntime;

    const jniIdsIndirection = runtime.add(jniIdsIndirectionOffset).readInt();

    if (jniIdsIndirection !== kPointer) {
      const jniIdManager = runtime.add(jniIdManagerOffset).readPointer();
      return api[apiMethod](jniIdManager, genericId);
    }
  }

  return genericId;
}

const artQuickCodeReplacementTrampolineWriters = {
  ia32: writeArtQuickCodeReplacementTrampolineIA32,
  x64: writeArtQuickCodeReplacementTrampolineX64,
  arm: writeArtQuickCodeReplacementTrampolineArm,
  arm64: writeArtQuickCodeReplacementTrampolineArm64
};

function writeArtQuickCodeReplacementTrampolineIA32 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [esp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [esp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('ebp', 'esp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('esp', 0xfffffff0);
    writer.putSubRegImm('esp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegFsU32Ptr('ebx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['eax', 'ebx']);

    writer.putTestRegReg('eax', 'eax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of eax in the current frame.
    writer.putMovRegOffsetPtrReg('ebp', 7 * 4, 'eax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('esp', 'ebp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('eax', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineX64 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [rsp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [rsp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('rbp', 'rsp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('rsp', 0xfffffff0);
    writer.putSubRegImm('rsp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegGsU32Ptr('rbx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['rdi', 'rbx']);

    writer.putTestRegReg('rax', 'rax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of rdi in the current frame.
    writer.putMovRegOffsetPtrReg('rbp', 8 * 8, 'rax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('rsp', 'rbp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('rdi', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm (trampoline, target, redirectSize, constraints, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });
    const relocator = new ThumbRelocator(targetAddress, writer);

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */

    // Save core args, callee-saves, LR.
    writer.putPushRegs([
      'r1',
      'r2',
      'r3',
      'r5',
      'r6',
      'r7',
      'r8',
      'r10',
      'r11',
      'lr'
    ]);

    // Save FPRs.
    writer.putBytes(vpushFpRegs);

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 8);
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['r0', 'r9']);

    writer.putCmpRegImm('r0', 0);
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of r0 in the current frame.
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('r0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 8);

    // Restore FPRs.
    writer.putBytes(vpopFpRegs);

    // Restore LR, callee-saves & core args.
    writer.putPopRegs([
      'lr',
      'r11',
      'r10',
      'r8',
      'r7',
      'r6',
      'r5',
      'r3',
      'r2',
      'r1'
    ]);

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putLdrRegAddress('pc', target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('pc', 'r0', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm64 (trampoline, target, redirectSize, { availableScratchRegs }, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });
    const relocator = new Arm64Relocator(target, writer);

    // Save FPRs.
    writer.putPushRegReg('d0', 'd1');
    writer.putPushRegReg('d2', 'd3');
    writer.putPushRegReg('d4', 'd5');
    writer.putPushRegReg('d6', 'd7');

    // Save core args, callee-saves & LR.
    writer.putPushRegReg('x1', 'x2');
    writer.putPushRegReg('x3', 'x4');
    writer.putPushRegReg('x5', 'x6');
    writer.putPushRegReg('x7', 'x20');
    writer.putPushRegReg('x21', 'x22');
    writer.putPushRegReg('x23', 'x24');
    writer.putPushRegReg('x25', 'x26');
    writer.putPushRegReg('x27', 'x28');
    writer.putPushRegReg('x29', 'lr');

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 16);
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['x0', 'x19']);

    writer.putCmpRegReg('x0', 'xzr');
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of x0 in the current frame.
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('x0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 16);

    // Restore core args, callee-saves & LR.
    writer.putPopRegReg('x29', 'lr');
    writer.putPopRegReg('x27', 'x28');
    writer.putPopRegReg('x25', 'x26');
    writer.putPopRegReg('x23', 'x24');
    writer.putPopRegReg('x21', 'x22');
    writer.putPopRegReg('x7', 'x20');
    writer.putPopRegReg('x5', 'x6');
    writer.putPopRegReg('x3', 'x4');
    writer.putPopRegReg('x1', 'x2');

    // Restore FPRs.
    writer.putPopRegReg('d6', 'd7');
    writer.putPopRegReg('d4', 'd5');
    writer.putPopRegReg('d2', 'd3');
    writer.putPopRegReg('d0', 'd1');

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      const scratchReg = Array.from(availableScratchRegs)[0];
      writer.putLdrRegAddress(scratchReg, target.add(offset));
      writer.putBrReg(scratchReg);
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('x16', 'x0', artMethodOffsets.quickCode);
    writer.putBrReg('x16');

    writer.flush();
  });

  return offset;
}

const artQuickCodePrologueWriters = {
  ia32: writeArtQuickCodePrologueX86,
  x64: writeArtQuickCodePrologueX86,
  arm: writeArtQuickCodePrologueArm,
  arm64: writeArtQuickCodePrologueArm64
};

function writeArtQuickCodePrologueX86 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new X86Writer(code, { pc: target });

    writer.putJmpAddress(trampoline);
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm (target, trampoline, redirectSize) {
  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  Memory.patchCode(targetAddress, 16, code => {
    const writer = new ThumbWriter(code, { pc: targetAddress });

    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm64 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new Arm64Writer(code, { pc: target });

    if (redirectSize === 16) {
      writer.putLdrRegAddress('x16', trampoline);
    } else {
      writer.putAdrpRegAddress('x16', trampoline);
    }

    writer.putBrReg('x16');

    writer.flush();
  });
}

const artQuickCodeHookRedirectSize = {
  ia32: 5,
  x64: 16,
  arm: 8,
  arm64: 16
};

class ArtQuickCodeInterceptor {
  constructor (quickCode) {
    this.quickCode = quickCode;
    this.quickCodeAddress = (Process.arch === 'arm')
      ? quickCode.and(THUMB_BIT_REMOVAL_MASK)
      : quickCode;

    this.redirectSize = 0;
    this.trampoline = null;
    this.overwrittenPrologue = null;
    this.overwrittenPrologueLength = 0;
  }

  _canRelocateCode (relocationSize, constraints) {
    const Writer = thunkWriters[Process.arch];
    const Relocator = thunkRelocators[Process.arch];

    const { quickCodeAddress } = this;

    const writer = new Writer(quickCodeAddress);
    const relocator = new Relocator(quickCodeAddress, writer);

    let offset;
    if (Process.arch === 'arm64') {
      let availableScratchRegs = new Set(['x16', 'x17']);

      do {
        const nextOffset = relocator.readOne();

        const nextScratchRegs = new Set(availableScratchRegs);
        const { read, written } = relocator.input.regsAccessed;
        for (const regs of [read, written]) {
          for (const reg of regs) {
            let name;
            if (reg.startsWith('w')) {
              name = 'x' + reg.substring(1);
            } else {
              name = reg;
            }
            nextScratchRegs.delete(name);
          }
        }
        if (nextScratchRegs.size === 0) {
          break;
        }

        offset = nextOffset;
        availableScratchRegs = nextScratchRegs;
      } while (offset < relocationSize && !relocator.eoi);

      constraints.availableScratchRegs = availableScratchRegs;
    } else {
      do {
        offset = relocator.readOne();
      } while (offset < relocationSize && !relocator.eoi);
    }

    return offset >= relocationSize;
  }

  _allocateTrampoline () {
    if (trampolineAllocator === null) {
      const trampolineSize = (pointerSize === 4) ? 128 : 256;
      trampolineAllocator = makeCodeAllocator(trampolineSize);
    }

    const maxRedirectSize = artQuickCodeHookRedirectSize[Process.arch];

    let redirectSize, spec;
    let alignment = 1;
    const constraints = {};
    if (pointerSize === 4 || this._canRelocateCode(maxRedirectSize, constraints)) {
      redirectSize = maxRedirectSize;

      spec = {};
    } else {
      let maxDistance;
      if (Process.arch === 'x64') {
        redirectSize = 5;
        maxDistance = X86_JMP_MAX_DISTANCE;
      } else if (Process.arch === 'arm64') {
        redirectSize = 8;
        maxDistance = ARM64_ADRP_MAX_DISTANCE;
        alignment = 4096;
      }

      spec = { near: this.quickCodeAddress, maxDistance };
    }

    this.redirectSize = redirectSize;
    this.trampoline = trampolineAllocator.allocateSlice(spec, alignment);

    return constraints;
  }

  _destroyTrampoline () {
    trampolineAllocator.freeSlice(this.trampoline);
  }

  activate (vm) {
    const constraints = this._allocateTrampoline();

    const { trampoline, quickCode, redirectSize } = this;

    const writeTrampoline = artQuickCodeReplacementTrampolineWriters[Process.arch];
    const prologueLength = writeTrampoline(trampoline, quickCode, redirectSize, constraints, vm);
    this.overwrittenPrologueLength = prologueLength;

    this.overwrittenPrologue = Memory.dup(this.quickCodeAddress, prologueLength);

    const writePrologue = artQuickCodePrologueWriters[Process.arch];
    writePrologue(quickCode, trampoline, redirectSize);
  }

  deactivate () {
    const { quickCodeAddress, overwrittenPrologueLength: prologueLength } = this;

    const Writer = thunkWriters[Process.arch];
    Memory.patchCode(quickCodeAddress, prologueLength, code => {
      const writer = new Writer(code, { pc: quickCodeAddress });

      const { overwrittenPrologue } = this;

      writer.putBytes(overwrittenPrologue.readByteArray(prologueLength));
      writer.flush();
    });

    this._destroyTrampoline();
  }
}

function isArtQuickEntrypoint (address) {
  const api = getApi();

  const { module: m, artClassLinker } = api;

  return address.equals(artClassLinker.quickGenericJniTrampoline) ||
      address.equals(artClassLinker.quickToInterpreterBridgeTrampoline) ||
      address.equals(artClassLinker.quickResolutionTrampoline) ||
      address.equals(artClassLinker.quickImtConflictTrampoline) ||
      (address.compare(m.base) >= 0 && address.compare(m.base.add(m.size)) < 0);
}

class ArtMethodMangler {
  constructor (opaqueMethodId) {
    const methodId = unwrapMethodId(opaqueMethodId);

    this.methodId = methodId;
    this.originalMethod = null;
    this.hookedMethodId = methodId;
    this.replacementMethodId = null;

    this.interceptor = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { kAccCompileDontBother, artNterpEntryPoint } = api;

    this.originalMethod = fetchArtMethod(this.methodId, vm);

    const originalFlags = this.originalMethod.accessFlags;

    if ((originalFlags & kAccXposedHookedMethod) !== 0 && xposedIsSupported()) {
      const hookInfo = this.originalMethod.jniCode;
      this.hookedMethodId = hookInfo.add(2 * pointerSize).readPointer();
      this.originalMethod = fetchArtMethod(this.hookedMethodId, vm);
    }

    const { hookedMethodId } = this;

    const replacementMethodId = cloneArtMethod(hookedMethodId, vm);
    this.replacementMethodId = replacementMethodId;

    patchArtMethod(replacementMethodId, {
      jniCode: impl,
      accessFlags: ((originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag)) | kAccNative | kAccCompileDontBother) >>> 0,
      quickCode: api.artClassLinker.quickGenericJniTrampoline,
      interpreterCode: api.artInterpreterToCompiledCodeBridge
    }, vm);

    // Remove kAccFastInterpreterToInterpreterInvoke and kAccSkipAccessChecks to disable use_fast_path
    // in interpreter_common.h
    let hookedMethodRemovedFlags = kAccFastInterpreterToInterpreterInvoke | kAccSingleImplementation | kAccNterpEntryPointFastPathFlag;
    if ((originalFlags & kAccNative) === 0) {
      hookedMethodRemovedFlags |= kAccSkipAccessChecks;
    }

    patchArtMethod(hookedMethodId, {
      accessFlags: ((originalFlags & ~(hookedMethodRemovedFlags)) | kAccCompileDontBother) >>> 0
    }, vm);

    const quickCode = this.originalMethod.quickCode;

    // Replace Nterp quick entrypoints with art_quick_to_interpreter_bridge to force stepping out
    // of ART's next-generation interpreter and use the quick stub instead.
    if (artNterpEntryPoint !== null && quickCode.equals(artNterpEntryPoint)) {
      patchArtMethod(hookedMethodId, {
        quickCode: api.artQuickToInterpreterBridge
      }, vm);
    }

    if (!isArtQuickEntrypoint(quickCode)) {
      const interceptor = new ArtQuickCodeInterceptor(quickCode);
      interceptor.activate(vm);

      this.interceptor = interceptor;
    }

    artController.replacedMethods.set(hookedMethodId, replacementMethodId);

    notifyArtMethodHooked(hookedMethodId, vm);
  }

  revert (vm) {
    const { hookedMethodId, interceptor } = this;

    patchArtMethod(hookedMethodId, this.originalMethod, vm);

    artController.replacedMethods.delete(hookedMethodId);

    if (interceptor !== null) {
      interceptor.deactivate();

      this.interceptor = null;
    }
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    return this.hookedMethodId;
  }
}

function xposedIsSupported () {
  return getAndroidApiLevel() < 28;
}

function fetchArtMethod (methodId, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  return (['jniCode', 'accessFlags', 'quickCode', 'interpreterCode']
    .reduce((original, name) => {
      const offset = artMethodOffset[name];
      if (offset === undefined) {
        return original;
      }
      const address = methodId.add(offset);
      const read = (name === 'accessFlags') ? readU32 : readPointer;
      original[name] = read.call(address);
      return original;
    }, {}));
}

function patchArtMethod (methodId, patches, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  Object.keys(patches).forEach(name => {
    const offset = artMethodOffset[name];
    if (offset === undefined) {
      return;
    }
    const address = methodId.add(offset);
    const write = (name === 'accessFlags') ? writeU32 : writePointer;
    write.call(address, patches[name]);
  });
}

class DalvikMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.originalMethod = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { methodId } = this;

    this.originalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);

    let argsSize = argTypes.reduce((acc, t) => (acc + t.size), 0);
    if (isInstanceMethod) {
      argsSize++;
    }

    /*
     * make method native (with kAccNative)
     * insSize and registersSize are set to arguments size
     */
    const accessFlags = (methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).readU32() | kAccNative) >>> 0;
    const registersSize = argsSize;
    const outsSize = 0;
    const insSize = argsSize;

    methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).writeU32(accessFlags);
    methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE).writeU16(registersSize);
    methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE).writeU16(outsSize);
    methodId.add(DVM_METHOD_OFFSET_INS_SIZE).writeU16(insSize);
    methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO).writeU32(computeDalvikJniArgInfo(methodId));

    api.dvmUseJNIBridge(methodId, impl);
  }

  revert (vm) {
    Memory.copy(this.methodId, this.originalMethod, DVM_METHOD_SIZE);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

    let objectPtr;
    if (isInstanceMethod) {
      objectPtr = api.dvmDecodeIndirectRef(thread, wrapper.$h);
    } else {
      const h = wrapper.$borrowClassHandle(env);
      objectPtr = api.dvmDecodeIndirectRef(thread, h.value);
      h.unref(env);
    }

    let classObject;
    if (isInstanceMethod) {
      classObject = objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ).readPointer();
    } else {
      classObject = objectPtr;
    }

    const classKey = classObject.toString(16);
    let entry = patchedClasses.get(classKey);
    if (entry === undefined) {
      const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
      const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
      const vtable = vtablePtr.readPointer();
      const vtableCount = vtableCountPtr.readS32();

      const vtableSize = vtableCount * pointerSize;
      const shadowVtable = Memory.alloc(2 * vtableSize);
      Memory.copy(shadowVtable, vtable, vtableSize);
      vtablePtr.writePointer(shadowVtable);

      entry = {
        classObject,
        vtablePtr,
        vtableCountPtr,
        vtable,
        vtableCount,
        shadowVtable,
        shadowVtableCount: vtableCount,
        targetMethods: new Map()
      };
      patchedClasses.set(classKey, entry);
    }

    const methodKey = this.methodId.toString(16);
    let targetMethod = entry.targetMethods.get(methodKey);
    if (targetMethod === undefined) {
      targetMethod = Memory.dup(this.originalMethod, DVM_METHOD_SIZE);

      const methodIndex = entry.shadowVtableCount++;
      entry.shadowVtable.add(methodIndex * pointerSize).writePointer(targetMethod);
      targetMethod.add(DVM_METHOD_OFFSET_METHOD_INDEX).writeU16(methodIndex);
      entry.vtableCountPtr.writeS32(entry.shadowVtableCount);

      entry.targetMethods.set(methodKey, targetMethod);
    }

    return targetMethod;
  }
}

function computeDalvikJniArgInfo (methodId) {
  if (Process.arch !== 'ia32') {
    return DALVIK_JNI_NO_ARG_INFO;
  }

  // For the x86 ABI, valid hints should always be generated.
  const shorty = methodId.add(DVM_METHOD_OFFSET_SHORTY).readPointer().readCString();
  if (shorty === null || shorty.length === 0 || shorty.length > 0xffff) {
    return DALVIK_JNI_NO_ARG_INFO;
  }

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

function cloneArtMethod (method, vm) {
  const api = getApi();

  if (getAndroidApiLevel() < 23) {
    const thread = api['art::Thread::CurrentFromGdb']();
    return api['art::mirror::Object::Clone'](method, thread);
  }

  return Memory.dup(method, getArtMethodSpec(vm).size);
}

export function deoptimizeMethod (vm, env, method) {
  requestDeoptimization(vm, env, kSelectiveDeoptimization, method);
}

export function deoptimizeEverything (vm, env) {
  requestDeoptimization(vm, env, kFullDeoptimization);
}

export function deoptimizeBootImage (vm, env) {
  const api = getApi();

  if (getAndroidApiLevel() < 26) {
    throw new Error('This API is only available on Android >= 8.0');
  }

  withRunnableArtThread(vm, env, thread => {
    api['art::Runtime::DeoptimizeBootImage'](api.artRuntime);
  });
}

function requestDeoptimization (vm, env, kind, method) {
  const api = getApi();

  if (getAndroidApiLevel() < 24) {
    throw new Error('This API is only available on Android >= 7.0');
  }

  withRunnableArtThread(vm, env, thread => {
    if (getAndroidApiLevel() < 30) {
      if (!api.isJdwpStarted()) {
        const session = startJdwp(api);
        jdwpSessions.push(session);
      }

      if (!api.isDebuggerActive()) {
        api['art::Dbg::GoActive']();
      }

      const request = Memory.alloc(8 + pointerSize);
      request.writeU32(kind);

      switch (kind) {
        case kFullDeoptimization:
          break;
        case kSelectiveDeoptimization:
          request.add(8).writePointer(method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }

      api['art::Dbg::RequestDeoptimization'](request);

      api['art::Dbg::ManageDeoptimization']();
    } else {
      const instrumentation = api.artInstrumentation;
      if (instrumentation === null) {
        throw new Error('Unable to find Instrumentation class in ART; please file a bug');
      }

      const enableDeopt = api['art::Instrumentation::EnableDeoptimization'];
      if (enableDeopt !== undefined) {
        const deoptimizationEnabled = !!instrumentation.add(getArtInstrumentationSpec().offset.deoptimizationEnabled).readU8();
        if (!deoptimizationEnabled) {
          enableDeopt(instrumentation);
        }
      }

      switch (kind) {
        case kFullDeoptimization:
          api['art::Instrumentation::DeoptimizeEverything'](instrumentation, Memory.allocUtf8String('frida'));
          break;
        case kSelectiveDeoptimization:
          api['art::Instrumentation::Deoptimize'](instrumentation, method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }
    }
  });
}

class JdwpSession {
  constructor () {
    /*
     * We partially stub out the ADB JDWP transport to ensure we always
     * succeed in starting JDWP. Failure will crash the process.
     */
    const libart = Process.getModuleByName('libart.so');
    const acceptImpl = libart.getExportByName('_ZN3art4JDWP12JdwpAdbState6AcceptEv');
    const receiveClientFdImpl = libart.getExportByName('_ZN3art4JDWP12JdwpAdbState15ReceiveClientFdEv');

    const controlPair = makeSocketPair();
    const clientPair = makeSocketPair();

    this._controlFd = controlPair[0];
    this._clientFd = clientPair[0];

    let acceptListener = null;
    acceptListener = Interceptor.attach(acceptImpl, function (args) {
      const state = args[0];

      const controlSockPtr = Memory.scanSync(state.add(8252), 256, '00 ff ff ff ff 00')[0].address.add(1);

      /*
       * This will make JdwpAdbState::Accept() skip the control socket() and connect(),
       * and skip right to calling ReceiveClientFd(), replaced below.
       */
      controlSockPtr.writeS32(controlPair[1]);

      acceptListener.detach();
    });

    Interceptor.replace(receiveClientFdImpl, new NativeCallback(function (state) {
      Interceptor.revert(receiveClientFdImpl);

      return clientPair[1];
    }, 'int', ['pointer']));

    Interceptor.flush();

    this._handshakeRequest = this._performHandshake();
  }

  async _performHandshake () {
    const input = new UnixInputStream(this._clientFd, { autoClose: false });
    const output = new UnixOutputStream(this._clientFd, { autoClose: false });

    const handshakePacket = [0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65];
    try {
      await output.writeAll(handshakePacket);
      await input.readAll(handshakePacket.length);
    } catch (e) { /* empty */ }
  }
}

function startJdwp (api) {
  const session = new JdwpSession();

  api['art::Dbg::SetJdwpAllowed'](1);

  const options = makeJdwpOptions();
  api['art::Dbg::ConfigureJdwp'](options);

  const startDebugger = api['art::InternalDebuggerControlCallback::StartDebugger'];
  if (startDebugger !== undefined) {
    startDebugger(NULL);
  } else {
    api['art::Dbg::StartJdwp']();
  }

  return session;
}

function makeJdwpOptions () {
  const kJdwpTransportAndroidAdb = getAndroidApiLevel() < 28 ? 2 : 3;
  const kJdwpPortFirstAvailable = 0;

  const transport = kJdwpTransportAndroidAdb;
  const server = true;
  const suspend = false;
  const port = kJdwpPortFirstAvailable;

  const size = 8 + STD_STRING_SIZE + 2;
  const result = Memory.alloc(size);
  result
    .writeU32(transport).add(4)
    .writeU8(server ? 1 : 0).add(1)
    .writeU8(suspend ? 1 : 0).add(1)
    .add(STD_STRING_SIZE) // We leave `host` zeroed, i.e. empty string
    .writeU16(port);
  return result;
}

function makeSocketPair () {
  if (socketpair === null) {
    socketpair = new NativeFunction(
      Process.getModuleByName('libc.so').getExportByName('socketpair'),
      'int',
      ['int', 'int', 'int', 'pointer']);
  }

  const buf = Memory.alloc(8);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, buf) === -1) {
    throw new Error('Unable to create socketpair for JDWP');
  }

  return [
    buf.readS32(),
    buf.add(4).readS32()
  ];
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

function makeDecodeGlobalFallback (api) {
  /*
   * Fallback for art::JavaVMExt::DecodeGlobal, which is
   * unavailable in Android versions <= 5 and >= 15.
   */
  const decode = api['art::Thread::DecodeJObject'];
  if (decode === undefined) {
    throw new Error('art::Thread::DecodeJObject is not available; please file a bug');
  }

  return function (vm, thread, ref) {
    return decode(thread, ref);
  };
}

/*
 * In order to call internal ART APIs we need to transition our native thread's
 * art::Thread to the proper state. The ScopedObjectAccess (SOA) helper that ART
 * uses internally is what we would like to use to accomplish this goal.
 *
 * There is however a challenge. The SOA implementation is fully inlined, so
 * we cannot just allocate a chunk of memory and call its constructor and
 * destructor to get the desired setup and teardown.
 *
 * We could however precompile such code using a C++ compiler, but considering
 * how many versions of ART we would need to compile it for, multiplied by the
 * number of supported architectures, we really don't want to go there.
 *
 * Reimplementing it in JavaScript is not desirable either, as we would need
 * to keep track of even more internals prone to change as ART evolves.
 *
 * So our least terrible option is to find a really simple C++ method in ART
 * that sets up a SOA object, performs as few and distinct operations as
 * possible, and then returns. If we clone that implementation we can swap
 * out the few/distinct operations with our own.
 *
 * We can accomplish this by using Frida's relocator API, and detecting the
 * few/distinct operations happening between setup and teardown of the scope.
 * We skip those when making our copy and instead put a call to a NativeCallback
 * there. Our NativeCallback is thus able to call internal ART APIs safely.
 *
 * The ExceptionClear() implementation that's part of the JNIEnv's vtable is
 * a perfect fit, as all it does is clear one field of the art::Thread.
 * (Except on older versions where it also clears a bit more... but still
 * pretty simple.)
 *
 * However, checked JNI might be enabled, making ExceptionClear() a bit more
 * complex, and essentially a wrapper around the unchecked version.
 *
 * One last thing to note is that we also look up the address of FatalError(),
 * as ExceptionClear() typically ends with a __stack_chk_fail() noreturn call
 * that's followed by the next JNIEnv vtable method, FatalError(). We don't want
 * to recompile its code as well, so we try to detect it. There might however be
 * padding between the two functions, which we need to ignore. Ideally we would
 * know that the call is to __stack_chk_fail(), so we can stop at that point,
 * but detecting that isn't trivial.
 */

const threadStateTransitionRecompilers = {
  ia32: recompileExceptionClearForX86,
  x64: recompileExceptionClearForX86,
  arm: recompileExceptionClearForArm,
  arm64: recompileExceptionClearForArm64
};

function makeArtThreadStateTransitionImpl (vm, env, callback) {
  const api = getApi();
  const envVtable = env.handle.readPointer();

  let exceptionClearImpl;
  const innerExceptionClearImpl = api.find('_ZN3art3JNIILb1EE14ExceptionClearEP7_JNIEnv');
  if (innerExceptionClearImpl !== null) {
    exceptionClearImpl = innerExceptionClearImpl;
  } else {
    exceptionClearImpl = envVtable.add(ENV_VTABLE_OFFSET_EXCEPTION_CLEAR).readPointer();
  }

  let nextFuncImpl;
  const innerNextFuncImpl = api.find('_ZN3art3JNIILb1EE10FatalErrorEP7_JNIEnvPKc');
  if (innerNextFuncImpl !== null) {
    nextFuncImpl = innerNextFuncImpl;
  } else {
    nextFuncImpl = envVtable.add(ENV_VTABLE_OFFSET_FATAL_ERROR).readPointer();
  }

  const recompile = threadStateTransitionRecompilers[Process.arch];
  if (recompile === undefined) {
    throw new Error('Not yet implemented for ' + Process.arch);
  }

  let perform = null;

  const threadOffsets = getArtThreadSpec(vm).offset;

  const exceptionOffset = threadOffsets.exception;

  const neuteredOffsets = new Set();
  const isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;
  if (isReportedOffset !== null) {
    neuteredOffsets.add(isReportedOffset);
  }
  const throwLocationStartOffset = threadOffsets.throwLocation;
  if (throwLocationStartOffset !== null) {
    neuteredOffsets.add(throwLocationStartOffset);
    neuteredOffsets.add(throwLocationStartOffset + pointerSize);
    neuteredOffsets.add(throwLocationStartOffset + (2 * pointerSize));
  }

  const codeSize = 65536;
  const code = Memory.alloc(codeSize);
  Memory.patchCode(code, codeSize, buffer => {
    perform = recompile(buffer, code, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback);
  });

  perform._code = code;
  perform._callback = callback;

  return perform;
}

function recompileExceptionClearForX86 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'jmp':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new X86Writer(buffer, { pc });

  let foundCore = false;
  let threadReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new X86Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'jmp':
          writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), 'no-hint');
          keep = false;
          break;
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'mov': {
          const [dst, src] = insn.operands;

          if (dst.type === 'mem' && src.type === 'imm') {
            const dstValue = dst.value;
            const dstOffset = dstValue.disp;

            if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
              threadReg = dstValue.base;

              writer.putPushfx();
              writer.putPushax();
              writer.putMovRegReg('xbp', 'xsp');
              if (pointerSize === 4) {
                writer.putAndRegU32('esp', 0xfffffff0);
              } else {
                const scratchReg = (threadReg !== 'rdi') ? 'rdi' : 'rsi';
                writer.putMovRegU64(scratchReg, uint64('0xfffffffffffffff0'));
                writer.putAndRegReg('rsp', scratchReg);
              }
              writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
              writer.putMovRegReg('xsp', 'xbp');
              writer.putPopax();
              writer.putPopfx();

              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'call': {
          const target = insn.operands[0];
          if (target.type === 'mem' && target.value.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            /*
             * Get art::Thread * from JNIEnv *
             */
            if (pointerSize === 4) {
              writer.putPopReg('eax');
              writer.putMovRegRegOffsetPtr('eax', 'eax', 4);
              writer.putPushReg('eax');
            } else {
              writer.putMovRegRegOffsetPtr('rdi', 'rdi', 8);
            }

            writer.putCallAddressWithArguments(callback, []);

            foundCore = true;
            keep = false;
          }

          break;
        }
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const thumbBitRemovalMask = ptr(1).not();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const begin = current.and(thumbBitRemovalMask);
    const blockId = begin.toString();
    const thumbBit = current.and(1);

    let block = {
      begin
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    let ifThenBlockRemaining = 0;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      const { mnemonic } = insn;
      lastInsn = insn;

      const currentAddress = current.and(thumbBitRemovalMask);
      const insnId = currentAddress.toString();

      const existingBlock = blocks[insnId];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockId] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      const isOutsideIfThenBlock = ifThenBlockRemaining === 0;

      let branchTarget = null;

      switch (mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = isOutsideIfThenBlock;
          break;
        case 'beq.w':
        case 'beq':
        case 'bne':
        case 'bne.w':
        case 'bgt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'pop.w':
          if (isOutsideIfThenBlock) {
            reachedEndOfBlock = insn.operands.filter(op => op.value === 'pc').length === 1;
          }
          break;
      }

      switch (mnemonic) {
        case 'it':
          ifThenBlockRemaining = 1;
          break;
        case 'itt':
          ifThenBlockRemaining = 2;
          break;
        case 'ittt':
          ifThenBlockRemaining = 3;
          break;
        case 'itttt':
          ifThenBlockRemaining = 4;
          break;
        default:
          if (ifThenBlockRemaining > 0) {
            ifThenBlockRemaining--;
          }
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget.or(thumbBit));
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockId] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new ThumbWriter(buffer, { pc });

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const relocator = new ThumbRelocator(block.begin, writer);

    let address = block.begin;
    const end = block.end;
    let size = 0;
    do {
      const offset = relocator.readOne();
      if (offset === 0) {
        throw new Error('Unexpected end of block');
      }
      const insn = relocator.input;
      address = insn.address;
      size = insn.size;
      const { mnemonic } = insn;

      const insnAddressId = address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq.w':
          writer.putBCondLabelWide('eq', branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'bne.w':
          writer.putBCondLabelWide('ne', branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq':
        case 'bne':
        case 'bgt':
          writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str':
        case 'str.w': {
          const dstValue = insn.operands[1].value;
          const dstOffset = dstValue.disp;

          if (dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            const nzcvqReg = (threadReg !== 'r4') ? 'r4' : 'r5';
            const clobberedRegs = ['r0', 'r1', 'r2', 'r3', nzcvqReg, 'r9', 'r12', 'lr'];

            writer.putPushRegs(clobberedRegs);
            writer.putMrsRegReg(nzcvqReg, 'apsr-nzcvq');

            writer.putCallAddressWithArguments(callback, [threadReg]);

            writer.putMsrRegReg('apsr-nzcvq', nzcvqReg);
            writer.putPopRegs(clobberedRegs);

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const [dstOp, srcOp] = insn.operands;

          if (srcOp.type === 'mem') {
            const src = srcOp.value;

            if (src.base[0] === 'r' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              realImplReg = dstOp.value;
            }
          }

          break;
        }
        case 'blx':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('r0', 'r0', 4); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['r0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
    } while (!address.add(size).equals(end));

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc.or(1), 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm64 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      let insn;
      try {
        insn = Instruction.parse(current);
      } catch (e) {
        if (current.readU32() === 0x00000000) {
          reachedEndOfBlock = true;
          break;
        } else {
          throw e;
        }
      }
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'tbz':
        case 'tbnz':
          branchTarget = ptr(insn.operands[2].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new Arm64Writer(buffer, { pc });

  writer.putBLabel('performTransition');

  const invokeCallback = pc.add(writer.offset);
  writer.putPushAllXRegisters();
  writer.putCallAddressWithArguments(callback, ['x0']);
  writer.putPopAllXRegisters();
  writer.putRet();

  writer.putLabel('performTransition');

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new Arm64Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'tbz': {
          const ops = insn.operands;
          writer.putTbzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        case 'tbnz': {
          const ops = insn.operands;
          writer.putTbnzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str': {
          const ops = insn.operands;
          const srcReg = ops[0].value;
          const dstValue = ops[1].value;
          const dstOffset = dstValue.disp;

          if (srcReg === 'xzr' && dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            writer.putPushRegReg('x0', 'lr');
            writer.putMovRegReg('x0', threadReg);
            writer.putBlImm(invokeCallback);
            writer.putPopRegReg('x0', 'lr');

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const ops = insn.operands;

          const src = ops[1].value;
          if (src.base[0] === 'x' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            realImplReg = ops[0].value;
          }

          break;
        }
        case 'blr':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('x0', 'x0', 8); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['x0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function throwThreadStateTransitionParseError () {
  throw new Error('Unable to parse ART internals; please file a bug');
}

function fixupArtQuickDeliverExceptionBug (api) {
  const prettyMethod = api['art::ArtMethod::PrettyMethod'];
  if (prettyMethod === undefined) {
    return;
  }

  /*
   * There is a bug in art::Thread::QuickDeliverException() where it assumes
   * there is a Java stack frame present on the art::Thread's stack. This is
   * not the case if a native thread calls a throwing method like FindClass().
   *
   * We work around this bug here by detecting when method->PrettyMethod()
   * happens with method == nullptr.
   */
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}

function branchLabelFromOperand (op) {
  return ptr(op.value).toString();
}

function makeCxxMethodWrapperReturningPointerByValueGeneric (address, argTypes) {
  return new NativeFunction(address, 'pointer', argTypes, nativeFunctionOptions);
}

function makeCxxMethodWrapperReturningPointerByValueInFirstArg (address, argTypes) {
  const impl = new NativeFunction(address, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
  return function () {
    const resultPtr = Memory.alloc(pointerSize);
    impl(resultPtr, ...arguments);
    return resultPtr.readPointer();
  };
}

function makeCxxMethodWrapperReturningStdStringByValue (impl, argTypes) {
  const { arch } = Process;
  switch (arch) {
    case 'ia32':
    case 'arm64': {
      let thunk;
      if (arch === 'ia32') {
        thunk = makeThunk(64, writer => {
          const argCount = 1 + argTypes.length;
          const argvSize = argCount * 4;
          writer.putSubRegImm('esp', argvSize);
          for (let i = 0; i !== argCount; i++) {
            const offset = i * 4;
            writer.putMovRegRegOffsetPtr('eax', 'esp', argvSize + 4 + offset);
            writer.putMovRegOffsetPtrReg('esp', offset, 'eax');
          }
          writer.putCallAddress(impl);
          writer.putAddRegImm('esp', argvSize - 4);
          writer.putRet();
        });
      } else {
        thunk = makeThunk(32, writer => {
          writer.putMovRegReg('x8', 'x0');
          argTypes.forEach((t, i) => {
            writer.putMovRegReg('x' + i, 'x' + (i + 1));
          });
          writer.putLdrRegAddress('x7', impl);
          writer.putBrReg('x7');
        });
      }

      const invokeThunk = new NativeFunction(thunk, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      const wrapper = function (...args) {
        invokeThunk(...args);
      };
      wrapper.handle = thunk;
      wrapper.impl = impl;
      return wrapper;
    }
    default: {
      const result = new NativeFunction(impl, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      result.impl = impl;
      return result;
    }
  }
}

class StdString {
  constructor () {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }

  dispose () {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      getApi().$delete(data);
    }
  }

  disposeToString () {
    const result = this.toString();
    this.dispose();
    return result;
  }

  toString () {
    const [data] = this._getData();
    return data.readUtf8String();
  }

  _getData () {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * pointerSize).readPointer();
    return [data, isTiny];
  }
}

class StdVector {
  $delete () {
    this.dispose();
    getApi().$delete(this);
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

  dispose () {
    getApi().$delete(this.begin);
  }

  get begin () {
    return this._begin.readPointer();
  }

  set begin (value) {
    this._begin.writePointer(value);
  }

  get end () {
    return this._end.readPointer();
  }

  set end (value) {
    this._end.writePointer(value);
  }

  get storage () {
    return this._storage.readPointer();
  }

  set storage (value) {
    this._storage.writePointer(value);
  }

  get size () {
    return this.end.sub(this.begin).toInt32() / this._elementSize;
  }
}

export class HandleVector extends StdVector {
  static $new () {
    const vector = new HandleVector(getApi().$new(STD_VECTOR_SIZE));
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
      result.push(cur.readPointer());
      cur = cur.add(pointerSize);
    }

    return result;
  }
}

const BHS_OFFSET_LINK = 0;
const BHS_OFFSET_NUM_REFS = pointerSize;
const BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;

const kNumReferencesVariableSized = -1;

class BaseHandleScope {
  $delete () {
    this.dispose();
    getApi().$delete(this);
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

export class VariableSizedHandleScope extends BaseHandleScope {
  static $new (thread, vm) {
    const scope = new VariableSizedHandleScope(getApi().$new(VSHS_SIZE));
    scope.init(thread, vm);
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

  init (thread, vm) {
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
    const scope = new FixedSizeHandleScope(getApi().$new(layout.size), layout);
    scope.init();
    return scope;
  }

  constructor (storage, layout) {
    super(storage);

    const { offset } = layout;
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
      0xbf00 // nop
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
      0xd65f03c0 // ret
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

export function makeObjectVisitorPredicate (needle, onMatch) {
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

function alignPointerOffset (offset) {
  const remainder = offset % pointerSize;
  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }
  return offset;
}
