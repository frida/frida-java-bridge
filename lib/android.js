'use strict';

/* global Interceptor, Memory, Module, NativeCallback, NativeFunction, NULL, ptr, Process */

const {checkJniResult} = require('./result');

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;

const STD_STRING_SIZE = (pointerSize === 4) ? 12 : 24;

const getApi = memoize(_getApi);
const getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
const getArtClassLinkerSpec = memoize(_getArtClassLinkerSpec);
const getAndroidApiLevel = memoize(_getAndroidApiLevel);

function _getApi () {
  const flavor = (Process.findModuleByName('libart.so') !== null) ? 'art' : 'dalvik';
  const isArt = flavor === 'art';

  const temporaryApi = {
    addLocalReference: null,
    flavor: flavor
  };

  const pending = isArt ? [{
    module: 'libart.so',
    functions: {
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],
      'artInterpreterToCompiledCodeBridge': function (address) {
        this.artInterpreterToCompiledCodeBridge = address;
      }
    },
    variables: {
      '_ZN3art7Runtime9instance_E': function (address) {
        this.artRuntime = Memory.readPointer(address);
      }
    }
  }] : [{
    module: 'libdvm.so',
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

  let remaining = 0;

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    remaining += Object.keys(functions).length + Object.keys(variables).length;

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
          remaining--;
        } else {
          if (optionals.has(name)) {
            remaining--;
          }
        }
      });

    Object.keys(variables)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined && exp.type === 'variable') {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
          remaining--;
        }
      });
  });

  if (remaining > 0) {
    return null;
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (Memory.readInt(vmCount) === 0) {
    return null;
  }
  temporaryApi.vm = Memory.readPointer(vms);

  if (isArt) {
    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */
    const classLinker = Memory.readPointer(temporaryApi.artRuntime.add(getArtRuntimeSpec(temporaryApi).offset.classLinker));
    temporaryApi.artClassLinker = classLinker;
    temporaryApi.artQuickGenericJniTrampoline = Memory.readPointer(classLinker.add(getArtClassLinkerSpec(temporaryApi).offset.quickGenericJniTrampoline));
  }

  return temporaryApi;
}

function _getArtRuntimeSpec (api) {
  /*
   * class Runtime {
   * ...
   * InternTable* intern_table_;      <-- we need to find these
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * std::string stack_trace_file_;
   * JavaVMExt* java_vm_;             <-- we find this then calculate our way backwards
   * ...
   * }
   */

  const vm = api.vm;
  const runtime = api.artRuntime;

  const startOffset = (pointerSize === 4) ? 200 : 384;
  const endOffset = startOffset + (100 * pointerSize);

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = Memory.readPointer(runtime.add(offset));
    if (value.equals(vm)) {
      const classLinkerOffset = offset - STD_STRING_SIZE - (2 * pointerSize);
      spec = {
        offset: {
          internTable: classLinkerOffset - pointerSize,
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

  const startOffset = (pointerSize === 4) ? 200 : 400;
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
  let spec;

  vm.perform(() => {
    const env = vm.getEnv();
    const process = env.findClass('android/os/Process');
    const setArgV0 = env.getStaticMethodId(process, 'setArgV0', '(Ljava/lang/String;)V');

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const entrypointFieldSize = (getAndroidApiLevel() <= 21) ? 8 : pointerSize;

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

    spec = {
      size: probeArtMethodSize(),
      offset: {
        interpreterCode: jniCodeOffset - entrypointFieldSize,
        jniCode: jniCodeOffset,
        quickCode: jniCodeOffset + entrypointFieldSize,
        accessFlags: accessFlagsOffset
      }
    };
  });

  return spec;
}

function probeArtMethodSize () {
  let result = -1;

  const allocArtMethodArray = new NativeFunction(Module.findExportByName('libart.so', '_ZN3art11ClassLinker19AllocArtMethodArrayEPNS_6ThreadEj'), 'pointer', ['pointer', 'pointer', 'pointer']);
  const allocSignature = {
    retType: 'pointer',
    argTypes: ['pointer', 'pointer', 'pointer']
  };
  const allocImpl = new NativeFunction(Module.findExportByName('libart.so', '_ZN3art11LinearAlloc5AllocEPNS_6ThreadEj'), allocSignature.retType, allocSignature.argTypes);

  const proberThread = Process.getCurrentThreadId();

  Interceptor.replace(allocImpl, new NativeCallback(function (self, thread, rawSize) {
    if (Process.getCurrentThreadId() === proberThread) {
      const size = rawSize.toInt32();
      result = size;
      return Memory.alloc(size);
    }

    return allocImpl(self, thread, rawSize);
  }, allocSignature.retType, allocSignature.argTypes));
  Interceptor.flush();

  allocArtMethodArray(getApi().artClassLinker, NULL, ptr(1));

  Interceptor.revert(allocImpl);
  Interceptor.flush();

  return result;
}

const systemPropertyGet = new NativeFunction(Module.findExportByName('libc.so', '__system_property_get'), 'int', ['pointer', 'pointer']);
const PROP_VALUE_MAX = 92;

function _getAndroidVersion () {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidApiLevel () {
  return parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

function getAndroidSystemProperty (name) {
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return Memory.readUtf8String(buf);
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
  getApi: getApi,
  getAndroidVersion: memoize(_getAndroidVersion),
  getAndroidApiLevel: getAndroidApiLevel,
  getArtMethodSpec: memoize(_getArtMethodSpec)
};
