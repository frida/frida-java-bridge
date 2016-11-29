'use strict';

/* global Memory, Module, NativeFunction, Process */

const {checkJniResult} = require('./result');

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;

const STD_STRING_SIZE = (pointerSize === 4) ? 12 : 24;

function getApi () {
  const temporaryApi = {
    addLocalReference: null,
    flavor: Process.findModuleByName('libart.so') !== null ? 'art' : 'dalvik'
  };

  const pending = temporaryApi.flavor === 'art' ? [{
    module: 'libart.so',
    functions: {
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],
      'artInterpreterToCompiledCodeBridge': function (address) {
        this.artInterpreterToCompiledCodeBridge = address;
      },
      '_ZN3art6Thread14CurrentFromGdbEv': ['art::Thread::CurrentFromGdb', 'pointer', []],
      '_ZNK3art6Thread13DecodeJObjectEP8_jobject': ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadE': ['art::mirror::Object::Clone', 'pointer', ['pointer', 'pointer']]
    },
    variables: {
      '_ZN3art7Runtime9instance_E': function (address) {
        this.runtime_instance_ptr = address;
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
    const optionals = api.optionals || {};

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
          const optional = optionals[name];
          if (optional) {
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

  return temporaryApi;
}

function getAndroidVersion (classFactory) {
  const SystemProperties = classFactory.use('android.os.SystemProperties');
  return SystemProperties.get('ro.build.version.release', 'unknown');
}

function getArtRuntimeSpec () {
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

  const api = getApi();
  const vm = api.vm;

  const runtime = Memory.readPointer(api.runtime_instance_ptr);

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

function getArtClassLinkerSpec (vm, classFactory) {
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

  const api = getApi();

  const runtime = Memory.readPointer(api.runtime_instance_ptr);
  const runtimeSpec = getArtRuntimeSpec();

  const classLinker = Memory.readPointer(runtime.add(runtimeSpec.offset.classLinker));
  const internTable = Memory.readPointer(runtime.add(runtimeSpec.offset.internTable));

  const startOffset = (pointerSize === 4) ? 200 : 400;
  const endOffset = startOffset + (100 * pointerSize);

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = Memory.readPointer(classLinker.add(offset));
    if (value.equals(internTable)) {
      const version = getAndroidVersion(classFactory).split('.');
      const majorVersion = parseInt(version[0], 10);
      const delta = (majorVersion >= 6) ? 3 : 5;

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

function getArtMethodSpec (vm, classFactory) {
  let spec;

  vm.perform(() => {
    const env = vm.getEnv();
    const process = env.findClass('android/os/Process');
    const setArgV0 = env.getStaticMethodId(process, 'setArgV0', '(Ljava/lang/String;)V');

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const version = getAndroidVersion(classFactory).split('.');
    const majorVersion = parseInt(version[0], 10);
    const minorVersion = parseInt(version[1], 10);
    const isLollipopOrBelow = ((majorVersion === 5 && minorVersion === 0) || majorVersion < 5);

    const entrypointFieldSize = isLollipopOrBelow ? 8 : pointerSize;

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

function memoize(compute) {
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
  getApi: memoize(getApi),
  getAndroidVersion: memoize(getAndroidVersion),
  getArtRuntimeSpec: memoize(getArtRuntimeSpec),
  getArtClassLinkerSpec: memoize(getArtClassLinkerSpec),
  getArtMethodSpec: memoize(getArtMethodSpec)
};
