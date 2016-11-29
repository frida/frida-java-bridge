'use strict';

/* global Memory, Module, NativeFunction, Process */

const {checkJniResult} = require('./result');

let cachedApi = null;
let cachedVersion = null;

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;

function getApi () {
  if (cachedApi !== null) {
    return cachedApi;
  }

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

  if (remaining === 0) {
    const vms = Memory.alloc(pointerSize);
    const vmCount = Memory.alloc(jsizeSize);
    checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
    if (Memory.readInt(vmCount) === 0) {
      return null;
    }
    temporaryApi.vm = Memory.readPointer(vms);

    cachedApi = temporaryApi;
  }

  return cachedApi;
}

function getAndroidVersion (classFactory) {
  if (cachedVersion === null) {
    const SystemProperties = classFactory.use('android.os.SystemProperties');
    cachedVersion = SystemProperties.get('ro.build.version.release', 'unknown');
  }

  return cachedVersion;
}

const getRuntimeSpec = resolveStructSpec.bind({
  '5.0.': {
    4: {
      // size: 680, // unsure
      offset: {
        classLinker: 208
      }
    }
  },
  '6.0.': {
    4: {
      offset: {
        classLinker: 236
      }
    }
  }
});

const getClassLinkerSpec = resolveStructSpec.bind({
  '5.0.': {
    4: {
      size: 228,
      offset: {
        portableResolutionTrampoline: 208,
        quickResolutionTrampoline: 212,
        portableImConflictTrampoline: 216,
        quickImtConflictTrampoline: 220,
        quickGenericJniTrampoline: 224
      }
    }
  },
  '6.0.': {
    4: {
      offset: {
        quickGenericJniTrampoline: 296
      }
    }
  }
});

const getArtMethodSpec = resolveStructSpec.bind({
  '5.0.': {
    4: {
      size: 72,
      offset: {
        klass: 0,
        monitor: 4,
        declaringClass: 8,
        dexCacheResolvedMethods: 12,
        dexCacheResolvedTypes: 16,
        dexCacheStrings: 20,
        interpreterCode: 24,
        jniCode: 32,
        quickCode: 40,
        gcMap: 48,
        accessFlags: 56,
        dexItemIndex: 60,
        dexMethodIndex: 64,
        index: 68
      }
    },
    8: {
      size: 72,
      offset: {
        klass: 0,
        monitor: 4,
        declaringClass: 8,
        dexCacheResolvedMethods: 12,
        dexCacheResolvedTypes: 16,
        dexCacheStrings: 20,
        interpreterCode: 24,
        jniCode: 32,
        quickCode: 40,
        gcMap: 48,
        accessFlags: 56,
        dexItemIndex: 60,
        dexMethodIndex: 64,
        index: 68
      }
    }
  },
  '5.1.': {
    4: {
      size: 48,
      offset: {
        jniCode: 40,
        quickCode: 44,
        accessFlags: 20,
        dexItemIndex: 24,
        dexMethodIndex: 28,
        index: 32
      }
    },
    8: {
      size: 60,
      offset: {
        jniCode: 44,
        quickCode: 52,
        accessFlags: 20,
        dexItemIndex: 24,
        dexMethodIndex: 28,
        index: 32
      }
    }
  },
  '6.0.': {
    4: {
      size: 40,
      offset: {
        interpreterCode: 28,
        jniCode: 32,
        quickCode: 36,
        accessFlags: 12,
        dexItemIndex: 16,
        dexMethodIndex: 20,
        index: 24
      }
    },
    8: {
      size: 52,
      offset: {
        interpreterCode: 28,
        jniCode: 36,
        quickCode: 44,
        accessFlags: 12,
        dexItemIndex: 16,
        dexMethodIndex: 20,
        index: 24
      }
    }
  },
  git: {
    4: {
      size: 36,
      offset: {
        jniCode: 28,
        quickCode: 32,
        accessFlags: 4,
        dexItemIndex: 8,
        dexMethodIndex: 12,
        index: 16
      }
    },
    8: {
      size: 52,
      offset: {
        jniCode: 36,
        quickCode: 44,
        accessFlags: 4,
        dexItemIndex: 8,
        dexMethodIndex: 12,
        index: 16
      }
    }
  },
  _default: function (vm) {
    let _artMethodSpec;

    vm.perform(() => {
      const env = vm.getEnv();
      const process = env.findClass('android/os/Process');
      const setArgV0 = env.getStaticMethodId(process, 'setArgV0', '(Ljava/lang/String;)V');

      const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
      const runtimeStart = runtimeModule.base;
      const runtimeEnd = runtimeStart.add(runtimeModule.size);

      const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;

      let jniCodeOffset = null;
      let accessFlagsOffset = null;
      let remaining = 2;
      for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
        const field = setArgV0.add(offset);

        if (jniCodeOffset === null && offset % pointerSize === 0) {
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

      const isMarshmallowOrNewer = accessFlagsOffset < jniCodeOffset;

      const size = isMarshmallowOrNewer
        ? (jniCodeOffset + (2 * pointerSize))
        : (accessFlagsOffset + 16);

      _artMethodSpec = {
        size: size,
        offset: {
          interpreterCode: jniCodeOffset - pointerSize,
          jniCode: jniCodeOffset,
          quickCode: jniCodeOffset + pointerSize,
          accessFlags: accessFlagsOffset
        }
      };
    });

    return _artMethodSpec;
  }
});

function resolveStructSpec (vm, classFactory) {
  if (this._current !== undefined) {
    return this._current;
  }

  let specByPointerSize = this[getAndroidVersion(classFactory).substr(0, 4)];
  if (specByPointerSize === undefined) {
    if (this._default) {
      try {
        const spec = this._default(vm);
        this._current = spec;
        return spec;
      } catch (e) {}
    }
    specByPointerSize = this.git;
  }

  this._current = specByPointerSize && specByPointerSize[Process.pointerSize];
  return this._current;
}

module.exports = {
  getApi,
  getAndroidVersion,
  getRuntimeSpec,
  getClassLinkerSpec,
  getArtMethodSpec
};
