const memoize = require('./memoize');
const { checkJniResult } = require('./result');
const VM = require('./vm');

const jsizeSize = 4;
const { pointerSize } = Process;

const JNI_VERSION_1_8 = 0x00010008;
const JVM_ACC_NATIVE = 0x0100;
const JVM_ACC_IS_OLD = 0x00010000;
const JVM_ACC_IS_OBSOLETE = 0x00020000;
const JVMTI_VERSION_1_0 = 0x30010000;

const jvmtiCapabilities = {
  canTagObjects: 1
};

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const getJvmMethodSpec = memoize(_getJvmMethodSpec);

let cachedApi = null;

function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /jvm.(dll|dylib|so)$/.test(m.name));
  if (vmModules.length === 0) {
    return null;
  }

  const vmModule = vmModules[0];

  const temporaryApi = {
    flavor: 'jvm'
  };

  const pending = [{
    module: vmModule.path,
    functions: {
      JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

      _ZN6Method4sizeEb: ['Method::size', 'int', ['int']],
      _ZN6Method19set_native_functionEPhb: ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
      _ZN6Method21clear_native_functionEv: ['Method::clear_native_function', 'void', ['pointer']],
      _ZN6Method24restore_unshareable_infoEP6Thread: ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
      _ZN6Method10jmethod_idEv: ['Method::jmethod_id', 'pointer', ['pointer']],

      _ZNK5Klass15start_of_vtableEv: ['Klass::start_of_vtable', 'pointer', ['pointer']],
      _ZNK13InstanceKlass6vtableEv: ['InstanceKlass::vtable', 'pointer', ['pointer']],
      // JDK >= 13
      _ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass: ['VM_RedefineClasses::mark_dependent_code', 'void', ['pointer', 'pointer']],
      _ZN18VM_RedefineClasses20flush_dependent_codeEv: ['VM_RedefineClasses::flush_dependent_code', 'void', []],
      // JDK < 13
      _ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],
      // JDK < 10
      _ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],

      _ZN19ResolvedMethodTable21adjust_method_entriesEPb: ['ResolvedMethodTable::adjust_method_entries', 'void', ['pointer']],
      // JDK < 10
      _ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb: ['MemberNameTable::adjust_method_entries', 'void', ['pointer', 'pointer', 'pointer']],

      _ZN17ConstantPoolCache21adjust_method_entriesEPb: function (address) {
        const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
        this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
          adjustMethod(thisPtr, tracePtr);
        };
      },
      // JDK < 13
      _ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb: function (address) {
        const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
        this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
          adjustMethod(thisPtr, holderPtr, tracePtr);
        };
      },

      _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure: ['ClassLoaderDataGraph::classes_do', 'void', ['pointer']],

      _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_: ['JavaThread::thread_from_jni_environment', 'pointer', ['pointer']]
    },
    variables: {
      // JDK <= 9
      _ZN18VM_RedefineClasses14_the_class_oopE: function (address) {
        this.redefineClass = address;
      },
      // 9 < JDK < 13
      _ZN18VM_RedefineClasses10_the_classE: function (address) {
        this.redefineClass = address;
      },
      // JDK < 13
      _ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass: function (address) {
        this.doKlass = address;
      },
      // JDK >= 13
      _ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass: function (address) {
        this.doKlass = address;
      }
    },
    optionals: [
      '_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass',
      '_ZN18VM_RedefineClasses20flush_dependent_codeEv',
      '_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread',
      '_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread',

      '_ZNK5Klass15start_of_vtableEv',
      '_ZNK13InstanceKlass6vtableEv',

      '_ZN19ResolvedMethodTable21adjust_method_entriesEPb',
      '_ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb',

      '_ZN17ConstantPoolCache21adjust_method_entriesEPb',
      '_ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb',

      '_ZN18VM_RedefineClasses14_the_class_oopE',
      '_ZN18VM_RedefineClasses10_the_classE',
      '_ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass',
      '_ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass'
    ]
  }];

  const missing = [];

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    const tmp = Module
      .enumerateExports(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});

    const exportByName = Module
      .enumerateSymbols(api.module)
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, tmp);

    Object.keys(functions)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined) {
          const signature = functions[name];
          if (typeof signature === 'function') {
            signature.call(temporaryApi, exp.address);
          } else {
            temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions);
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
        if (exp !== undefined) {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });
  });

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

  temporaryApi.$new = new NativeFunction(Module.getExportByName(null, '_Znwm'), 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi.$delete = new NativeFunction(Module.getExportByName(null, '_ZdlPv'), 'void', ['pointer'], nativeFunctionOptions);

  temporaryApi.jvmti = getEnvJvmti(temporaryApi);

  return temporaryApi;
}

function getEnvJvmti (api) {
  const vm = new VM(api);

  let env;
  vm.perform(() => {
    const getEnv = new NativeFunction(vm.handle.readPointer().add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'],
      nativeFunctionOptions);
    const envBuf = Memory.alloc(pointerSize);
    let result = getEnv(vm.handle, envBuf, JVMTI_VERSION_1_0);
    checkJniResult('getEnvJvmti::GetEnv', result);
    env = new EnvJvmti(envBuf.readPointer(), vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    result = env.addCapabilities(capaBuf);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });

  return env;
}

function EnvJvmti (handle, vm) {
  this.handle = handle;
  this.vm = vm;
  this.vtable = handle.readPointer();
}

EnvJvmti.prototype.deallocate = proxy(47, 'int32', ['pointer', 'pointer'], function (impl, mem) {
  return impl(this.handle, mem);
});

EnvJvmti.prototype.getLoadedClasses = proxy(78, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, classCountPtr, classesPtr) {
  const result = impl(this.handle, classCountPtr, classesPtr);
  checkJniResult('EnvJvmti::getLoadedClasses', result);
});

EnvJvmti.prototype.iterateOverInstancesOfClass = proxy(112, 'int32', ['pointer', 'pointer', 'int', 'pointer', 'pointer'], function (impl, klass, objectFilter, heapObjectCallback, userData) {
  const result = impl(this.handle, klass, objectFilter, heapObjectCallback, userData);
  checkJniResult('EnvJvmti::iterateOverInstancesOfClass', result);
});

EnvJvmti.prototype.getObjectsWithTags = proxy(114, 'int32', ['pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer'], function (impl, tagCount, tags, countPtr, objectResultPtr, tagResultPtr) {
  const result = impl(this.handle, tagCount, tags, countPtr, objectResultPtr, tagResultPtr);
  checkJniResult('EnvJvmti::getObjectsWithTags', result);
});

EnvJvmti.prototype.addCapabilities = proxy(142, 'int32', ['pointer', 'pointer'], function (impl, capabilitiesPtr) {
  return impl(this.handle, capabilitiesPtr);
});

function proxy (offset, retType, argTypes, wrapper) {
  let impl = null;
  return function () {
    if (impl === null) {
      impl = new NativeFunction(this.vtable.add((offset - 1) * pointerSize).readPointer(), retType, argTypes, nativeFunctionOptions);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

function ensureClassInitialized (env, classRef) {
}

class JvmMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.method = methodId.readPointer();
    this.originalMethod = null;
    this.newMethod = null;
    this.resolved = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { method, methodId } = this;
    this.originalMethod = fetchJvmMethod(method, vm);
    this.newMethod = nativeJvmMethod(method, impl, vm);
    installJvmMethod(this.newMethod, methodId, vm);
  }

  revert (vm) {
    const { originalMethod, methodId } = this;
    revertJvmMethod(originalMethod);
    const revert = originalMethod.oldMethod;
    revert.oldMethod = this.newMethod;
    installJvmMethod(revert, methodId, vm);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const { resolved, originalMethod } = this;
    if (resolved !== null) {
      return resolved;
    }

    const vip = originalMethod.oldMethod.vtableIndexPtr;

    // Make old method final with nonvirtual_vtable_index = -2
    // so that we don't need a vtable entry when calling old method.
    vip.writeS32(-2);

    const jmethodID = Memory.alloc(pointerSize);
    jmethodID.writePointer(this.method);
    this.resolved = jmethodID;

    return jmethodID;
  }
}

function makeMethodMangler (methodId) {
  return new JvmMethodMangler(methodId);
}

function installJvmMethod (method, methodId, vm) {
  const { method: handle, oldMethod: old } = method;
  const api = getApi();
  const env = vm.getEnv();
  const thread = api['JavaThread::thread_from_jni_environment'](env.handle);

  // Replace position in methodsArray with new method.
  method.methodsArray.add(method.methodIndex * pointerSize).writePointer(handle);

  // Replace method handle in vtable
  if (method.vtableIndex >= 0) {
    method.vtable.add(method.vtableIndex * pointerSize).writePointer(handle);
  }

  // Replace jmethodID with new method.
  methodId.writePointer(handle);

  old.accessFlagsPtr.writeU32((old.accessFlags | JVM_ACC_IS_OLD | JVM_ACC_IS_OBSOLETE) >>> 0);

  // Deoptimize dependent code.
  const mark = api['VM_RedefineClasses::mark_dependent_code'];
  const flush = api['VM_RedefineClasses::flush_dependent_code'];
  if (mark !== undefined) {
    mark(NULL, method.instanceKlass);
    flush();
  } else {
    flush(NULL, method.instanceKlass, thread);
  }

  const traceNamePrinted = Memory.alloc(1);
  traceNamePrinted.writeU8(1);
  api['ConstantPoolCache::adjust_method_entries'](method.cache, method.instanceKlass, traceNamePrinted);

  const klassClosure = Memory.alloc(3 * pointerSize);
  const doKlassPtr = Memory.alloc(pointerSize);
  doKlassPtr.writePointer(api.doKlass);
  klassClosure.writePointer(doKlassPtr);
  klassClosure.add(pointerSize).writePointer(thread);
  klassClosure.add(2 * pointerSize).writePointer(thread);
  if (api.redefineClass !== undefined) {
    api.redefineClass.writePointer(method.instanceKlass);
  }
  api['ClassLoaderDataGraph::classes_do'](klassClosure);

  const rmtAdjustMethodEntries = api['ResolvedMethodTable::adjust_method_entries'];
  if (rmtAdjustMethodEntries !== undefined) {
    rmtAdjustMethodEntries(traceNamePrinted);
  } else {
    const { memberNames } = method;
    if (!memberNames.isNull()) {
      const mntAdjustMethodEntries = api['MemberNameTable::adjust_method_entries'];
      if (mntAdjustMethodEntries !== undefined) {
        mntAdjustMethodEntries(memberNames, method.instanceKlass, traceNamePrinted);
      }
    }
  }
}

function nativeJvmMethod (method, impl, vm) {
  const api = getApi();

  const newMethod = fetchJvmMethod(method, vm);
  newMethod.constPtr.writePointer(newMethod.const);
  newMethod.accessFlagsPtr.writeU32((newMethod.accessFlags | JVM_ACC_NATIVE) >>> 0);
  newMethod.signatureHandler.writePointer(NULL);
  newMethod.adapter.writePointer(NULL);
  newMethod.i2iEntry.writePointer(NULL);

  // clear_native_function will also clear _from_compiled_entry
  // and _from_interpreted_entry
  api['Method::clear_native_function'](newMethod.method);
  api['Method::set_native_function'](newMethod.method, impl, 0);

  // Link method (Method::link_method)
  const env = vm.getEnv();
  const thread = api['JavaThread::thread_from_jni_environment'](env.handle);
  api['Method::restore_unshareable_info'](newMethod.method, thread);

  return newMethod;
}

function fetchJvmMethod (method, vm) {
  const spec = getJvmMethodSpec(vm);
  const constMethod = method.add(spec.method.constMethodOffset).readPointer();
  const constMehtodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize;
  const newConstMethod = Memory.alloc(constMehtodSize + spec.method.size);
  Memory.copy(newConstMethod, constMethod, constMehtodSize);
  const newMethod = newConstMethod.add(constMehtodSize);
  Memory.copy(newMethod, method, spec.method.size);
  const result = readJvmMethod(newMethod, newConstMethod, constMehtodSize, vm);
  const oldMethod = readJvmMethod(method, constMethod, constMehtodSize, vm);
  result.oldMethod = oldMethod;
  return result;
}

function readJvmMethod (method, constMethod, constMehtodSize, vm) {
  const api = getApi();
  const spec = getJvmMethodSpec(vm);

  const constPtr = method.add(spec.method.constMethodOffset);
  const accessFlagsPtr = method.add(spec.method.accessFlagsOffset);
  const accessFlags = accessFlagsPtr.readU32();
  const adapter = spec.getAdapterPointer(method, constMethod);
  const i2iEntry = method.add(spec.method.i2iEntryOffset);
  const signatureHandler = method.add(spec.method.signatureHandlerOffset);

  const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
  const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();
  const cache = constantPool.add(spec.constantPool.cacheOffset).readPointer();

  if (spec.instanceKlass.vtableOffset === 0) {
    const klassVtable = api['InstanceKlass::vtable'](instanceKlass);
    const vtableOffset = klassVtable.add(pointerSize).readS32();
    spec.instanceKlass.vtableOffset = vtableOffset;
    spec.instanceKlass.methodsOffset = vtableOffset - (7 * pointerSize);
    spec.instanceKlass.memberNamesOffset = vtableOffset - (17 * pointerSize);
  }

  const methods = instanceKlass.add(spec.instanceKlass.methodsOffset).readPointer();
  const methodsCount = methods.readS32();
  const methodsArray = methods.add(pointerSize);
  const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
  const vtableIndexPtr = method.add(spec.method.vtableIndexOffset);
  const vtableIndex = vtableIndexPtr.readS32();
  const vtable = instanceKlass.add(spec.instanceKlass.vtableOffset);
  const memberNames = instanceKlass.add(spec.instanceKlass.memberNamesOffset).readPointer();

  return {
    method: method,
    methodSize: spec.method.size,
    const: constMethod,
    constSize: constMehtodSize,
    constPtr,
    instanceKlass,
    methodsArray,
    methodsCount,
    methodIndex,
    vtableIndex,
    vtableIndexPtr,
    vtable,
    accessFlags,
    accessFlagsPtr,
    adapter,
    i2iEntry,
    signatureHandler,
    memberNames,
    cache
  };
}

function revertJvmMethod (method) {
  Memory.copy(method.oldMethod.const, method.const, method.constSize);
  Memory.copy(method.oldMethod.method, method.method, method.methodSize);
}

function _getJvmMethodSpec (vm) {
  const api = getApi();

  let spec;
  vm.perform(() => {
    const env = vm.getEnv();
    const version = env.getVersion();
    const adapterInConstMethod = (version > JNI_VERSION_1_8) ? 1 : 0;

    const isNative = 1;
    const methodSize = api['Method::size'](isNative) * pointerSize;
    const constMethodOffset = pointerSize;
    const accessFlagsOffset = 4 * pointerSize;
    const vtableIndexOffset = accessFlagsOffset + 4;
    const i2iEntryOffset = vtableIndexOffset + 4 + pointerSize;
    const nativeFunctionOffset = methodSize - 2 * pointerSize;
    const signatureHandlerOffset = methodSize - pointerSize;

    const constantPoolOffset = pointerSize;
    const constMethodSizeOffset = (3 + adapterInConstMethod) * pointerSize;
    const methodIdnumOffset = constMethodSizeOffset + 0xe;

    const cacheOffset = 2 * pointerSize;
    const instanceKlassOffset = 3 * pointerSize;
    let vtableOffset = 0;
    let methodsOffset = 0;
    let memberNamesOffset = 0;
    if ('Klass::start_of_vtable' in api) {
      vtableOffset = api['Klass::start_of_vtable'](NULL).toInt32();
      methodsOffset = vtableOffset - (7 * pointerSize);
      memberNamesOffset = vtableOffset - (17 * pointerSize);
    }

    const getAdapterPointer = adapterInConstMethod
      ? function (method, constMethod) {
        return constMethod.add(constantPoolOffset + 2 * pointerSize);
      } : function (method, constMethod) {
        return method.add(i2iEntryOffset + pointerSize);
      };

    spec = {
      getAdapterPointer: getAdapterPointer,
      method: {
        size: methodSize,
        constMethodOffset,
        accessFlagsOffset,
        vtableIndexOffset,
        i2iEntryOffset,
        nativeFunctionOffset,
        signatureHandlerOffset
      },
      constMethod: {
        constantPoolOffset,
        sizeOffset: constMethodSizeOffset,
        methodIdnumOffset
      },
      constantPool: {
        cacheOffset,
        instanceKlassOffset
      },
      instanceKlass: {
        vtableOffset,
        methodsOffset,
        memberNamesOffset
      }
    };
  });
  return spec;
}

function deoptimizeEverything (vm, env) {
}

module.exports = {
  getApi,
  ensureClassInitialized,
  makeMethodMangler,
  deoptimizeEverything
};
