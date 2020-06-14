const {checkJniResult} = require('./result');
const VM = require('./vm');

const jsizeSize = 4;
const pointerSize = Process.pointerSize;
const JNI_VERSION_1_8 = 0x00010008;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const JVM_ACC_NATIVE = 0x0100;
const JVM_ACC_IS_OLD = 0x00010000;
const JVM_ACC_IS_OBSOLETE = 0x00020000;

const JVMTI_VERSION_1_0 = 0x30010000;
const JVMTI_HEAP_OBJECT_EITHER = 3;
const jvmtiCapabilities = {
  'can_tag_objects' : 1,                                      // since 1.0
  'can_generate_field_modification_events' : 2,
  'can_generate_field_access_events' : 4,
  'can_get_bytecodes' : 8,
  'can_get_synthetic_attribute' : 10,
  'can_get_owned_monitor_info' : 20,
  'can_get_current_contended_monitor' : 40,
  'can_get_monitor_info' : 80,
  'can_pop_frame' : 100,
  'can_redefine_classes' : 200,
  'can_signal_thread' : 400,
  'can_get_source_file_name' : 800,
  'can_get_line_numbers' : 1000,
  'can_get_source_debug_extension' : 2000,
  'can_access_local_variables' : 4000,
  'can_maintain_original_method_order' : 8000,
  'can_generate_single_step_events' : 10000,
  'can_generate_exception_events' : 20000,
  'can_generate_frame_pop_events' : 40000,
  'can_generate_breakpoint_events' : 80000,
  'can_suspend' : 100000,
  'can_redefine_any_class' : 200000,
  'can_get_current_thread_cpu_time' : 400000,
  'can_get_thread_cpu_time' : 800000,
  'can_generate_method_entry_events' : 1000000,
  'can_generate_method_exit_events' : 2000000,
  'can_generate_all_class_hook_events' : 4000000,
  'can_generate_compiled_method_load_events' : 8000000,
  'can_generate_monitor_events' : 10000000,
  'can_generate_vm_object_alloc_events' : 20000000,
  'can_generate_native_method_bind_events' : 40000000,
  'can_generate_garbage_collection_events' : 80000000,
  'can_generate_object_free_events' : 100000000,
  'can_force_early_return' : 200000000,                       // since 1.1
  'can_get_owned_monitor_stack_depth_info' : 400000000,
  'can_get_constant_pool' : 800000000,
  'can_set_native_method_prefix' : 1000000000,
  'can_retransform_classes' : 2000000000,
  'can_retransform_any_class' : 4000000000,
  'can_generate_resource_exhaustion_heap_events' : 8000000000,
  'can_generate_resource_exhaustion_threads_events' : 10000000000,
  'can_generate_early_vmstart' : 20000000000,                 // since 9
  'can_generate_early_class_hook_events' : 40000000000,
  'can_generate_sampled_object_alloc_events' : 80000000000,   // since 11
}

const getJvmMethodSpec = memoize(_getJvmMethodSpec);
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

let cachedApi = null;
let MethodMangler = null;
const patchedClasses = new Map();

function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /jvm.(dylib|dll|so)$/.test(m.name));
  if (vmModules.length === 0) {
    return null;
  }

  const vmModule = vmModules[0];

  const flavor = 'jvm';

  const temporaryApi = {
    flavor: flavor,
    addLocalReference: null
  };

  const pending = [{
    module: vmModule.path,
    functions: {
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

      '_ZN6Method4sizeEb' : ['Method::size', 'int', ['int']],
      '_ZN6Method19set_native_functionEPhb' : ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
      '_ZN6Method21clear_native_functionEv' : ['Method::clear_native_function', 'void', ['pointer']],
      '_ZN6Method24restore_unshareable_infoEP6Thread' : ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
      '_ZN6Method10jmethod_idEv' : ['Method::jmethod_id', 'pointer', ['pointer']],

      '_ZNK5Klass15start_of_vtableEv' : ['Klass::start_of_vtable', 'pointer', ['pointer']],
      '_ZNK13InstanceKlass6vtableEv' : ['InstanceKlass::vtable', 'pointer', ['pointer']],
      // jdk >= 13
      '_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass' : ['VM_RedefineClasses::mark_dependent_code', 'void', ['pointer', 'pointer']],
      '_ZN18VM_RedefineClasses20flush_dependent_codeEv' : ['VM_RedefineClasses::flush_dependent_code', 'void', []],
      // jdk < 13
      '_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread' : ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],
      // jdk < 10
      '_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread' : ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],

      '_ZN19ResolvedMethodTable21adjust_method_entriesEPb' : ['ResolvedMethodTable::adjust_method_entries', 'void', ['pointer']],
      '_ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_' : ['JavaThread::thread_from_jni_environment', 'pointer', ['pointer']],
    },
    variables: {
    },
    optionals: [
      '_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass',
      '_ZN18VM_RedefineClasses20flush_dependent_codeEv',
      '_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread',
      '_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread',

      '_ZNK5Klass15start_of_vtableEv',
      '_ZNK13InstanceKlass6vtableEv',

      '_ZN19ResolvedMethodTable21adjust_method_entriesEPb'
    ]
  }];

  const missing = [];
  let total = 0;

  pending.forEach(function (api) {
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    total += Object.keys(functions).length + Object.keys(variables).length;

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

  temporaryApi['$new'] = new NativeFunction(Module.getExportByName(null, '_Znwm'), 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi['$delete'] = new NativeFunction(Module.getExportByName(null, '_ZdlPv'), 'void', ['pointer'], nativeFunctionOptions);

  MethodMangler = JvmMethodMangler;

  temporaryApi.jvmti = getEnvJvmti(temporaryApi);

  return temporaryApi;
}

function EnvJvmti (handle, vm) {
  this.handle = handle;
  this.vm = vm;
  this.vtable = handle.readPointer();
  this.globalRefs = [];
}

EnvJvmti.prototype._register = function (globalRef) {
  if (globalRef !== null && !globalRef.isNull()) {
    this.globalRefs.push(globalRef);
  }
  return globalRef;
}

EnvJvmti.prototype._dispose = function () {
  this.vm.perform(() => {
    this.globalRefs.forEach(this.deallocate, this);
    this.globalRefs = [];
  });
};

function getEnvJvmti (api) {
  const vm = new VM(api);
  let env;
  vm.perform(() => {
    const getEnv = new NativeFunction(vm.handle.readPointer().add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'], nativeFunctionOptions);
    const envBuf = Memory.alloc(pointerSize);
    let result = getEnv(vm.handle, envBuf, JVMTI_VERSION_1_0);
    checkJniResult('getEnvJvmti::GetEnv', result);
    env = new EnvJvmti(envBuf.readPointer(), vm);

    const capaPoint = Memory.alloc(8);
    const capa = jvmtiCapabilities.can_tag_objects;
    capaPoint.writeU64(capa);
    result = env.addCapabilities(capaPoint);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });

  WeakRef.bind(env, () => { env._dispose(); });
  return env;
};

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

EnvJvmti.prototype.deallocate = proxy(47, 'int32', ['pointer', 'pointer'], function (impl, mem) {
  return impl(this.handle, mem);
});

EnvJvmti.prototype.addCapabilities = proxy(142, 'int32', ['pointer', 'pointer'], function (impl, capabilities_ptr) {
  return impl(this.handle, capabilities_ptr);
});

EnvJvmti.prototype.getLoadedClasses = proxy(78, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, class_count_ptr, classes_ptr) {
  const result = impl(this.handle, class_count_ptr, classes_ptr);
  checkJniResult('EnvJvmti::getLoadedClasses', result);
  this._register(classes_ptr.readPointer());
  return result;
});

EnvJvmti.prototype.getClassLoaderClasses = proxy(79, 'int32', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, initiating_loader, class_count_ptr, classes_ptr) {
  const result = impl(this.handle, initiating_loader, class_count_ptr, classes_ptr);
  checkJniResult('EnvJvmti::getClassLoaderClasses', result);
  this._register(classes_ptr.readPointer());
  return result;
});

EnvJvmti.prototype.iterateOverInstancesOfClass = proxy(112, 'int32', ['pointer', 'pointer', 'int', 'pointer', 'pointer'], function (impl, klass, object_filter, heap_object_callback, user_data) {
  const result = impl(this.handle, klass, object_filter, heap_object_callback, user_data);
  checkJniResult('EnvJvmti::iterateOverInstancesOfClass', result);
  return result;
});

EnvJvmti.prototype.getObjectsWithTags = proxy(114, 'int32', ['pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer'], function (impl, tag_count, tags, count_ptr, object_result_ptr, tag_result_ptr) {
  const result = impl(this.handle, tag_count, tags, count_ptr, object_result_ptr, tag_result_ptr);
  checkJniResult('EnvJvmti::getObjectsWithTags', result);
  if (!object_result_ptr.isNull()) this._register(object_result_ptr.readPointer());
  if (!tag_result_ptr.isNull()) this._register(tag_result_ptr.readPointer());
  return result;
});

function ensureClassInitialized (env, classRef) {
  return;
}

function makeMethodMangler (methodId) {
  return new MethodMangler(methodId);
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
    const {method, methodId} = this;
    this.originalMethod = fetchJvmMethod(method, vm);
    this.newMethod = nativeJvmMethod(method, impl, vm);
    installJvmMethod(this.newMethod, this.newMethod.method, methodId, vm);
  }

  revert (vm) {
    const {originalMethod, methodId} = this;
    revertJvmMethod(originalMethod);
    installJvmMethod(originalMethod, this.method, methodId, vm);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const {originalMethod, resolved} = this;
    if (resolved !== null) {
      return resolved;
    }
    const spec = getJvmMethodSpec(env.vm);
    // make old method final with nonvirtual_vtable_index = -2
    // so that we don't need a vtable entry when calling old method
    this.method.add(spec.method.vtableIndexOffset).writeS32(-2);
    // // unique methodID for old method so new jmethodID is generated
    // const constMethod = originalMethod.oldConstHandle;
    // const id = originalMethod.methodIndex + originalMethod.methodsCount;
    // constMethod.add(spec.constMethod.methodIdnumOffset).writeU16(id);
    // const jmethodID = api['Method::jmethod_id'](this.method);

    const jmethodID = Memory.alloc(pointerSize);
    jmethodID.writePointer(this.method);
    this.resolved = jmethodID;
    return jmethodID;
  }
}

function installJvmMethod (method, handle, methodId, vm) {
  const api = getApi();
  // replace position in methodsArray with new method
  method.methodsArray.add(method.methodIndex * pointerSize).writePointer(handle);
  // replace method handle in vtable
  if (method.vtableIndex >= 0) {
    method.vtable.add(method.vtableIndex * pointerSize).writePointer(handle);
  }
  // replace jmethodID with new method
  methodId.writePointer(handle);
  // deoptimize dependent code
  if ('VM_RedefineClasses::mark_dependent_code' in api) {
    api['VM_RedefineClasses::mark_dependent_code'](NULL, method.instanceKlass);
    api['VM_RedefineClasses::flush_dependent_code']();
  } else {
    const env = vm.getEnv();
    const thread = api['JavaThread::thread_from_jni_environment'](env.handle);
    api['VM_RedefineClasses::flush_dependent_code'](NULL, method.instanceKlass, thread);
  }
  // // klassVtable::adjust_method_entries
  // const trace_name_printed = Memory.alloc(pointerSize);
  // trace_name_printed.writePointer(NULL);
  // api['ResolvedMethodTable::adjust_method_entries'](trace_name_printed);
}

function nativeJvmMethod (method, impl, vm) {
  const api = getApi();
  const newMethod = fetchJvmMethod(method, vm);
  newMethod.constPointer.writePointer(newMethod.const);
  newMethod.accessFlagsPointer.writeU32((newMethod.accessFlags | JVM_ACC_NATIVE) >>> 0);
  newMethod.signatureHandler.writePointer(NULL);
  newMethod.adapter.writePointer(NULL);
  newMethod.i2iEntry.writePointer(NULL);
  // clear_native_function will also clear _from_compiled_entry
  // and _from_interpreted_entry
  api['Method::clear_native_function'](newMethod.method);
  api['Method::set_native_function'](newMethod.method, impl, 0);
  // link method Method::link_method
  const env = vm.getEnv();
  const thread = api['JavaThread::thread_from_jni_environment'](env.handle);
  api['Method::restore_unshareable_info'](newMethod.method, thread);
  return newMethod;
}

function fetchJvmMethod (method, vm) {
  const api = getApi();
  const spec = getJvmMethodSpec(vm);
  const constMethod = method.add(spec.method.constMethodOffset).readPointer();
  const constMehtodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize;
  const newConstMethod = Memory.alloc(constMehtodSize + spec.method.size);
  Memory.copy(newConstMethod, constMethod, constMehtodSize);
  const newMethod = newConstMethod.add(constMehtodSize);
  Memory.copy(newMethod, method, spec.method.size);

  const constPointer = newMethod.add(spec.method.constMethodOffset);
  const accessFlagsPointer = newMethod.add(spec.method.accessFlagsOffset);
  const accessFlags = accessFlagsPointer.readU32();
  const adapter = spec.getAdapterPointer(newMethod, newConstMethod);
  const i2iEntry = newMethod.add(spec.method.i2iEntryOffset);
  const signatureHandler = newMethod.add(spec.method.signatureHandlerOffset);

  const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
  const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();

  if (spec.instanceKlass.vtableOffset === 0) {
    const klassVtable = api['InstanceKlass::vtable'](instanceKlass);
    const vtableOffset = klassVtable.add(pointerSize).readS32();
    spec.instanceKlass.vtableOffset = vtableOffset;
    spec.instanceKlass.methodsOffset = vtableOffset - (7 * pointerSize);
  }

  const methods = instanceKlass.add(spec.instanceKlass.methodsOffset).readPointer();
  const methodsCount = methods.readS32();
  const methodsArray = methods.add(pointerSize);
  const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
  const vtableIndex = method.add(spec.method.vtableIndexOffset).readS32();
  const vtable = instanceKlass.add(spec.instanceKlass.vtableOffset);

  return {
    method: newMethod,
    methodSize: spec.method.size,
    oldMethodHandle: method,
    const: newConstMethod,
    constSize: constMehtodSize,
    oldConstHandle: constMethod,
    constPointer,
    instanceKlass,
    methodsArray,
    methodsCount,
    methodIndex,
    vtableIndex,
    vtable,
    accessFlags,
    accessFlagsPointer,
    adapter,
    i2iEntry,
    signatureHandler
  }
}

function revertJvmMethod (method) {
  Memory.copy(method.oldConstHandle, method.const, method.constSize);
  Memory.copy(method.oldMethodHandle, method.method, method.methodSize);
}

function _getJvmMethodSpec (vm) {
  const api = getApi();
  let spec;
  vm.perform(() => {
    const env = vm.getEnv();
    const version = env.getVersion();
    const adapterInConstMethod = (version > JNI_VERSION_1_8) ? 1 : 0;

    const methodSize = api['Method::size'](1/*is_native*/) * pointerSize;
    const constMethodOffset = pointerSize;
    const accessFlagsOffset = 4 * pointerSize;
    const vtableIndexOffset = accessFlagsOffset + 4;
    const i2iEntryOffset = vtableIndexOffset + 4 + pointerSize;
    const nativeFunctionOffset = methodSize - 2 * pointerSize;
    const signatureHandlerOffset = methodSize - pointerSize;

    const constantPoolOffset = pointerSize;
    const constMethodSizeOffset = (3 + adapterInConstMethod) * pointerSize;
    const methodIdnumOffset = constMethodSizeOffset + 0xe;

    const instanceKlassOffset = 3 * pointerSize;
    let vtableOffset = 0;
    let methodsOffset = 0;
    if ('Klass::start_of_vtable' in api) {
      vtableOffset = api['Klass::start_of_vtable'](NULL).toInt32();
      methodsOffset = vtableOffset - (7 * pointerSize);
    }

    const getAdapterPointer = (adapterInConstMethod) ?
      function (method, constMethod) {
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
        instanceKlassOffset,
      },
      instanceKlass: {
        vtableOffset,
        methodsOffset
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
  deoptimizeEverything,
};
