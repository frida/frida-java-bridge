import Env from './env.js';
import { JNI_OK, checkJniResult } from './result.js';

const JNI_VERSION_1_6 = 0x00010006;

const pointerSize = Process.pointerSize;

const jsThreadID = Process.getCurrentThreadId();
const attachedThreads = new Map();
const activeEnvs = new Map();

export default function VM (api) {
  const handle = api.vm;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;

  function initialize () {
    const vtable = handle.readPointer();
    const options = {
      exceptions: 'propagate'
    };
    attachCurrentThread = new NativeFunction(vtable.add(4 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'pointer'], options);
    detachCurrentThread = new NativeFunction(vtable.add(5 * pointerSize).readPointer(), 'int32', ['pointer'], options);
    getEnv = new NativeFunction(vtable.add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'], options);
  }

  this.handle = handle;

  this.perform = function (fn) {
    const threadId = Process.getCurrentThreadId();

    const cachedEnv = tryGetCachedEnv(threadId);
    if (cachedEnv !== null) {
      return fn(cachedEnv);
    }

    let env = this._tryGetEnv();
    const alreadyAttached = env !== null;
    if (!alreadyAttached) {
      env = this.attachCurrentThread();
      attachedThreads.set(threadId, true);
    }

    this.link(threadId, env);

    try {
      return fn(env);
    } finally {
      const isJsThread = threadId === jsThreadID;

      if (!isJsThread) {
        this.unlink(threadId);
      }

      if (!alreadyAttached && !isJsThread) {
        const allowedToDetach = attachedThreads.get(threadId);
        attachedThreads.delete(threadId);

        if (allowedToDetach) {
          this.detachCurrentThread();
        }
      }
    }
  };

  this.attachCurrentThread = function () {
    const envBuf = Memory.alloc(pointerSize);
    checkJniResult('VM::AttachCurrentThread', attachCurrentThread(handle, envBuf, NULL));
    return new Env(envBuf.readPointer(), this);
  };

  this.detachCurrentThread = function () {
    checkJniResult('VM::DetachCurrentThread', detachCurrentThread(handle));
  };

  this.preventDetachDueToClassLoader = function () {
    const threadId = Process.getCurrentThreadId();

    if (attachedThreads.has(threadId)) {
      attachedThreads.set(threadId, false);
    }
  };

  this.getEnv = function () {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }

    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result === -2) {
      throw new Error('Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback');
    }
    checkJniResult('VM::GetEnv', result);
    return new Env(envBuf.readPointer(), this);
  };

  this.tryGetEnv = function () {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }

    return this._tryGetEnv();
  };

  this._tryGetEnv = function () {
    const h = this.tryGetEnvHandle(JNI_VERSION_1_6);
    if (h === null) {
      return null;
    }
    return new Env(h, this);
  };

  this.tryGetEnvHandle = function (version) {
    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, version);
    if (result !== JNI_OK) {
      return null;
    }
    return envBuf.readPointer();
  };

  this.makeHandleDestructor = function (handle) {
    return () => {
      this.perform(env => {
        env.deleteGlobalRef(handle);
      });
    };
  };

  this.link = function (tid, env) {
    const entry = activeEnvs.get(tid);
    if (entry === undefined) {
      activeEnvs.set(tid, [env, 1]);
    } else {
      entry[1]++;
    }
  };

  this.unlink = function (tid) {
    const entry = activeEnvs.get(tid);
    if (entry[1] === 1) {
      activeEnvs.delete(tid);
    } else {
      entry[1]--;
    }
  };

  function tryGetCachedEnv (threadId) {
    const entry = activeEnvs.get(threadId);
    if (entry === undefined) {
      return null;
    }
    return entry[0];
  }

  initialize.call(this);
}

VM.dispose = function (vm) {
  if (attachedThreads.get(jsThreadID) === true) {
    attachedThreads.delete(jsThreadID);
    vm.detachCurrentThread();
  }
};
