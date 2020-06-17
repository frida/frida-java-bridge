const Env = require('./env');
const { JNI_OK, checkJniResult } = require('./result');

const JNI_VERSION_1_6 = 0x00010006;

const pointerSize = Process.pointerSize;

function VM (api) {
  const handle = api.vm;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;
  const attachedThreads = {};

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
    let threadId = null;

    let env = this.tryGetEnv();
    const alreadyAttached = env !== null;
    if (!alreadyAttached) {
      env = this.attachCurrentThread();

      threadId = Process.getCurrentThreadId();
      attachedThreads[threadId] = true;
    }

    try {
      return fn();
    } finally {
      if (!alreadyAttached) {
        const allowedToDetach = attachedThreads[threadId];
        delete attachedThreads[threadId];

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
    if (threadId in attachedThreads) {
      attachedThreads[threadId] = false;
    }
  };

  this.getEnv = function () {
    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result === -2) {
      throw new Error('Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback');
    }
    checkJniResult('VM::GetEnv', result);
    return new Env(envBuf.readPointer(), this);
  };

  this.tryGetEnv = function () {
    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result !== JNI_OK) {
      return null;
    }
    return new Env(envBuf.readPointer(), this);
  };

  this.makeHandleDestructor = function (handle) {
    return () => {
      this.perform(() => {
        const env = this.getEnv();
        env.deleteGlobalRef(handle);
      });
    };
  };

  initialize.call(this);
}

module.exports = VM;

/* global Memory, NativeFunction, NULL, Process */
