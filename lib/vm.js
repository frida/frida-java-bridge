'use strict';

const Env = require('./env');
const {JNI_OK, checkJniResult} = require('./result');

const JNI_VERSION_1_6 = 0x00010006;

const pointerSize = Process.pointerSize;

function VM (api) {
  let handle = null;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;
  const attachedThreads = {};

  function initialize () {
    handle = api.vm;

    const vtable = Memory.readPointer(handle);
    const options = {
      exceptions: 'propagate'
    };
    attachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(4 * pointerSize)), 'int32', ['pointer', 'pointer', 'pointer'], options);
    detachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(5 * pointerSize)), 'int32', ['pointer'], options);
    getEnv = new NativeFunction(Memory.readPointer(vtable.add(6 * pointerSize)), 'int32', ['pointer', 'pointer', 'int32'], options);
  }

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
      fn();
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
    return new Env(Memory.readPointer(envBuf), this);
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
    checkJniResult('VM::GetEnv', getEnv(handle, envBuf, JNI_VERSION_1_6));
    return new Env(Memory.readPointer(envBuf), this);
  };

  this.tryGetEnv = function () {
    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result !== JNI_OK) {
      return null;
    }
    return new Env(Memory.readPointer(envBuf), this);
  };

  initialize.call(this);
}

module.exports = VM;

/* global Memory, NativeFunction, NULL, Process */
