'use strict';

const {
  getArtRuntimeSpec,
  getArtClassLinkerSpec,
  getArtMethodSpec
} = require('../../lib/android');
const Java = require('../..');

let hookTriggerCount = 0;

rpc.exports = {
  getPointerSize() {
    return Process.pointerSize;
  },

  getAndroidVersion() {
    return performOnJavaVM(() => {
      return Java.androidVersion;
    });
  },

  getArtRuntimeSpec() {
    return performOnJavaVM(() => {
      return getArtRuntimeSpec(Java.vm, Java.classFactory);
    });
  },

  getArtClassLinkerSpec() {
    return performOnJavaVM(() => {
      return getArtClassLinkerSpec(Java.vm, Java.classFactory);
    });
  },

  getArtMethodSpec() {
    return performOnJavaVM(() => {
      return getArtMethodSpec(Java.vm, Java.classFactory);
    });
  },

  getHookTriggerCount() {
    return hookTriggerCount;
  },

  callJavaMethod() {
    return performOnJavaVM(() => {
      const URL = Java.use('java.net.URL');

      const url = URL.$new('http://www.ikke.no/');
      const host = url.getHost();
      console.log('host=' + host);
    });
  },

  hookJavaMethod() {
    return performOnJavaVM(() => {
      const URL = Java.use('java.net.URL');

      URL.getHost.implementation = function () {
        hookTriggerCount++;
        return this.getHost();
      };
    });
  }
};

function performOnJavaVM (task) {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        const result = task();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}
