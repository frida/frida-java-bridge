'use strict';

const Java = require('../..');

rpc.exports = {
  getAndroidVersion() {
    return performOnJavaVM(() => {
      return Java.androidVersion;
    });
  },
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
