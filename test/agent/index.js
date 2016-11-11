'use strict';

const Java = require('../..');

rpc.exports = {
  enumerateLoadedClasses() {
    return new Promise((resolve, reject) => {
      Java.perform(() => {
        try {
          const classes = Java.enumerateLoadedClassesSync();
          resolve(classes.length);
        } catch (e) {
          reject(e);
        }
      });
    });
  },

  hookUrlApi() {
    Java.perform(() => {
      const URL = Java.use('java.net.URL');

      m = URL.openConnection.overload('')
      m.implementation = function () {
        console.log('URL.openConnection()');
        return m.call(this);
      };
    });
  },
};
