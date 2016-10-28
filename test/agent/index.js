'use strict';

const Java = require('../..');

rpc.exports = {
  hookUrlApi() {
    Java.perform(() => {
      const URL = Java.use('java.net.URL');

      m = URL.openConnection.overload('')
      m.implementation = function () {
        console.log('URL.openConnection()');
        return m.call(this);
      };
    });
  }
};
