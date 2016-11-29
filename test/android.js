'use strict';

/* global before, describe, it */

const Promise = require('bluebird');
require('bluebird-co');

const exec = require('child_process').exec;
const frida = require('frida');
const readFile = Promise.promisify(require('fs').readFile);
require('should');

describe('Android', function () {
  let agentCode;

  this.timeout(30000);

  before(Promise.coroutine(function* () {
    agentCode = yield readFile(require.resolve('./_agent'), 'utf8');
  }));

  it('should detect internal field offsets correctly', Promise.coroutine(function* () {
    const ids = yield getConnectedDevicesIds();
    console.log('ids:', ids);

    for (let i = 0; i !== ids.length; i++) {
      const device = yield frida.getDevice(ids[i], 500);

      const session = yield device.attach('com.android.systemui');

      const script = yield session.createScript(agentCode);
      script.events.listen('message', onMessage);
      yield script.load();

      const agent = yield script.getExports();

      const version = yield agent.getAndroidVersion();
      console.log('version=' + version);

      yield script.unload();
      yield session.detach();
    }
  }));
});

function getConnectedDevicesIds () {
  return new Promise((resolve, reject) => {
    exec('adb devices -l', (error, stdout, stderr) => {
      if (error !== null) {
        reject(error);
        return;
      }

      const ids = stdout.split('\n').slice(1)
      .filter(line => {
        return line.length > 0;
      })
      .map(line => {
        const tokens = line.split(' ', 2);
        return tokens[0];
      });

      resolve(ids);
    });
  });
}

function onMessage (message, data) {
  console.log(message);
}
