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
    ids.sort();

    // 5.0
    // const ids = ['emulator-5554'];

    // 5.1
    // const ids = ['emulator-5556'];

    // 6.0
    // const ids = ['emulator-5558'];

    // 6.0 64-bit
    // const ids = ['03157df369703a2a'];

    for (let i = 0; i !== ids.length; i++) {
      const device = yield frida.getDevice(ids[i], 500);

      const session = yield device.attach('com.android.systemui');

      const script = yield session.createScript(agentCode);
      script.events.listen('message', onMessage);
      yield script.load();

      const agent = yield script.getExports();

      const version = yield agent.getAndroidVersion();
      const pointerSize = yield agent.getPointerSize();
      console.log('id:', ids[i], 'version:', version, 'pointerSize:', pointerSize);

      const runtimeSpec = yield agent.getArtRuntimeSpec();
      const classLinkerOffset = runtimeSpec.offset.classLinker;
      if (version.startsWith('5.0') && pointerSize === 4) {
        classLinkerOffset.should.equal(208);
      } else if (version.startsWith('5.1') && pointerSize === 4) {
        classLinkerOffset.should.equal(212);
      } else if (version.startsWith('6.0') && pointerSize === 4) {
        classLinkerOffset.should.equal(236);
      } else if (version.startsWith('6.0') && pointerSize === 8) {
        classLinkerOffset.should.equal(392);
      } else {
        throw new Error('Unhandled flavor');
      }

      const linkerSpec = yield agent.getArtClassLinkerSpec();
      const trampolineOffset = linkerSpec.offset.quickGenericJniTrampoline;
      if (version.startsWith('5.0') && pointerSize === 4) {
        trampolineOffset.should.equal(224);
      } else if (version.startsWith('5.1') && pointerSize === 4) {
        trampolineOffset.should.equal(296);
      } else if (version.startsWith('6.0') && pointerSize === 4) {
        trampolineOffset.should.equal(296);
      } else if (version.startsWith('6.0') && pointerSize === 8) {
        trampolineOffset.should.equal(440);
      } else {
        throw new Error('Unhandled flavor');
      }

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
