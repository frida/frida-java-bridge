'use strict';

/* global describe, before, after, afterEach, it */

const Promise = require('bluebird');
require('bluebird-co');

const frida = require('frida');
const readFile = Promise.promisify(require('fs').readFile);
const should = require('should');

describe('Hook', function () {
  let device, session, script, agent;

  this.timeout(30000);

  before(Promise.coroutine(function* () {
    device = yield frida.getUsbDevice(3000);

    const pid = yield device.spawn(['com.twitter.android']);

    session = yield device.attach(pid);

    const source = yield readFile(require.resolve('./_agent'), 'utf8');
    script = yield session.createScript(source);
    script.events.listen('message', onMessage);
    yield script.load();
    agent = yield script.getExports();
  }));

  it('should be able to hook a system method', Promise.coroutine(function* () {
    console.log('hooking');
    yield agent.hookUrlApi();

    console.log('resuming');
    yield device.resume(pid);

    console.log('w00t, waiting 3 seconds');
    yield Promise.delay(3000);

    console.log('done');
  }));
});

function onMessage(message, data) {
  console.log(message);
}
