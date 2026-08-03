/*
 * Bundled variant of repro-deadlock.js for testing a specific
 * frida-java-bridge build (e.g. this branch's fix).
 *
 *   npm install frida-java-bridge   # from this branch, or a local path
 *   npx frida-compile repro-deadlock-entry.js -o repro-bundled.js
 *   frida -U -f com.android.settings -l repro-bundled.js
 */
const mod = require('frida-java-bridge');
const Java = mod.default ?? mod;
globalThis.Java = Java;
require('./repro-deadlock.js');
