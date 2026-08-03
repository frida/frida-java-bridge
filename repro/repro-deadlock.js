'use strict';

/*
 * Reproduction for: process-wide deadlock on arm64 when .implementation
 * hooks are installed (frida-java-bridge replacement-method dispatch
 * takes a blocking GMutex on ART's hot dispatch paths).
 *
 * How it works:
 *   - hooks frequently-called native methods with forwarding
 *     implementations. Every call to a hooked method crosses the patched
 *     quick entrypoints on the CALLING ART thread (the app's binder
 *     pool, main thread, and background threads call these constantly),
 *     which is the path that takes the dispatch GMutex on the unfixed
 *     bridge;
 *   - prints a heartbeat every 30 s that includes a Java round-trip
 *     latency probe. If Java wedges, the probe blocks forever and the
 *     heartbeats stop: that is the bug.
 *
 * Usage (arm64 Android 13/14 emulator or device, frida >= 17):
 *
 *   # disable the JIT (recommended: with the JIT on, the workload can
 *   # instead trip the entrypoint patch race and crash; the deadlock
 *   # fires with the JIT on or off)
 *   adb root && adb shell "setprop dalvik.vm.usejit false && stop && start"
 *
 *   # build the script bundle (this file is not runnable standalone:
 *   # the Java bridge must be bundled with it)
 *   npm install frida-java-bridge frida-compile
 *   npx frida-compile repro/repro-deadlock-entry.js -o repro-bundled.js
 *   adb push frida-server /data/local/tmp/ && adb shell \
 *       "/data/local/tmp/frida-server &"
 *   frida -U -f com.android.settings -l repro-bundled.js
 *
 * Optional: set ALLOC=1 in the script to also drive GC / flip pressure
 * from the JS thread (allocation only — never Runtime.gc(), a direct GC
 * request from the JS thread wedges even without hooks). The deadlock
 * also fires from the framework's own traffic alone, just more slowly.
 *
 * To reproduce with the UNFIXED bridge, install the released
 * frida-java-bridge from npm; to verify the fix, install it from this
 * branch. Everything else stays the same.
 *
 * Expected behaviour:
 *   - UNFIXED bridge (any released frida-java-bridge): heartbeats stop
 *     within a few minutes and the app ANRs. Confirm with
 *     `adb shell kill -3 <pid>` and inspect the newest /data/anr/anr_*:
 *     several threads blocked in pthread_mutex_lock (bionic
 *     NonPI::MutexLockWithTimeout) at the SAME PC in jit-cache/anonymous
 *     code, entered from art_quick_generic_jni_trampoline.
 *   - FIXED bridge: heartbeats continue for the full run (default
 *     10 minutes) and no ANR is produced.
 */

const HOOKS = [
  ['java.lang.System', 'currentTimeMillis', []],
  ['java.lang.System', 'nanoTime', []],
  ['java.lang.System', 'identityHashCode', ['java.lang.Object']],
  ['java.lang.Thread', 'currentThread', []],
  ['android.os.SystemClock', 'uptimeMillis', []],
  ['android.os.SystemClock', 'elapsedRealtime', []],
  ['android.os.Process', 'myTid', []],
  ['java.lang.Runtime', 'maxMemory', []],
];

const RUN_MILLIS = 10 * 60 * 1000; // 10 minutes
const JAVA_STALL_MILLIS = 5000; // heartbeat probe threshold

let startedAt = 0;

function installHooks() {
  const installed = [];
  for (const [clsName, methodName, overloadArgs] of HOOKS) {
    try {
      const cls = Java.use(clsName);
      const method = overloadArgs.length > 0
        ? cls[methodName].overload(...overloadArgs)
        : cls[methodName].overload();
      method.implementation = function (...args) {
        return this[methodName](...args);
      };
      installed.push(clsName + '.' + methodName);
    } catch (e) {
      console.log('[repro] skip ' + clsName + '.' + methodName + ': ' + e);
    }
  }
  console.log('[repro] hooked ' + installed.length + '/' + HOOKS.length +
      ' native methods');
}

function startAllocator() {
  // Allocation pressure only: triggers the GC daemon's normal cycles and
  // thread flips. Deliberately NOT Runtime.gc(): a direct GC request from
  // the JS thread blocks in ART's GC-completion wait in Runnable state
  // and wedges even without any hooks, which would confound the repro.
  const allocs = [];
  setInterval(() => {
    allocs.push(Java.array('byte', new Array(16384).fill(0)));
    if (allocs.length > 128) {
      allocs.length = 0;
    }
  }, 200);
  console.log('[repro] allocator running (GC / flip pressure)');
}

function startHeartbeat() {
  const System = Java.use('java.lang.System');
  const timer = setInterval(() => {
    const t0 = Date.now();
    let roundTrip;
    try {
      System.currentTimeMillis();
      roundTrip = Date.now() - t0;
    } catch (e) {
      console.log('[repro] heartbeat java probe failed: ' + e);
      roundTrip = -1;
    }
    const elapsed = Date.now() - startedAt;
    console.log('[repro] alive after ' + elapsed + ' ms (java round-trip ' +
        roundTrip + ' ms)');
    if (roundTrip > JAVA_STALL_MILLIS) {
      console.log('[repro] JAVA STALLED: dispatch wedged (bug reproduced)');
      clearInterval(timer);
    } else if (elapsed >= RUN_MILLIS) {
      clearInterval(timer);
      console.log('[repro] completed without wedging (fix works)');
    }
  }, 30000);
}

let started = false;

function tryStart() {
  if (started) {
    return;
  }
  try {
    Java.perform(() => {
      if (started) {
        return;
      }
      started = true;
      start();
    });
  } catch (e) {
    console.log('[repro] Java.perform failed: ' + e);
  }
}

function start() {
  startedAt = Date.now();
  installHooks();
  // allocator disabled for this A/B: JS-thread allocation wedges
  // frida's attached thread under GC pressure regardless of the bridge
  // (a repro artifact), so it is toggled via the ALLOC env flag below.
  if (globalThis.ALLOC) {
    startAllocator();
  }
  startHeartbeat();
  console.log('[repro] running for ' + RUN_MILLIS +
      ' ms; heartbeat stopping early = wedged (bug reproduced)');
}

tryStart();
setInterval(tryStart, 250);
