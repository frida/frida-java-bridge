# arm64 dispatch deadlock — reproduction

Reproduces the process-wide deadlock described in the PR: with
`.implementation` hooks installed, frida-java-bridge's replacement-method
dispatch takes a blocking `GMutex` on ART's hot dispatch paths, which
deadlocks against ART thread suspension (GC, thread flips) on arm64.

## What you need

- arm64 Android 13 or 14 emulator (e.g. Cuttlefish, or an arm64 AVD)
- frida >= 17 and frida-server for the same version
- Node.js with `frida-compile`
- Java + `d8` (Android build-tools) — optional, only for the worker dex

## Steps

```sh
# 1. Build and push frida-server
adb push frida-server /data/local/tmp/
adb shell "/data/local/tmp/frida-server &"

# 2. Disable the JIT (optional but recommended: with the JIT on, the
#    workload can instead trip the dispatch-trampoline patch race and
#    crash; the deadlock itself fires with the JIT on or off)
adb root
adb shell "setprop dalvik.vm.usejit false && stop && start"

# 3. Bundle the script against the frida-java-bridge build under test
npm install frida-java-bridge frida-compile   # released npm = unfixed
npx frida-compile repro-deadlock-entry.js -o repro-bundled.js
adb push repro-bundled.js /data/local/tmp/

# 4. Run it against any app (Settings works fine)
frida -U -f com.android.settings -l /data/local/tmp/repro-bundled.js
```

The script hooks frequently-called native methods (forwarding
implementations) and prints a heartbeat every 30 s that includes a Java
round-trip latency probe.

## Expected results

**Unfixed bridge (any released frida-java-bridge):** the process wedges
within minutes. The heartbeat stops (the JS thread's next Java call parks
on the dispatch mutex) and the app ANRs. Confirm the signature with
`adb shell kill -3 <pid>` and inspect the newest `/data/anr/anr_*`
(or `debuggerd -b <pid>`): several threads blocked in
`pthread_mutex_lock` (bionic `NonPI::MutexLockWithTimeout`) at the SAME
PC in the dispatch trampoline's code, entered from
`art_quick_generic_jni_trampoline`.

**Fixed bridge (this branch):** no dispatch-mutex cluster appears, the
app's threads stay responsive, and the run completes without a wedge.

## Notes

- The deadlock needs concurrent JNI crossing + GC/flip activity. On an
  idle app the crossing volume comes from the framework's constant calls
  to the hooked time/id methods; if your device is very quiet, bump the
  crossing rate by opening the app's settings pages or adding the
  optional worker dex (see `ReproWorker.java`).
- Do not drive GCs from the script's own thread: a direct
  `Runtime.gc()` (or heavy allocation) from the frida JS thread wedges
  that thread against ART's GC-completion wait even with no hooks at
  all, which confounds the repro.
- On fast emulators with the JIT enabled the workload can instead trip
  the trampoline-prologue patch race (crash) — the deadlock is the
  failure mode on slower devices and with the JIT off, which is also
  what the ANR-trace signature distinguishes.
