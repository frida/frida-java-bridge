/*
 * Repro worker: real Java threads that hammer the instrumented JNI
 * boundary while driving GC pressure. Loaded via frida's
 * Java.openClassFile() from /data/local/tmp/repro-worker.dex (built from
 * ReproWorker.java; see README.md).
 */
package com.example.repro;

public final class ReproWorker implements Runnable {
    private static final long RUN_NANOS = 10L * 60L * 1000L * 1000L * 1000L;
    private static final int GC_INTERVAL = 4096;
    private static final int BATCH = 64;
    private static final int SLOT_SIZE = 4096;

    public void run() {
        final long end = System.nanoTime() + RUN_NANOS;
        final Runtime rt = Runtime.getRuntime();
        final Object marker = new Object();
        final byte[][] slots = new byte[4096][];
        int n = 0;
        int counter = 0;
        while (System.nanoTime() < end) {
            // Every one of these is a hooked native method, so each call
            // crosses the patched quick entrypoints (and, on the unfixed
            // bridge, the dispatch GMutex).
            System.currentTimeMillis();
            System.nanoTime();
            System.identityHashCode(marker);
            Thread.currentThread();
            for (int i = 0; i < BATCH; i++) {
                slots[n++ % slots.length] = new byte[SLOT_SIZE];
            }
            if ((counter++ & (GC_INTERVAL - 1)) == 0) {
                rt.gc();
            }
        }
    }
}
