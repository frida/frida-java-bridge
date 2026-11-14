package re.frida;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.runner.JUnitCore;

public class TestRunner {
    public static String fridaJavaBundle;
    public static long classLoaderPointer;

    private static String dataDir;
    private static String cacheDir;

    public static void main(String[] args, String dataDir, String cacheDir,
            long classLoaderPointer) {
        TestRunner.dataDir = dataDir;
        TestRunner.cacheDir = cacheDir;
        TestRunner.classLoaderPointer = classLoaderPointer;

        TestRunner.fridaJavaBundle = slurp("frida-java-bridge.js");

        registerClassLoader(TestRunner.class.getClassLoader());

        JUnitCore.main(
            "re.frida.ClassRegistryTest",
            "re.frida.MethodTest",
            "re.frida.ClassCreationTest"
        );
    }

    public static String getCacheDir() {
        return dataDir;
    }

    public static String getCodeCacheDir() {
        return cacheDir;
    }

    public static String bundleWith(String code) {
        // The bundle is a package of ES modules, where GumJS ignores anything
        // following the last asset. Append the code as a package of its own,
        // so its entrypoint gets evaluated right after the bundle's.
        int size = code.getBytes(StandardCharsets.UTF_8).length;
        return fridaJavaBundle +
                "\n\u2704\n" +
                size + " /test.js" +
                "\n\u2704\n" +
                code;
    }

    private static native void registerClassLoader(ClassLoader loader);

    public static String slurp(String name) {
        File file = new File(dataDir, name);
        try {
            DataInputStream input = new DataInputStream(new FileInputStream(file));
            try {
                byte[] data = new byte[(int) file.length()];
                input.readFully(data);
                return new String(data, "UTF-8");
            } finally {
                input.close();
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }
}
