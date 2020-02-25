package re.frida;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

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
