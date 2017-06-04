package re.frida;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

import org.junit.runner.JUnitCore;

public class TestRunner {
    public static String fridaJavaBundle;
    public static long classLoaderPointer;

    private static String dataDir;

    public static void main(String[] args, String dataDir, long classLoaderPointer) {
        TestRunner.dataDir = dataDir;
        TestRunner.classLoaderPointer = classLoaderPointer;

        TestRunner.fridaJavaBundle = slurp("frida-java.js");

        registerClassLoader(TestRunner.class.getClassLoader());

        JUnitCore.main(
            "re.frida.ClassRegistryTest",
            "re.frida.MethodTest",
            "re.frida.ClassCreationTest"
        );
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
