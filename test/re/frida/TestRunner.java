package re.frida;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

import org.junit.runner.JUnitCore;

public class TestRunner {
    public static String fridaJavaBundle;

    private static String dataDir;

    public static void main(String[] args, String dataDir) {
        TestRunner.dataDir = dataDir;

        TestRunner.fridaJavaBundle = slurp("frida-java.js");

        JUnitCore.main("re.frida.HookTest");
    }

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
