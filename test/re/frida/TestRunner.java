package re.frida;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

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
            "re.frida.ClassCreationTest",
            "re.frida.ClassInitializerTest"
        );
    }

    // Archive markers, written as escapes rather than literally, as javac is given
    // no -encoding and would otherwise read this file in the platform default charset.
    private static final String MAGIC = "\uD83D\uDCE6";    // PACKAGE
    private static final String END_OF_HEADER = "\u2704";  // BLACK SCISSORS
    private static final String ALIAS_PREFIX = "\u21BB";   // CLOCKWISE OPEN CIRCLE ARROW
    private static final String BODY_DELIMITER = "\n" + END_OF_HEADER + "\n";
    private static final byte[] DELIMITER = BODY_DELIMITER.getBytes(UTF_8);

    /**
     * Wraps the bundle around a snippet of test code, yielding a loadable script.
     *
     * frida-compile does not emit a plain script but an archive: a header naming
     * each module and the exact number of bytes it occupies, followed by the module
     * bodies. Code appended to such a file lands past the last body's declared
     * extent, where nothing will ever parse it. It has to go inside the entrypoint
     * module instead, with the length the header declares for that module fixed up
     * to match. A bundle that is a plain script is handled as one.
     */
    public static String buildScript(String code) {
        String archive = fridaJavaBundle;

        if (!archive.startsWith(MAGIC)) {
            return archive + ";\n" + code;
        }

        // The first delimiter ends the header; the rest separate one body from the next.
        int headerEnd = archive.indexOf(BODY_DELIMITER);
        String[] lines = archive.substring(MAGIC.length() + 1, headerEnd).split("\n");
        byte[] region = archive.substring(headerEnd + BODY_DELIMITER.length()).getBytes(UTF_8);
        byte[] addition = ("\n" + code).getBytes(UTF_8);

        // Walk the header as far as the entrypoint -- the first module that is not a source
        // map -- summing what the modules up to and including it occupy, which is where its
        // body ends. Alias lines belong to the module above them and take up no body.
        int entrypoint = -1;
        int bodyEnd = 0;
        int modules = 0;
        for (int i = 0; i != lines.length && entrypoint == -1; i++) {
            String line = lines[i];
            if (line.startsWith(ALIAS_PREFIX)) {
                continue;
            }

            if (modules++ != 0) {
                bodyEnd += DELIMITER.length;
            }

            int space = line.indexOf(' ');
            int length = Integer.parseInt(line.substring(0, space));
            bodyEnd += length;

            if (!line.endsWith(".map")) {
                entrypoint = i;
                lines[i] = (length + addition.length) + line.substring(space);
            }
        }

        StringBuilder header = new StringBuilder(MAGIC).append('\n');
        for (String line : lines) {
            header.append(line).append('\n');
        }
        header.append(END_OF_HEADER).append('\n');

        byte[] preamble = header.toString().getBytes(UTF_8);

        ByteArrayOutputStream out =
                new ByteArrayOutputStream(preamble.length + region.length + addition.length);
        out.write(preamble, 0, preamble.length);
        out.write(region, 0, bodyEnd);
        out.write(addition, 0, addition.length);
        out.write(region, bodyEnd, region.length - bodyEnd);

        return new String(out.toByteArray(), UTF_8);
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
