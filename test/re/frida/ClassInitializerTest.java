package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;

public class ClassInitializerTest {
    @Test
    public void classInitializerCanBeHooked() {
        loadScript("var Lazy = Java.use('re.frida.LazilyInitialized');" +
                "Lazy.$clinit.implementation = function () {" +
                    "send('before');" +
                    "this.$clinit();" +
                    "send('after');" +
                "};");

        assertEquals("initialized", LazilyInitialized.getGreeting());
        assertEquals("before", script.getNextMessage());
        assertEquals("after", script.getNextMessage());
    }

    @Test
    public void classInitializerCanBeReplaced() {
        loadScript("var Lazy = Java.use('re.frida.ReplaceablyInitialized');" +
                "Lazy.$clinit.implementation = function () {" +
                    "send('skipped');" +
                "};");

        assertEquals(null, ReplaceablyInitialized.getGreeting());
        assertEquals("skipped", script.getNextMessage());
    }

    @Test
    public void classInitializerIsEnumerable() {
        loadScript("Java.use('re.frida.EnumerablyInitialized');" +
                "var names = [];" +
                "Java.enumerateMethods('re.frida.EnumerablyInitialized!*').forEach(function (group) {" +
                    "group.classes.forEach(function (klass) {" +
                        "names = names.concat(klass.methods);" +
                    "});" +
                "});" +
                "send(names.indexOf('$clinit') !== -1 ? 'found' : names.join(','));");

        assertEquals("found", script.getNextMessage());
    }

    @Test
    public void classWithoutClassInitializerThrows() {
        loadScript("var Bare = Java.use('re.frida.NeverInitialized');" +
                "try {" +
                    "Bare.$clinit;" +
                    "send('no error');" +
                "} catch (e) {" +
                    "send(e.message);" +
                "}");

        assertEquals("re.frida.NeverInitialized has no class initializer",
                script.getNextMessage());
    }

    private Script script = null;

    private void loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                code +
                "});" +
                "})(LocalJava);");
        this.script = script;
    }

    private void unloadScript() throws IOException {
        if (script != null) {
            script.close();
            script = null;
        }
    }

    @After
    public void tearDown() throws IOException {
        unloadScript();
    }
}

class LazilyInitialized {
    private static String greeting;

    static {
        greeting = "initialized";
    }

    public static String getGreeting() {
        return greeting;
    }
}

class ReplaceablyInitialized {
    private static String greeting;

    static {
        greeting = "initialized";
    }

    public static String getGreeting() {
        return greeting;
    }
}

class EnumerablyInitialized {
    private static String greeting;

    static {
        greeting = "initialized";
    }

    public static String getGreeting() {
        return greeting;
    }
}

class NeverInitialized {
    public static String getGreeting() {
        return "static";
    }
}
