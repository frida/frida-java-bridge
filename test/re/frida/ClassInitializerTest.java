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

        assertEquals("initialized", LazilyInitialized.greeting);
        assertEquals("before", script.getNextMessage());
        assertEquals("after", script.getNextMessage());
    }

    @Test
    public void classInitializerCanBeReplaced() {
        loadScript("var Lazy = Java.use('re.frida.ReplaceablyInitialized');" +
                "Lazy.$clinit.implementation = function () {" +
                    "send('skipped');" +
                "};");

        assertEquals(null, ReplaceablyInitialized.greeting);
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
        Script script = new Script(TestRunner.buildScript(
                "(function (Java) {" +
                "Java.perform(function () {" +
                code +
                "});" +
                "})(LocalJava);"));
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

// A non-final static field with an initializer is enough to give a class a <clinit>,
// and reading it is enough to trigger one. Each test needs its own, as a class is only
// ever initialized once.
class LazilyInitialized {
    public static String greeting = "initialized";
}

class ReplaceablyInitialized {
    public static String greeting = "initialized";
}

class EnumerablyInitialized {
    public static String greeting = "initialized";
}

class NeverInitialized {
}
