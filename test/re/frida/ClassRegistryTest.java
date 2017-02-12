package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;

public class ClassRegistryTest {
    @Test
    public void loadedClassesCanBeEnumerated() {
        loadScript("var found = false;" +
                "Java.enumerateLoadedClasses({" +
                "  onMatch: function (entry) {" +
                "    if (entry === 're.frida.ClassRegistryTest') {" +
                "      found = true;" +
                "    }" +
                "  }," +
                "  onComplete: function () {" +
                "    send('found=' + found);" +
                "  }" +
                "});");
        assertEquals("found=true", script.getNextMessage());
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

    @After
    public void tearDown() throws IOException {
        if (script != null) {
            script.close();
            script = null;
        }
    }
}
