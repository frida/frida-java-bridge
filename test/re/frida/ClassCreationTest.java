package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;

public class ClassCreationTest {
    private static Class bananaClass = null;

    @Test
    public void interfaceCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var Eatable = Java.use('re.frida.Eatable');" +
                "var Banana = Java.registerClass({" +
                "  name: 're.frida.Banana'," +
                "  implements: [Eatable]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'Banana';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams * 2;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').bananaClass.value = Banana.class;");
        Eatable eatable = (Eatable) bananaClass.newInstance();
        assertEquals("Banana", eatable.getName());
        assertEquals(100, eatable.getCalories(50));
    }

    private Script script = null;

    private void loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                "Java.classFactory.loader = Java.cast(Memory.readPointer(ptr(" + TestRunner.classLoaderPointer +
                    ")), Java.use('java.lang.ClassLoader'));" +
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
