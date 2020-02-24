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

    @Test
    public void classLoadersCanBeEnumerated() {
        if (android.os.Build.VERSION.SDK_INT < 24) {
            return;
        }

        loadScript("var count = 0;" +
                "Java.enumerateClassLoaders({" +
                "  onMatch: function (loader) {" +
                "    count++;" +
                "  }," +
                "  onComplete: function () {" +
                "    send((count > 0) ? 'count > 0' : 'count == 0');" +
                "  }" +
                "});");
        assertEquals("count > 0", script.getNextMessage());
    }

    private UniqueBadger badger = null;

    @Test
    public void liveObjectsCanBeEnumerated() {
        badger = new UniqueBadger("Joe");
        loadScript("var count = 0;" +
                "var name = null;" +
                "Java.choose('re.frida.UniqueBadger', {" +
                "  onMatch: function (entry) {" +
                "    count++;" +
                "    name = entry.name.value;" +
                "  }," +
                "  onComplete: function () {" +
                "    send('count=' + count);" +
                "    send('name=' + name);" +
                "  }" +
                "});");
        assertEquals("count=1", script.getNextMessage());
        assertEquals("name=Joe", script.getNextMessage());
    }

    // Issue #139
    @Test
    public void classWrapperShouldBeJavaLangClass() {
        loadScript("var clazz = Java.use('java.lang.Class');" +
                "send(clazz.class.$className);" +
                "send(clazz.getClassLoader.overloads.length);" +
                "clazz = Java.use('java.lang.Exception').$new().getClass();" +
                "send(clazz.class.$className);" +
                "send(clazz.getClassLoader.overloads.length);");
        assertEquals("java.lang.Class", script.getNextMessage());
        assertEquals("1", script.getNextMessage());
        assertEquals("java.lang.Class", script.getNextMessage());
        assertEquals("1", script.getNextMessage());
    }

    @Test
    public void classWrapperShouldSupportInQueries() {
        loadScript("var JObject = Java.use('java.lang.Object');" +
                "send('notifyAll' in JObject);");
        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void classWrapperShouldSupportFetchingKeys() {
        loadScript("var JObject = Java.use('java.lang.Object');" +
                "var keys = Object.keys(JObject);" +
                "send(keys.indexOf('notifyAll') !== -1);");
        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void classWrapperShouldSupportQueryingClassName() {
        loadScript("var JString = Java.use('java.lang.String');" +
                "send(JString.$className);" +
                "var str = JString.$new('Yo');" +
                "send(str.$className);" +
                "var obj = Java.cast(str, Java.use('java.lang.Object'));" +
                "send(obj.$className);");
        assertEquals("java.lang.String", script.getNextMessage());
        assertEquals("java.lang.String", script.getNextMessage());
        assertEquals("java.lang.String", script.getNextMessage());
    }

    @Test
    public void classWrapperShouldSupportToString() {
        loadScript("var JString = Java.use('java.lang.String');" +
                "send(JString.toString());");
        assertEquals("<class: java.lang.String>", script.getNextMessage());
    }

    @Test
    public void classWrapperShouldSupportToJSON() {
        loadScript("var JString = Java.use('java.lang.String');" +
                "send(JSON.stringify(JString.toJSON()));" +
                "var str = JString.$new('Yo');" +
                "send(JSON.stringify(str.toJSON()));" +
                "var obj = Java.cast(str, Java.use('java.lang.Object'));" +
                "send(JSON.stringify(obj.toJSON()));");
        assertEquals("\"<class: java.lang.String>\"", script.getNextMessage());
        assertEquals("\"<instance: java.lang.String>\"", script.getNextMessage());
        assertEquals("\"<instance: java.lang.Object, " +
            "$className: java.lang.String>\"", script.getNextMessage());
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

class UniqueBadger {
    public String name;

    public UniqueBadger(String name) {
        this.name = name;
    }
}
