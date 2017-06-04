package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.Cipher;
import java.io.IOException;

public class MethodTest {
    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void callPropagatesExceptions() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var badger = Badger.$new();" +
                "try {" +
                    "badger.die();" +
                    "send('should not get here');" +
                "} catch (e) {" +
                    "send(e.message);" +
                "}");
        assertEquals("java.lang.IllegalStateException: Already dead", script.getNextMessage());
    }

    @Test
    public void replacementCanThrowJavaException() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var IllegalArgumentException = Java.use('java.lang.IllegalArgumentException');" +
                "Badger.die.implementation = function () {" +
                    "throw IllegalArgumentException.$new('Not today');" +
                "};");

        Badger badger = new Badger();

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Not today");
        badger.die();
    }

    @Test
    public void replacementPropagatesExceptions() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.die.implementation = function () {" +
                    "this.die();" +
                "};");

        Badger badger = new Badger();

        thrown.expect(IllegalStateException.class);
        thrown.expectMessage("Already dead");
        badger.die();
    }

    @Test
    public void genericsCanBeUsed() {
        loadScript("var ArrayList = Java.use('java.util.ArrayList');" +
                "var items = ArrayList.$new();" +
                "items.add('Badger');" +
                "send(items.get(0).toString());");
        assertEquals("Badger", script.getNextMessage());
    }

    @Test
    public void fieldsThatCollideWithMethodsGetPrefixed() {
        loadScript("var Collider = Java.use('re.frida.Collider');" +
                "var collider = Collider.$new();" +
                "send(collider._particle.value);");
        assertEquals("1", script.getNextMessage());
    }

    @Test
    public void methodsThatCollideWithFieldsKeepName() {
        loadScript("var Collider = Java.use('re.frida.Collider');" +
                "var collider = Collider.$new();" +
                "send(collider.particle());");
        assertEquals("3", script.getNextMessage());
    }

    @Test
    public void fieldsThatCollideWithMethodsGetPrefixed2() {
        loadScript("var Collider = Java.use('re.frida.Collider');" +
                "var collider = Collider.$new();" +
                "send(collider._particle2.value);");
        assertEquals("2", script.getNextMessage());
    }

    @Test
    public void methodsThatCollideWithFieldsKeepName2() {
        loadScript("var Collider = Java.use('re.frida.Collider');" +
                "var collider = Collider.$new();" +
                "send(collider.particle2());");
        assertEquals("4", script.getNextMessage());
    }

    @Test
    public void staticFieldCanBeRead() {
        loadScript("var Cipher = Java.use('javax.crypto.Cipher');" +
                "send('' + Cipher.ENCRYPT_MODE.value);");
        assertEquals("" + Cipher.ENCRYPT_MODE, script.getNextMessage());
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

class Badger {
    void die() {
        throw new IllegalStateException("Already dead");
    }

    static Class<?> forName() {
        return Badger.class;
    }

    public int returnZero() {
        return 0;
    }
}

class Collider {
    static int particle = 1;
    int particle2 = 2;

    int particle() {
        return 3;
    }

    static int particle2() {
        return 4;
    }
}
