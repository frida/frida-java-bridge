package re.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

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
    public void overloadCanBeSpecified() {
        loadScript("var Overloader = Java.use('re.frida.Overloader');" +
                "var overloader = Overloader.$new();" +
                "send(overloader.frobnicate());" +
                "send(overloader.frobnicate(1));" +
                "var frobnicate = overloader.frobnicate;" +
                "send(frobnicate.overload().call(overloader));" +
                "send(frobnicate.overload('int').call(overloader, 2));");
        assertEquals("13", script.getNextMessage());
        assertEquals("37", script.getNextMessage());
        assertEquals("13", script.getNextMessage());
        assertEquals("74", script.getNextMessage());
    }

    @Test
    public void charSequenceCanBeReturned() {
        loadScript("var Returner = Java.use('re.frida.Returner');" +
                "var returner = Returner.$new();" +
                "send(returner.getString());" +
                "send(returner.getStringBuffer().toString());");
        assertEquals("izi", script.getNextMessage());
        assertEquals("let me in", script.getNextMessage());
    }

    @Test
    public void primitiveArrayCanBeReturned() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "var pending = buffinator.getPending();" +
                "send(pending.length);" +
                "send(pending[0]);" +
                "send(pending[1]);" +
                "send(typeof pending[2]);");
        assertEquals("2", script.getNextMessage());
        assertEquals("13", script.getNextMessage());
        assertEquals("37", script.getNextMessage());
        assertEquals("undefined", script.getNextMessage());
    }

    @Test
    public void primitiveArrayCanBePassed() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "send(buffinator.sum([ 3, 7, 2 ]));");
        assertEquals("12", script.getNextMessage());
    }

    @Test
    public void primitiveArrayCanBeModified() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "var buffer = Java.array('int', [ 1003, 1005, 1007 ]);" +
                "send(buffer.length);" +
                "send(buffer[0]);" +
                "send(buffer[1]);" +
                "send(buffer[2]);" +
                "buffer[2] = 9000;" +
                "send(buffer[2]);" +
                "buffinator.bump(buffer);" +
                "send(buffer[0]);" +
                "send(buffer[1]);" +
                "send(buffer[2]);");
        assertEquals("3", script.getNextMessage());
        assertEquals("1003", script.getNextMessage());
        assertEquals("1005", script.getNextMessage());
        assertEquals("1007", script.getNextMessage());
        assertEquals("9000", script.getNextMessage());
        assertEquals("2003", script.getNextMessage());
        assertEquals("2005", script.getNextMessage());
        assertEquals("10000", script.getNextMessage());
    }

    @Test
    public void primitiveArrayOverloadCanBeCalledImplicitly() {
        loadScript("var JString = Java.use('java.lang.String');" +
                "var str = JString.$new(Java.array('byte', [ 0x48, 0x65, 0x69 ]));" +
                "send(str.toString());");
        assertEquals("Hei", script.getNextMessage());
    }

    @Test
    public void primitiveArrayOwnKeysCanBeQueried() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "var buffer = Java.array('int', [ 13, 37 ]);" +
                "send(Object.getOwnPropertyNames(buffer));");
        assertEquals("[\"$handle\",\"type\",\"length\",\"0\",\"1\"]", script.getNextMessage());
    }

    @Test
    public void primitiveArrayCanBeSerializedToJson() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "var buffer = Java.array('int', [ 13, 37 ]);" +
                "send(buffer);");
        assertEquals("[13,37]", script.getNextMessage());
    }

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
    public void passingJSStringToReplacementThatThrowsShouldNotCrash() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var IllegalStateException = Java.use('java.lang.IllegalStateException');" +
                "var error = IllegalStateException.$new('Already dead: w00t');" +
                "Badger.dieWithMessage.implementation = function (message) {" +
                    "throw error;" +
                "};" +
                "var b = Badger.$new();" +
                "try {" +
                    "b.dieWithMessage('w00t');" +
                "} catch (e) {" +
                    "send(e.message);" +
                "}");
        assertEquals("java.lang.IllegalStateException: Already dead: w00t", script.getNextMessage());
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

    @Test
    public void replacementCanBeDoneOnReflection() {
        loadScript("var classDef = Java.use('java.lang.Class');\n" +
                   "var getMethod = classDef.getMethod.overload('java.lang.String',\n" +
                                                               "'[Ljava.lang.Class;');\n" +
                   "send('overload found');\n" +
                   "getMethod.implementation = function(name, array) {\n" +
                       "var method = getMethod.call(this, name, array);\n" +
                       "send(name + ' dereflected');\n" +
                       "return method;\n" +
                   "}\n" +
                   "send('implementation replaced');\n");
        assertEquals("overload found", script.getNextMessage());
        assertEquals("implementation replaced", script.getNextMessage());

        Class reflector = Reflector.class;
        java.lang.reflect.Method method;
        try {
            method = reflector.getMethod("reflected");
            assertEquals("reflected dereflected", script.getNextMessage());
        } catch (Exception e) {
            fail(e.toString());
        }
    }

    // Issue #125
    @Test
    public void genericArrayTypeShouldConvertToArray() {
        loadScript("var GenericArray = Java.use('re.frida.GenericArray');" +
            "var genericArray = GenericArray.getArray();" +
            "send(Array.isArray(genericArray) + ',' + genericArray.length);");
        assertEquals("true,2", script.getNextMessage());
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

class Overloader {
    public int frobnicate() {
        return 13;
    }

    public int frobnicate(int factor) {
        return factor * 37;
    }
}

class Returner {
    public static String s = "izi";

    // Any class that implements CharacterSequence and is not a String
    public static StringBuffer sb = new StringBuffer("let me in");

    public String getString() {
        return s;
    }

    public StringBuffer getStringBuffer() {
        return sb;
    }
}

class Buffinator {
    public byte[] getPending() {
        return new byte[] { 13, 37 };
    }

    public int sum(byte[] values) {
        int result = 0;
        for (byte value : values) {
            result += value;
        }
        return result;
    }

    public void bump(int[] values) {
        for (int i = 0; i != values.length; i++) {
            values[i] += 1000;
        }
    }
}

class Badger {
    public void die() {
        throw new IllegalStateException("Already dead");
    }

    public void dieWithMessage(String message) {
        throw new IllegalStateException("Already dead: " + message);
    }

    public static Class<?> forName() {
        return Badger.class;
    }

    public int returnZero() {
        return 0;
    }
}

class Collider {
    public static int particle = 1;
    public int particle2 = 2;

    public int particle() {
        return 3;
    }

    public static int particle2() {
        return 4;
    }
}

class Reflector {
    public static void reflected() {
    }
}

class GenericArray {
    public static Class<?>[] getArray() {
        return new Class<?>[] { Collider.class, Reflector.class };
    }
}
