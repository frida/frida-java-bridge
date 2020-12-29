package re.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.lang.UnsupportedOperationException;
import javax.crypto.Cipher;

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
    public void primitiveArrayCanBeQueried() {
        loadScript("var Buffinator = Java.use('re.frida.Buffinator');" +
                "var buffinator = Buffinator.$new();" +
                "var buffer = Java.array('int', [ 13, 37 ]);" +
                "send('length' in buffer);" +
                "send('0' in buffer);" +
                "send('1' in buffer);" +
                "send('2' in buffer);" +
                "send(Object.getOwnPropertyNames(buffer));" +
                "send(Object.keys(buffer));" +
                "send(typeof buffer[Symbol('foo')]);");
        assertEquals("true", script.getNextMessage());
        assertEquals("true", script.getNextMessage());
        assertEquals("true", script.getNextMessage());
        assertEquals("false", script.getNextMessage());
        assertEquals("[\"0\",\"1\",\"length\"]", script.getNextMessage());
        assertEquals("[\"0\",\"1\",\"length\"]", script.getNextMessage());
        assertEquals("undefined", script.getNextMessage());
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
    public void methodWithCharArgumentCanBeInvoked() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var str = Badger.join(' ', [ 'Hello', 'World!' ]);" +
                "send(str);");
        assertEquals("Hello World!", script.getNextMessage());
    }

    @Test
    public void methodWithBoolObjectLongSignatureCanBeHooked() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var validate = Badger.validate;" +
                "validate.implementation = function (label, size) {" +
                    "send(label);" +
                    "send(size);" +
                    "return validate.call(this, label, size);" +
                "};");
        Badger badger = new Badger();
        assertEquals(true, badger.validate("awesome", 42));
        assertEquals("awesome", script.getNextMessage());
        assertEquals("42", script.getNextMessage());
        assertEquals(false, badger.validate("nope", 43));
        assertEquals("nope", script.getNextMessage());
        assertEquals("43", script.getNextMessage());
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
    public void callCanBeTraced() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "var returnZero = Badger.returnZero.clone({ traps: 'all', exceptions: 'propagate' });" +
                "var badger = Badger.$new();" +

                "Stalker.exclude(Process.getModuleByName('runner'));" +
                "Stalker.queueDrainInterval = 0;" +

                "Stalker.follow({" +
                    "events: {" +
                        "call: true," +
                    "}," +
                    "onCallSummary: function (summary) {" +
                        "send('onCallSummary');" +
                    "}" +
                "});" +

                "send(returnZero.call(badger));" +

                "Stalker.flush();");
        assertEquals("0", script.getNextMessage());
        assertEquals("onCallSummary", script.getNextMessage());
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
    public void replacementCanRetainInstance() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.returnZero.implementation = function () {" +
                    "var b = Java.retain(this);" +
                    "send(b.$h.equals(this.$h));" +
                    "setTimeout(processBadger, 50, b, this.id.value);" +
                    "return 1;" +
                "};" +
                "function processBadger(badger, id) {" +
                    "Java.perform(function () {" +
                        "send(badger.id.value === id);" +
                    "});" +
                "}");

        Badger badger = new Badger();

        assertEquals(badger.returnZero(), 1);
        assertEquals("false", script.getNextMessage());
        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void replacementCanRetainObjectParameter() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.eat.implementation = function (mushroom) {" +
                    "var m = Java.retain(mushroom);" +
                    "setTimeout(processMushroom, 50, m, mushroom.label.value);" +
                "};" +
                "function processMushroom(mushroom, label) {" +
                    "Java.perform(function () {" +
                        "send(mushroom.label.value === label);" +
                    "});" +
                "}");

        Badger badger = new Badger();

        Mushroom mushroom = new Mushroom();
        mushroom.label = "magic";
        badger.eat(mushroom);

        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void replacementCanRetainObjectArrayParameter() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.eatMany.implementation = function (mushrooms) {" +
                    "var mushroom = mushrooms[0];" +
                    "var m = Java.retain(mushroom);" +
                    "setTimeout(processMushroom, 50, m, mushroom.label.value);" +
                "};" +
                "function processMushroom(mushroom, label) {" +
                    "Java.perform(function () {" +
                        "send(mushroom.label.value === label);" +
                    "});" +
                "}");

        Badger badger = new Badger();

        badger.eatMany(new Mushroom[] { new Mushroom(), new Mushroom() });
        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void replacementCanAcceptStringArrayParameter() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.observe.implementation = function (labels) {" +
                    "return 'yes: ' + labels.join(', ');" +
                "};");

        Badger badger = new Badger();

        assertEquals("yes: a, , b",
                badger.observe(new String[] { "a", null, "b" }));
    }

    @Test
    public void replacementCanRetainByteArrayParameter() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.eatBytes.implementation = function (bytes) {" +
                    "var b = Java.retain(bytes);" +
                    "setTimeout(processMushroom, 50, b, bytes[0]);" +
                "};" +
                "function processMushroom(bytes, firstByte) {" +
                    "Java.perform(function () {" +
                        "send(bytes[0] === firstByte);" +
                    "});" +
                "}");

        Badger badger = new Badger();

        badger.eatBytes(new byte[] { 42, 24 });
        assertEquals("true", script.getNextMessage());
    }

    @Test
    public void replacementCanRetainReturnedObject() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.makeMushroom.implementation = function () {" +
                    "var mushroom = this.makeMushroom();" +
                    "var m = Java.retain(mushroom);" +
                    "setTimeout(processMushroom, 50, m, mushroom.label.value);" +
                    "return mushroom;" +
                "};" +
                "function processMushroom(mushroom, label) {" +
                    "Java.perform(function () {" +
                        "send(mushroom.label.value === label);" +
                    "});" +
                "}");

        Badger badger = new Badger();

        Mushroom mushroom = badger.makeMushroom();
        assertEquals("tasty", mushroom.label);

        assertEquals("true", script.getNextMessage());
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
    public void replacementCanBeReverted() {
        loadScript("var Snake = Java.use('re.frida.Snake');" +
                "Snake.die.implementation = function () {};" +
                "Snake.die.implementation = null;");

        Snake snake = new Snake();

        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("Snakes cannot die");
        snake.die();
    }

    @Test
    public void replacementShouldBeRevertedOnUnload() throws IOException {
        loadScript("var Mushroom = Java.use('re.frida.Mushroom');" +
                "Mushroom.die.implementation = function () {};");
        unloadScript();

        Mushroom mushroom = new Mushroom();

        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("Mushrooms cannot die");
        mushroom.die();
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

        Class<?> reflector = Reflector.class;
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

    // Issue #143
    @Test
    public void instanceFieldAttributeCanBeRead() {
        loadScript("var Cipher = Java.use('javax.crypto.Cipher');" +
                "send('' + Cipher.provider.fieldType);" +
                "send('' + Cipher.provider.fieldReturnType.className);");
        assertEquals("2", script.getNextMessage());
        assertEquals("java.security.Provider", script.getNextMessage());
    }

    // Issue #143
    @Test
    public void instanceFieldValueCanNotBeRead() {
        loadScript("var Cipher = Java.use('javax.crypto.Cipher');" +
                "try {" +
                "  send(Cipher.provider.value);" +
                "} catch (e) {" +
                "  send(e.message);" +
                "}");
        assertEquals("Cannot access an instance field without an instance", script.getNextMessage());
    }

    @Test
    public void performNowWorks() {
        loadScript("var JString = Java.use('java.lang.String');" +
                "var str = JString.$new('Hello');" +
                "send(str.toString());",
                "performNow");
        assertEquals("Hello", script.getNextMessage());
    }

    @Test
    public void replacementCanAcceptModifiedUTF8StringParameter() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.eatString.implementation = function (str) {" +
                    "send('yes');" +
                "};");

        Badger badger = new Badger();
        badger.feedString();
        assertEquals("yes", script.getNextMessage());
    }

    @Test
    public void nativeMethodCanBeReplaced() {
        loadScript("var Badger = Java.use('re.frida.Badger');" +
                "Badger.nativeMethod.implementation = function (str) {" +
                    "send(str);" +
                "};");

        Badger badger = new Badger();
        badger.nativeMethod("randomString");
        assertEquals("randomString", script.getNextMessage());
    }

    private Script script = null;

    private void loadScript(String code) {
        loadScript(code, "perform");
    }

    private void loadScript(String code, String performMethodName) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java." + performMethodName + "(function () {" +
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
    public int id;

    private static int nextId = 1;

    public Badger() {
        id = nextId++;
    }

    public native void nativeMethod(String arg);

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

    public void eat(Mushroom mushroom) {
    }

    public void eatMany(Mushroom[] mushrooms) {
    }

    public String observe(String[] labels) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i != labels.length; i++) {
            String label = labels[i];
            if (label != null) {
                result.append(labels);
            }
        }

        return result.toString();
    }

    public void eatString(String label) {
    }

    public void feedString() {
        StringBuilder sb = new StringBuilder();
        sb.append("apple");
        sb.append(String.valueOf((char) 0x00));
        eatString(sb.toString());
    }

    public void eatBytes(byte[] bytes) {
    }

    public Mushroom makeMushroom() {
        Mushroom mushroom = new Mushroom();
        mushroom.label = "tasty";
        return mushroom;
    }

    public static String join(char delimiter, String... values) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i != values.length; i++) {
            if (i > 0) {
                result.append(delimiter);
            }
            result.append(values[i]);
        }

        return result.toString();
    }

    public final boolean validate(String label, long size) {
        return label.equals("awesome") && size == 42;
    }
}

class Snake {
    public void die() {
        throw new UnsupportedOperationException("Snakes cannot die");
    }
}

class Mushroom {
    public String label = "generic";

    public void die() {
        throw new UnsupportedOperationException("Mushrooms cannot die");
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
