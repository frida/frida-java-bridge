package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import static org.junit.Assert.assertNull;
import org.junit.rules.ExpectedException;

import javax.crypto.Cipher;
import java.io.IOException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    public void interfaceCannotBeInstantiated() {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "try {" +
                "  var tm = X509TrustManager.$new();" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('couldnt create trustmanager');" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    @Test
    public void genericReturnJavaLangClass() {
        loadScript("var C = Java.use('java.lang.Class');" +
                "try {" +
                "  var method1 = C.forName.overload('java.lang.String');" +
                "  method1.implementation = function (s) {" +
                "    return method1.call(this, s);" +
                "  };" +
                "  var d = C.forName('re.frida.MethodTest');" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('class.forName failed. ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    @Test
    public void genericReturnBadger() {
        loadScript("var C = Java.use('re.frida.Badger');" +
                "try {" +
                "  var method1 = C.forName;" +
                "  method1.implementation = function () {" +
                "    return method1.call(this);" +
                "  };" +
                "  var d = C.forName();" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('forName failed. ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    // this one still just producing
    // Error: access violation accessing 0xf2b295fe
    @Test
    public void nativeReturnGenericVmStack() {
        loadScript(
                "try {" +
                "  var C = Java.use('dalvik.system.VMStack');" +
                "  var method1 = C.getStackClass2;" +
                "  method1.implementation = function () {" +
                "    return method1.call(this);" +
                "  };" +
                "  var stack = C.getStackClass2();" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('nativeReturnGeneric: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    // this one still just producing
    // Error: access violation accessing 0x2133c66a
    @Test
    public void nativeReturnGenericBadgerWrapperAroundJavaLangClass() {
        loadScript(
                "try {" +
                "  var C = Java.use('re.frida.Badger');" +
                "  var method1 = C.forNameYo;" +
                "  method1.implementation = function () {" +
                "    return method1.call(this);" +
                "  };" +
                "  var test = C.forNameYo('re.frida.Badger', false, null);" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('nativeReturnGeneric: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    // this one was just hanging indefinitely during the test, but in an actual app, it was crashing
    //! either one of those is bad.
    //@Test
    public void methodInvoke() {
        loadScript("var C = Java.use('java.lang.reflect.Method');" +
                "var C2 = Java.use('java.lang.Class');" +
                "try {" +
                // hook the original
                "  var method1 = C.invoke;" +
                "  method1.implementation = function () {" +
                "    return method1.apply(this, arguments);" +
                "  };" +

                // now call it and see what happens
                "  var cl = C2.forName('re.frida.Badger');" +
                "  var method2 = cl.getMethod('returnZero', 'int');" +
                "  var ret = method2.invoke();" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('Method.invoke: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    @Test
    public void loadWorks() {
        loadScript("var C = Java.use('java.lang.System');" +
                "try {" +
                "  var method1 = C.load;" +
                "  method1.implementation = function (s) {" +
                "    return method1.call(this, s);" +
                "  };" +
                "  C.load('/system/lib/libc.so');" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('System.load: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    @Test
    public void runtimeLoadLibrary() {
        loadScript("var C = Java.use('java.lang.Runtime');" +
                "try {" +
                "  var method1 = C.loadLibrary.overload('java.lang.String');" +
                "  method1.implementation = function (s) {" +
                "    return method1.call(this, s);" +
                "  };" +

                // now look up the function again and call it
                "  var now = C.loadLibrary.overload('java.lang.String');" +
                "  now.call(C, '/system/lib/libc.so');" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('Runtime.loadLibrary: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    //@Test
    public void constructorReturnsCorrectType() {
        loadScript("var C = Java.use('javax.crypto.spec.SecretKeySpec');" +
                "try {" +
                "  var method1 = C.$init.overload('[B', 'java.lang.String');" +
                "  method1.implementation = function (a, b) {" +
                "    return method1.call(this, a, b);" +
                "  };" +

                // now look up the function again and call it
                "  var testConstructor = C.$new([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 'AES');" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('SecretKeySpec: ' + e);" +
                "}");
        assertEquals("ok", script.getNextMessage());
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

    public static Class<?> forNameYo(String className, boolean shouldInitialize, ClassLoader classLoader) throws ClassNotFoundException {
        return java.lang.Class.forName(className, shouldInitialize, classLoader);
    }

    public int returnZero() {
        return 0;
    }
}
