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

    // @Test
    public void interfaceCanBeImplemented() {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "try {" +
                "  var tm = X509TrustManager.$new();" +
                "  send('ok');" +
                "} catch (e) {" +
                "  send('couldnt create trustmanager');" +
                "}");
        assertEquals("ok", script.getNextMessage());
    }

    // this one was just hanging indefinitely during the test, but in an actual app, it was crashing
    //! either one of those is bad.
    // @Test
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

    // @Test
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

    // @Test
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
