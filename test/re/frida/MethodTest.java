package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import static org.junit.Assert.assertNull;
import org.junit.rules.ExpectedException;

import javax.crypto.Cipher;
import java.io.IOException;
import javax.crypto.Cipher;
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
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    @Test
    public void genericReturnJavaLangClass() {
        loadScript("var c = Java.use ('java.lang.Class');" +
                "try {" +
                "  var orig = c.forName.overload('java.lang.String');" +
                "  c.forName.overload('java.lang.String').implementation = function (s) {" +
                "    orig.call(this,s);" +
                "  };" +
                "  var d = c.forName('re.frida.MethodTest');" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('class.forName failed. ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    @Test
    public void genericReturnBadger() {
        loadScript("var c = Java.use('re.frida.Badger');" +
                "try {" +
                "  var orig = c.forName;" +
                "  c.forName.implementation = function () { " +
                "    orig.call(this);" +
                "  };" +
                "  var d = c.forName();" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('forName failed. ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    // this one still just producing 
    // Error: access violation accessing 0xf2b295fe
    @Test
    public void nativeReturnGenericVmStack() { 
        loadScript(
                "try {" +
                "  var c = Java.use('dalvik.system.VMStack');" +
                "  var orig = c.getStackClass2;" +
                "  c.getStackClass2.implementation = function () {" +
                "    orig.call(this);" +
                "  };" +
                "  var stack = c.getStackClass2();" +
                "  send('ok');" +
                "} catch(e) {" + 
                "  send('nativeReturnGeneric: ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    // this one still just producing 
    // Error: access violation accessing 0x2133c66a
    @Test
    public void nativeReturnGenericBadgerWrapperAroundJavaLangClass() { 
        loadScript(
                "try {" +
                "  var c = Java.use('re.frida.Badger');" +
                "  var orig = c.forNameYo;" +
                "  c.forNameYo.implementation = function () {" +
                "    orig.call(this);" +
                "  };" +
                "  var test = c.forNameYo('re.frida.Badger', false, null);" +
                "  send('ok');" +
                "} catch(e) {" + 
                "  send('nativeReturnGeneric: ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    // this one was just hanging indefinitely during the test, but in an actual app, it was crashing
    //! either one of those is bad.
    @Test
    public void methodInvoke() {
        loadScript("var c = Java.use('java.lang.reflect.Method');" +
                "var c2 = Java.use('java.lang.Class');" +
                "try {" +
                
                // hook the original
                "  var orig = c.invoke;" +
                "  c.invoke.implementation = function (obj, ...args) { " +
                "    orig.call(this, obj, args);" +
                "  };" +
                
                // now call it and see what happens
                "  var cl = c2.forName('re.frida.Badger');" +
                "  var method = cl.getMethod('returnZero', 'int');" +
                "  var ret = method.invoke();" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('Method.invoke: ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    @Test
    public void loadWorks() {
        loadScript("var c = Java.use('java.lang.System');" +
                "try {" +
                "  var orig = c.load;" +
                "  c.load.implementation = function (s) { " +
                "    orig.call(this,s);" +
                "  };" +
                "  c.load('/system/lib/libc.so')" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('System.load: ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    @Test
    public void runtimeLoadLibrary() {        
        loadScript("var c = Java.use('java.lang.Runtime');" +
                "try {" +
                "  var orig = c.loadLibrary.overload('java.lang.String');" +
                "  c.loadLibrary.overload('java.lang.String').implementation = function (s) {" +
                "    orig.call(this,s);" +
                "  };" +
                
                // now look up the function again and call it
                "  var now = c.loadLibrary.overload('java.lang.String');" +
                "  now.call(this, '/system/lib/libc.so')" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('Runtime.loadLibrary: ' + e);" + 
                "}"
                );
        assertEquals("ok", script.getNextMessage());
    }
    
    @Test
    public void constructorReturnsCorrectType() {
        loadScript("var c = Java.use('javax.crypto.spec.SecretKeySpec');" +
                "try {" +
                "  var orig = c.$init.overload('[B', 'java.lang.String');" +
                "  c.$init.overload('[B', 'java.lang.String').implementation = function (a, b) { " +
                "    orig.call(this, a, b);" +
                "  };" +
                
                // now look up the function again and call it
                "  var testConstructor = c.$new( [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], 'AES' );" +
                "  send('ok');" +
                "} catch (e) {" + 
                "  send('SecretKeySpec: ' + e);" + 
                "}"
                );
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
    
    public static Class<?> forNameYo(String className, boolean shouldInitialize,
            ClassLoader classLoader) throws ClassNotFoundException {
        return java.lang.Class.forName(className, shouldInitialize, classLoader);
    }
    
    public int returnZero()
    {
        return 0;
    }
}
