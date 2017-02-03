package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import static org.junit.Assert.assertNull;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MethodTest {
    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    /*@Test
    public void callPropagatesExceptions() {
        Script script = loadScript("var Badger = Java.use('re.frida.Badger');" +
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
    public void TestNewInterface() {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "try{" +
                "  var tm = X509TrustManager.$new();" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('couldnt create trustmanager: ' + e);" +
                "}"
                );
        assertNull(failString);
    }
    
    @Test
    public void TestClassForName() {
        loadScript("var c = Java.use('java.lang.Class');" +
                "try{" +
                "  var orig = c.forName.overload('java.lang.String');" +
                "  c.forName.overload('java.lang.String').implementation = function(s){ orig(s); };" +
                "  var d = c.forName('re.frida.MethodTest');" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('class.forName shat the bed: ' + e);" +
                "}"
                );
        assertNull(failString);
    }*/
    
    /*public int ReturnZero()
    {
      return 0;
    }
    
    // this one was just hanging indefinitely during the test, but in an actual app, it was crashing
    //! either one of those is bad.
    @Test
    public void TestMethodInvoke() {
        loadScript("var c = Java.use('java.lang.reflect.Method');" +
                "var c2 = Java.use('java.lang.Class');" +
                "try{" +
                
                // hook the original
                "  var orig = c.invoke;" +
                "  c.invoke.implementation = function(obj, ...args){ orig(obj, args); };" +
                
                // now call it and see what happens
                "  var cl = c.forName('re.frida.MethodTest');" +
                "  var method = cl.getMethod('ReturnZero', 'int');" +
                "  var ret = method.invoke();" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('Method.invoke shat the bed: ' + e);" +
                "}"
                );
        assertNull(failString);
    }*/
    
    /*@Test
    public void TestNativeLibraryLoading() {
        loadScript("var c = Java.use('java.lang.System');" +
                "try{" +
                "  var orig = c.load;" +
                "  c.load.implementation = function(s){ orig(s); };" +
                "  c.load('/system/lib/libc.so')" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('System.load() shat the bed: ' + e);" +
                "}"
                );
        assertNull(failString);
        
        loadScript("var c = Java.use('java.lang.Runtime');" +
                "try{" +
                "  var orig = c.loadLibrary.overload('java.lang.String');" +
                "  c.loadLibrary.overload('java.lang.String').implementation = function(s){ orig(s); };" +
                
                // now look up the function again and call it
                "  var now = c.loadLibrary.overload('java.lang.String');" +
                "  now('/system/lib/libc.so')" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('Runtime.loadLibrary() shat the bed: ' + e);" +
                "}"
                );
        assertNull(failString);
    }*/
    
    private void DoAThingWithACypherMode( Cipher cipher )
    {
    }
    
    @Test
    public void TestConstantField() {
        loadScript("var c = Java.use('javax.crypto.Cipher');" +
                "var MethodTest = Java.use('re.frida.MethodTest');  " + 
                "try{" +
                "  MethodTest.DoAThingWithACypherMode.implementation = function(cipher){" +
                
                // make sure the mode is accessible to avoid a crash
                "    var theClass = c.class;" +
                "    var field = theClass.getDeclaredField('mode');" +
                "    field.setAccessible(true);" +
                
                // we've been passed a Cipher.  check and see which mode it is
                // it should be an int
                "    var cipherMode = field.getInt(cipher);" +
                "    var ENCRYPT_MODE = theClass.ENCRYPT_MODE;" +
                
                // we set the mode to Cipher.ENCRYPT_MODE
                // somehow Cipher.ENCRYPT_MODE is coming back as an object rather than an int
                "    if( cipherMode !== ENCRYPT_MODE ){" +
                "      MethodTest.Fail('TestFields: cipherMode !== ENCRYPT_MODE');" +
                "    }" +
                "  };" +
                "  " +
                "}catch(e){" + 
                
                // shouldnt reach here
                "  MethodTest.Fail('TestFields shat the bed: ' + e);" +
                "}"
                );
        
        // cipher boilerplate
        byte[] ivBytes = "1234567812345678".getBytes();
        byte[] key = "keykeykeykeykey!".getBytes();
        try{
          SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");        
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes)); 
          DoAThingWithACypherMode(cipher);
        }
        catch(Exception e){
        // this try/catch should never get triggered.  just put it here so the compiler would shut up
          assertNull("this shouldnt happen:" + e);
        }
        
        assertNull(failString);
    }
    
    static private String failString = null;
    static private void Fail( String msg )
    {
      failString = msg;
    }

    private Script script = null;

    private Script loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                code +
                "});" +
                "})(LocalJava);");
        this.script = script;
        return script;
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
    public void die() {
        throw new IllegalStateException("Already dead");
    }
}
