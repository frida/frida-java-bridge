package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import static org.junit.Assert.assertNull;
import org.junit.rules.ExpectedException;

import java.io.IOException;

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
    }*/
    
    static private String failString = null;
    static private void Fail( String msg )
    {
      failString = msg;
    }
    
    //@Test
    /*public void TestNewInterface() {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "try{" +
                "  var tm = X509TrustManager.$new();" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('couldnt create trustmanager: ' + e);" +
                "}"
                );
        assertNull(failString);
    }*/
    
    /*@Test
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
    
    public int ReturnZero()
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
