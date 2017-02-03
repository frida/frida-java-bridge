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
    
    @Test
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
    
     @Test
    public void TestClassForName() {
        loadScript("var class = Java.use('java.lang.Class');" +
                "try{" +
                "  var orig = class.overload('java.lang.String')" +
                "  class.overload('java.lang.String').implementation = function(s){ orig(s); }" +
                "}catch(e){" + 
                "  var MethodTest = Java.use('re.frida.MethodTest');" +
                "  MethodTest.Fail('couldnt create trustmanager: ' + e);" +
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
