package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;

public class HookTest {
    private Script script = null;

    private Script createScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle + ";\n(function (Java) {" + code + "})(LocalJava);");
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

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void propagatesExceptions() {
        Script script = createScript("" +
                "Java.perform(function () {" +
                    "var Badger = Java.use('re.frida.HookTest$Badger');" +
                    "Badger.die.implementation = function () {" +
                        "this.die();" +
                    "};" +
                "});");

        Badger badger = new Badger();

        thrown.expect(IllegalStateException.class);
        thrown.expectMessage("Already dead");
        badger.die();
    }

    private class Badger {
        public void die() {
            throw new IllegalStateException("Already dead");
        }
    }
}
