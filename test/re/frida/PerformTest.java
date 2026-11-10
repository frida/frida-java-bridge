package re.frida;

import static org.junit.Assert.assertEquals;

import android.app.Application;

import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

public class PerformTest {
    // Frida can attach after the app has called handleBindApplication() and
    // getPackageInfo(), but before currentApplication() returns its Application.
    // The hooks perform() waits on never fire then, as in this runner, which is
    // not an app: the script makes perform() take the app path, and the
    // Application shows up 100 ms later.
    @Test
    public void performRunsWhenNoHookFires() {
        script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "var app = null;" +
                "Java.performNow(function () {" +
                "  var ActivityThread = Java.use('android.app.ActivityThread');" +
                "  ActivityThread.currentApplication.implementation = function () {" +
                "    return app;" +
                "  };" +
                "  var lateApp = Java.use('re.frida.LateApplication').$new();" +
                "  setTimeout(function () {" +
                "    app = lateApp;" +
                "  }, 100);" +
                "});" +
                "Java._cachedIsAppProcess = true;" +
                "Java.perform(function () {" +
                "  send('performed');" +
                "});" +
                "})(LocalJava);");
        assertEquals("performed", script.getNextMessage());
    }

    private Script script = null;

    @After
    public void tearDown() throws IOException {
        if (script != null) {
            script.close();
            script = null;
        }
    }
}

class LateApplication extends Application {
    @Override
    public ClassLoader getClassLoader() {
        return LateApplication.class.getClassLoader();
    }

    @Override
    public File getCacheDir() {
        return new File(TestRunner.getCacheDir());
    }

    @Override
    public File getCodeCacheDir() {
        return new File(TestRunner.getCodeCacheDir());
    }
}
