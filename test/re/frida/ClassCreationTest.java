package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class ClassCreationTest {
    private static Object badgerObject = null;
    private static Class bananaClass = null;
    private static Class trustManagerClass = null;

    @Test
    public void simpleClassCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var CustomBadger = Java.registerClass({" +
                "  name: 're.frida.CustomBadger'," +
                "  methods: {" +
                "    getName: {" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: []," +
                "      implementation: function () {" +
                "        return 'Fred';" +
                "      }," +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').badgerObject.value = CustomBadger.$new();");
    }

    @Test
    public void simpleInterfaceCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var Eatable = Java.use('re.frida.Eatable');" +
                "var Banana = Java.registerClass({" +
                "  name: 're.frida.Banana'," +
                "  implements: [Eatable]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'Banana';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams * 2;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').bananaClass.value = Banana.class;");
        Eatable eatable = (Eatable) bananaClass.newInstance();
        assertEquals("Banana", eatable.getName());
        assertEquals(100, eatable.getCalories(50));
    }

    @Test
    public void complexInterfaceCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException, CertificateException {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "var MyTrustManager = Java.registerClass({" +
                "  name: 'com.example.MyTrustManager'," +
                "  implements: [X509TrustManager]," +
                "  methods: {" +
                "    checkClientTrusted: function (chain, authType) {" +
                "    }," +
                "    checkServerTrusted: function (chain, authType) {" +
                "    }," +
                "    getAcceptedIssuers: function () {" +
                "      return [];" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').trustManagerClass.value = MyTrustManager.class;");
        X509TrustManager manager = (X509TrustManager) trustManagerClass.newInstance();
        X509Certificate[] emptyChain = new X509Certificate[0];
        manager.checkClientTrusted(emptyChain, "RSA");
        manager.checkServerTrusted(emptyChain, "RSA");
        assertEquals(new X509Certificate[0], manager.getAcceptedIssuers());
    }

    private Script script = null;

    private void loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                "Java.classFactory.loader = Java.cast(Memory.readPointer(ptr(" + TestRunner.classLoaderPointer +
                    ")), Java.use('java.lang.ClassLoader'));" +
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
