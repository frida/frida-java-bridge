package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class ClassCreationTest {
    private static Object badgerObject = null;
    private static Class bananaClass = null;
    private static Class trustManagerClass = null;
    private static Class formatterClass = null;
    private static Class weirdTrustManagerClass = null;

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

    @Test
    public void overloadedInterfaceMethodsCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var Formatter = Java.use('re.frida.Formatter');" +
                "var SimplerFormatter = Java.registerClass({" +
                "  name: 're.frida.SimpleFormatter'," +
                "  implements: [Formatter]," +
                "  methods: {" +
                "    format: [{" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: ['int']," +
                "      implementation: function (val) {" +
                "        return typeof val + ': ' + val;" +
                "      }" +
                "    }, {" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: ['java.lang.String']," +
                "      implementation: function (val) {" +
                "        return typeof val + ': \"' + val + '\"';" +
                "      }" +
                "    }]" +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').formatterClass.value = SimplerFormatter.class;");
        Formatter formatter = (Formatter) formatterClass.newInstance();
        assertEquals("number: 42", formatter.format(42));
        assertEquals("string: \"Hello\"", formatter.format("Hello"));
    }

    @Test
    public void interfaceMethodCanHaveUnrelatedOverload() throws ClassNotFoundException, InstantiationException,
           IllegalAccessException, CertificateException, NoSuchMethodException, InvocationTargetException {
        loadScript("var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');" +
                "var MyWeirdTrustManager = Java.registerClass({" +
                "  name: 'com.example.MyWeirdTrustManager'," +
                "  implements: [X509TrustManager]," +
                "  methods: {" +
                "    checkClientTrusted: function (chain, authType) {" +
                "      send('checkClientTrusted');" +
                "    }," +
                "    checkServerTrusted: [{" +
                "      returnType: 'void'," +
                "      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String']," +
                "      implementation: function (chain, authType) {" +
                "        send('checkServerTrusted A');" +
                "      }" +
                "    }, {" +
                "      returnType: 'java.util.List'," +
                "      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String']," +
                "      implementation: function (chain, authType, host) {" +
                "        send('checkServerTrusted B');" +
                "        return null;" +
                "      }" +
                "    }]," +
                "    getAcceptedIssuers: function () {" +
                "      send('getAcceptedIssuers');" +
                "      return [];" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').weirdTrustManagerClass.value = MyWeirdTrustManager.class;");
        X509TrustManager manager = (X509TrustManager) weirdTrustManagerClass.newInstance();
        X509Certificate[] emptyChain = new X509Certificate[0];

        manager.checkClientTrusted(emptyChain, "RSA");
        assertEquals("checkClientTrusted", script.getNextMessage());

        manager.checkServerTrusted(emptyChain, "RSA");
        assertEquals("checkServerTrusted A", script.getNextMessage());

        assertEquals(0, manager.getAcceptedIssuers().length);
        assertEquals("getAcceptedIssuers", script.getNextMessage());

        Method checkServerTrusted = manager.getClass().getMethod("checkServerTrusted",
            X509Certificate[].class,
            String.class,
            String.class);
        checkServerTrusted.invoke(manager, emptyChain, "RSA", "foo.bar.com");
        assertEquals("checkServerTrusted B", script.getNextMessage());
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
