package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.util.Arrays;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class ClassCreationTest {
    private static Object badgerObject = null;
    private static Class bananaClass = null;
    private static Class hasFieldClass = null;
    private static Class primitiveArrayClass = null;
    private static Class myOutputClass = null;
    private static Class trustManagerClass = null;
    private static Class formatterClass = null;
    private static Class weirdTrustManagerClass = null;
    private HasField hasField;

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
        assertEquals(0, manager.getAcceptedIssuers().length);
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

    // Testcase for Issue #119
    @Test
    public void interfaceHasFieldCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var HasField = Java.use('re.frida.HasField');" +
                "var SimpleHasField = Java.registerClass({" +
                "  name: 're.frida.SimpleHasField'," +
                "  implements: [HasField]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'hasField';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams * 2;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').hasFieldClass.value = SimpleHasField.class;");
        HasField hasField = (HasField) hasFieldClass.newInstance();
        assertEquals("hasField", hasField.getName());
        assertEquals(100, hasField.getCalories(50));
        assertEquals("Field", hasField.field);
    }

    // Testcase for Issue #121
    @Test
    public void primitiveArrayInterfaceMethodsCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var PrimitiveArray = Java.use('re.frida.PrimitiveArray');" +
                "var SimplePrimitiveArray = Java.registerClass({" +
                "  name: 're.frida.SimplePrimitiveArray'," +
                "  implements: [PrimitiveArray]," +
                "  methods: {" +
                "    getByteArray: [{" +
                "      returnType: '[B'," +
                "      argumentTypes: []," +
                "      implementation: function () {" +
                "        return [1, 2, 3, 4, 5];" +
                "      }" +
                "    }]," +
                "    setIntArray: function (array, off) {" +
                "      var s = '';" +
                "      for (var i = off; i < array.length; i++) s += array[i];" +
                "      return s;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').primitiveArrayClass.value = SimplePrimitiveArray.class;");
        PrimitiveArray primitiveArray = (PrimitiveArray) primitiveArrayClass.newInstance();
        assertEquals(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, primitiveArray.getByteArray()), true);
        assertEquals("345", primitiveArray.setIntArray(new int[] { 1, 2, 3, 4, 5 }, 2));
    }

    // Testcase for Issue #122
    @Test
    public void extendingClassCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
        loadScript("const bytes = [];" +
                "var MyOutputStream = Java.registerClass({" +
                "  name: 're.frida.MyOutputSteam'," +
                "  superClass: Java.use('java.io.OutputStream')," +
                "  methods: {" +
                "    write: [{" +
                "      returnType: 'void'," +
                "      argumentTypes: ['int']," +
                "      implementation: function (b) {" +
                "        bytes.push(b);" +
                "      }" +
                "    }]," +
                "    toString: {" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: []," +
                "      implementation: function () {" +
                "        return bytes.join(',');" +
                "      }" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').myOutputClass.value = MyOutputStream.class;");
        OutputStream myOutput = (OutputStream) myOutputClass.newInstance();
        myOutput.write(new byte[] { 1, 2, 3, 4, 5 });
        assertEquals("1,2,3,4,5", myOutput.toString());
        myOutput.write(new byte[] { 1, 2, 3, 4, 5 });
        assertEquals("1,2,3,4,5,1,2,3,4,5", myOutput.toString());
    }

    // Testcase for Issue #122
    @Test
    public void extendingClassCanInvoekSuperMethod() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
        loadScript("var SuperClass = Java.use('java.io.ByteArrayOutputStream');" +
                "var MyOutputStream = Java.registerClass({" +
                "  name: 're.frida.MyOutputSteamEx'," +
                "  superClass: SuperClass," +
                "  methods: {" +
                "    write: [{" +
                "      returnType: 'void'," +
                "      argumentTypes: ['[B', 'int', 'int']," +
                "      implementation: function (b, off, len) {" +
                "        this.$super.write(b, off, len);" +
                "      }" +
                "    }, {" +
                "      returnType: 'void'," +
                "      argumentTypes: ['int']," +
                "      implementation: function (b) {" +
                "        this.$super.write(b);" +
                "      }" +
                "    }]," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').myOutputClass.value = MyOutputStream.class;");
        OutputStream myOutput = (OutputStream) myOutputClass.newInstance();
        myOutput.write(new byte[] { '1', '2', '3', '4', '5' });
        assertEquals("12345", myOutput.toString());
        myOutput.write(new byte[] { '1', '2', '3', '4', '5' });
        assertEquals("1234512345", myOutput.toString());
    }

    // Testcase for Issue #124
    @Test
    public void extendInterfaceCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var Eatable = Java.use('re.frida.Eatable');" +
                "var EatableEx = Java.use('re.frida.EatableEx');" +
                "var BananaEx = Java.registerClass({" +
                "  name: 're.frida.BananaEx'," +
                "  implements: [EatableEx, Eatable]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'Banana';" +
                "    }," +
                "    getNameEx: function () {" +
                "      return 'BananaEx';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams * 2;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').bananaClass.value = BananaEx.class;");
        EatableEx eatable = (EatableEx) bananaClass.newInstance();
        assertEquals("Banana", eatable.getName());
        assertEquals("BananaEx", eatable.getNameEx());
        assertEquals(100, eatable.getCalories(50));
    }

    private Script script = null;

    private void loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                "Java.classFactory.loader = Java.cast(ptr('" + TestRunner.classLoaderPointer +
                    "').readPointer(), Java.use('java.lang.ClassLoader'));" +
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
