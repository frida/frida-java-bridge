package re.frida;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Test;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.X509TrustManager;

public class ClassCreationTest {
    private static Object badgerObject = null;
    private static Class bananaClass = null;
    private static Class trustManagerClass = null;
    private static Class formatterClass = null;
    private static Class weirdTrustManagerClass = null;
    private static Class appleClass = null;
    private static Class simplePrimitiveArrayClass = null;
    private static Class myOutputClass1 = null;
    private static Class myOutputClass2 = null;
    private static Class orangeClass = null;
    private static Class userDefinedFieldClass = null;

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

    // Issue #119
    @Test
    public void interfaceWithFieldCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var EatableWithField = Java.use('re.frida.EatableWithField');" +
                "var Apple = Java.registerClass({" +
                "  name: 're.frida.Apple'," +
                "  implements: [EatableWithField]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'Apple';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams / 2;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').appleClass.value = Apple.class;");
        EatableWithField eatable = (EatableWithField) appleClass.newInstance();
        assertEquals("Apple", eatable.getName());
        assertEquals(25, eatable.getCalories(50));
        assertEquals(9000, eatable.MAX_CALORIES);
    }

    // Issue #121
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
                "    setIntArray: function (array, offset) {" +
                "      var s = '';" +
                "      for (var i = offset; i < array.length; i++)" +
                "        s += array[i];" +
                "      return s;" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').simplePrimitiveArrayClass.value = SimplePrimitiveArray.class;");
        PrimitiveArray primitiveArray = (PrimitiveArray) simplePrimitiveArrayClass.newInstance();
        assertEquals(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, primitiveArray.getByteArray()), true);
        assertEquals("345", primitiveArray.setIntArray(new int[] { 1, 2, 3, 4, 5 }, 2));
    }

    // Issue #122
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
                "Java.use('re.frida.ClassCreationTest').myOutputClass1.value = MyOutputStream.class;");
        OutputStream myOutput = (OutputStream) myOutputClass1.newInstance();
        myOutput.write(new byte[] { 1, 2, 3, 4, 5 });
        assertEquals("1,2,3,4,5", myOutput.toString());
        myOutput.write(new byte[] { 1, 2, 3, 4, 5 });
        assertEquals("1,2,3,4,5,1,2,3,4,5", myOutput.toString());
    }

    // Issue #122
    @Test
    public void extendingClassCanInvokeSuperMethod() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
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
                "Java.use('re.frida.ClassCreationTest').myOutputClass2.value = MyOutputStream.class;");
        OutputStream myOutput = (OutputStream) myOutputClass2.newInstance();
        myOutput.write(new byte[] { '1', '2', '3', '4', '5' });
        assertEquals("12345", myOutput.toString());
        myOutput.write(new byte[] { '1', '2', '3', '4', '5' });
        assertEquals("1234512345", myOutput.toString());
    }

    // Issue #124
    @Test
    public void derivedInterfaceCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        loadScript("var Fruit = Java.use('re.frida.Fruit');" +
                "var Orange = Java.registerClass({" +
                "  name: 're.frida.Orange'," +
                "  implements: [Fruit]," +
                "  methods: {" +
                "    getName: function () {" +
                "      return 'Orange';" +
                "    }," +
                "    getCalories: function (grams) {" +
                "      return grams * 3;" +
                "    }," +
                "    getTags: function () {" +
                "      return ['tasty', 'sweet'];" +
                "    }," +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').orangeClass.value = Orange.class;");
        Fruit fruit = (Fruit) orangeClass.newInstance();
        assertEquals("Orange", fruit.getName());
        assertEquals(150, fruit.getCalories(50));
        assertEquals(Arrays.equals(new String[] { "tasty", "sweet" }, fruit.getTags()), true);
    }

    // Issue #76/#133
    @Test
    public void classWithUserDefinedFieldsCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
        loadScript("var Formatter = Java.use('re.frida.Formatter');" +
                "var UserDefinedFields = Java.registerClass({" +
                "  name: 're.frida.StatefulFormatter'," +
                "  implements: [Formatter]," +
                "  fields: {" +
                "    lastInt: 'int'," +
                "    lastStr: 'java.lang.String'," +
                "  }," +
                "  methods: {" +
                "    format: [{" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: ['int']," +
                "      implementation: function (val) {" +
                "        const oldVal = this.lastInt.value;" +
                "        this.lastInt.value = val;" +
                "        return oldVal + ': ' + val;" +
                "      }" +
                "    }, {" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: ['java.lang.String']," +
                "      implementation: function (val) {" +
                "        const oldVal = this.lastStr.value;" +
                "        this.lastStr.value = val;" +
                "        return oldVal + ': ' + val;" +
                "      }" +
                "    }]" +
                "  }" +
                "});" +
                "Java.use('re.frida.ClassCreationTest').userDefinedFieldClass.value = UserDefinedFields.class;");
        Formatter formatter = (Formatter) userDefinedFieldClass.newInstance();
        assertEquals("0: 1", formatter.format(1));
        assertEquals("1: 2", formatter.format(2));
        assertEquals("null: First", formatter.format("First"));
        assertEquals("First: Second", formatter.format("Second"));
    }

    // Issue #134
    @Test
    public void classWithUserConstructorsCanBeImplemented() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException {
        loadScript("var StringBuilder = Java.use('java.lang.StringBuilder');" +
                "var OutputStream = Java.use('java.io.OutputStream');" +
                "var MyOutputStream = Java.registerClass({" +
                "  name: 're.frida.MyOutputSteamWithCtor'," +
                "  superClass: OutputStream," +
                "  fields: {" +
                "    buf: 'java.lang.StringBuilder'," +
                "  }," +
                "  methods: {" +
                "    $init: [{" +
                "      returnType: 'void'," +
                "      argumentTypes: []," +
                "      implementation: function () {" +
                "        this.$super.$init();" +
                "        this.buf.value = StringBuilder.$new();" +
                "      }" +
                "    }, {" +
                "      returnType: 'void'," +
                "      argumentTypes: ['java.lang.String']," +
                "      implementation: function (s) {" +
                "        this.$super.$init();" +
                "        this.buf.value = StringBuilder.$new(s);" +
                "      }" +
                "    }]," +
                "    write: [{" +
                "      returnType: 'void'," +
                "      argumentTypes: ['int']," +
                "      implementation: function (b) {" +
                "        this.buf.value.append('' + b);" +
                "      }" +
                "    }]," +
                "    toString: {" +
                "      returnType: 'java.lang.String'," +
                "      argumentTypes: []," +
                "      implementation: function () {" +
                "        return this.buf.value.toString();" +
                "      }" +
                "    }," +
                "  }" +
                "});" +
                "const myOutput1 = Java.cast(MyOutputStream.$new(), OutputStream);" +
                "myOutput1.write([1, 2, 3], 0, 3);" +
                "myOutput1.write(4);" +
                "send(myOutput1.toString());" +
                "const myOutput2 = Java.cast(MyOutputStream.$new('abc'), OutputStream);" +
                "myOutput2.write([1, 2, 3], 0, 3);" +
                "myOutput2.write(4);" +
                "send(myOutput2.toString());");
        assertEquals("1234", script.getNextMessage());
        assertEquals("abc1234", script.getNextMessage());
    }

    private Script script = null;

    private void loadScript(String code) {
        Script script = new Script(TestRunner.fridaJavaBundle +
                ";\n(function (Java) {" +
                "Java.perform(function () {" +
                "Java.classFactory.cacheDir = '" +
                        TestRunner.getCacheDir() + "';" +
                "Java.classFactory.codeCacheDir = '" +
                        TestRunner.getCodeCacheDir() + "';" +
                "Java.classFactory.loader = Java.cast(ptr('" +
                        TestRunner.classLoaderPointer +
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
