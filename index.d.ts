declare module "frida-java-bridge" {
    namespace Java {
        /**
         * Whether the current process has a Java runtime loaded. Do not invoke any other Java properties or
         * methods unless this is the case.
         */
        const available: boolean;

        /**
         * Which version of Android we're running on.
         */
        const androidVersion: string;

        const ACC_PUBLIC: number;
        const ACC_PRIVATE: number;
        const ACC_PROTECTED: number;
        const ACC_STATIC: number;
        const ACC_FINAL: number;
        const ACC_SYNCHRONIZED: number;
        const ACC_BRIDGE: number;
        const ACC_VARARGS: number;
        const ACC_NATIVE: number;
        const ACC_ABSTRACT: number;
        const ACC_STRICT: number;
        const ACC_SYNTHETIC: number;

        /**
         * Calls `func` with the `obj` lock held.
         *
         * @param obj Instance whose lock to hold.
         * @param fn Function to call with lock held.
         */
        function synchronized(obj: Wrapper, fn: () => void): void;

        /**
         * Enumerates loaded classes.
         *
         * @param callbacks Object with callbacks.
         */
        function enumerateLoadedClasses(callbacks: EnumerateLoadedClassesCallbacks): void;

        /**
         * Synchronous version of `enumerateLoadedClasses()`.
         */
        function enumerateLoadedClassesSync(): string[];

        /**
         * Enumerates class loaders.
         *
         * You may pass such a loader to `Java.ClassFactory.get()` to be able to
         * `.use()` classes on the specified class loader.
         *
         * @param callbacks Object with callbacks.
         */
        function enumerateClassLoaders(callbacks: EnumerateClassLoadersCallbacks): void;

        /**
         * Synchronous version of `enumerateClassLoaders()`.
         */
        function enumerateClassLoadersSync(): Wrapper[];

        /**
         * Enumerates methods matching `query`.
         *
         * @param query Query specified as `class!method`, with globs permitted. May
         *              also be suffixed with `/` and one or more modifiers:
         *              - `i`: Case-insensitive matching.
         *              - `s`: Include method signatures, so e.g. `"putInt"` becomes
         *                `"putInt(java.lang.String, int): void"`.
         *              - `u`: User-defined classes only, ignoring system classes.
         */
        function enumerateMethods(query: string): EnumerateMethodsMatchGroup[];

        /**
         * Runs `fn` on the main thread of the VM.
         *
         * @param fn Function to run on the main thread of the VM.
         */
        function scheduleOnMainThread(fn: () => void): void;

        /**
         * Ensures that the current thread is attached to the VM and calls `fn`.
         * (This isn't necessary in callbacks from Java.)
         *
         * Will defer calling `fn` if the app's class loader is not available yet.
         * Use `Java.performNow()` if access to the app's classes is not needed.
         *
         * @param fn Function to run while attached to the VM.
         */
        function perform(fn: () => void): void;

        /**
         * Ensures that the current thread is attached to the VM and calls `fn`.
         * (This isn't necessary in callbacks from Java.)
         *
         * @param fn Function to run while attached to the VM.
         */
        function performNow(fn: () => void): void;

        /**
         * Dynamically generates a JavaScript wrapper for `className` that you can
         * instantiate objects from by calling `$new()` on to invoke a constructor.
         * Call `$dispose()` on an instance to clean it up explicitly, or wait for
         * the JavaScript object to get garbage-collected, or script to get
         * unloaded. Static and non-static methods are available, and you can even
         * replace method implementations.
         *
         * Uses the app's class loader, but you may access classes on other loaders
         * by calling `Java.ClassFactory.get()`.
         *
         * @param className Canonical class name to get a wrapper for.
         */
        function use<T extends Members<T> = {}>(className: string): Wrapper<T>;

        /**
         * Opens the .dex file at `filePath`.
         *
         * @param filePath Path to .dex to open.
         */
        function openClassFile(filePath: string): DexFile;

        /**
         * Enumerates live instances of the `className` class by scanning the Java
         * VM's heap.
         *
         * @param className Name of class to enumerate instances of.
         * @param callbacks Object with callbacks.
         */
        function choose<T extends Members<T> = {}>(className: string, callbacks: ChooseCallbacks<T>): void;

        /**
         * Duplicates a JavaScript wrapper for later use outside replacement method.
         *
         * @param obj An existing wrapper retrieved from `this` in replacement method.
         */
        function retain<T extends Members<T> = {}>(obj: Wrapper<T>): Wrapper<T>;

        /**
         * Creates a JavaScript wrapper given the existing instance at `handle` of
         * given class `klass` as returned from `Java.use()`.
         *
         * @param handle An existing wrapper or a JNI handle.
         * @param klass Class wrapper for type to cast to.
         */
        function cast<From extends Members<From> = {}, To extends Members<To> = {}>(
            handle: Wrapper<From> | NativePointerValue,
            klass: Wrapper<To>,
        ): Wrapper<To>;

        /**
         * Creates a Java array with elements of the specified `type`, from a
         * JavaScript array `elements`. The resulting Java array behaves like
         * a JS array, but can be passed by reference to Java APIs in order to
         * allow them to modify its contents.
         *
         * @param type Type name of elements.
         * @param elements Array of JavaScript values to use for constructing the
         *                 Java array.
         */
        function array(type: string, elements: any[]): any[];

        /**
         * Generates a backtrace for the current thread.
         *
         * @param options Options to customize the stack-walking.
         */
        function backtrace(options?: BacktraceOptions): Backtrace;

        /**
         * Determines whether the caller is running on the main thread.
         */
        function isMainThread(): boolean;

        /**
         * Creates a new Java class.
         *
         * @param spec Object describing the class to be created.
         */
        function registerClass(spec: ClassSpec): Wrapper;

        /**
         * Forces the VM to execute everything with its interpreter. Necessary to
         * prevent optimizations from bypassing method hooks in some cases, and
         * allows ART's Instrumentation APIs to be used for tracing the runtime.
         */
        function deoptimizeEverything(): void;

        /**
         * Similar to deoptimizeEverything but only deoptimizes boot image code.
         * Use with `dalvik.vm.dex2oat-flags --inline-max-code-units=0` for best
         * results.
         */
        function deoptimizeBootImage(): void;

        const vm: VM;

        /**
         * The default class factory used to implement e.g. `Java.use()`.
         * Uses the application's main class loader.
         */
        const classFactory: ClassFactory;

        interface EnumerateLoadedClassesCallbacks {
            /**
             * Called with the name of each currently loaded class, and a JNI
             * reference for its Java Class object.
             *
             * Pass the `name` to `Java.use()` to get a JavaScript wrapper.
             * You may also `Java.cast()` the `handle` to `java.lang.Class`.
             */
            onMatch: (name: string, handle: NativePointer) => void;

            /**
             * Called when all loaded classes have been enumerated.
             */
            onComplete: () => void;
        }

        interface EnumerateClassLoadersCallbacks {
            /**
             * Called with a `java.lang.ClassLoader` wrapper for each class loader
             * found in the VM.
             */
            onMatch: (loader: Wrapper) => void;

            /**
             * Called when all class loaders have been enumerated.
             */
            onComplete: () => void;
        }

        /**
         * Matching methods grouped by class loader.
         */
        interface EnumerateMethodsMatchGroup {
            /**
             * Class loader, or `null` for the bootstrap class loader.
             *
             * Typically passed to `ClassFactory.get()` to interact with classes of
             * interest.
             */
            loader: Wrapper | null;

            /**
             * One or more matching classes that have one or more methods matching
             * the given query.
             */
            classes: [EnumerateMethodsMatchClass, ...EnumerateMethodsMatchClass[]];
        }

        /**
         * Class matching query which has one or more matching methods.
         */
        interface EnumerateMethodsMatchClass {
            /**
             * Class name that matched the given query.
             */
            name: string;

            /**
             * One or more matching method names, each followed by signature when
             * the `s` modifier is used.
             */
            methods: [string, ...string[]];
        }

        interface ChooseCallbacks<T extends Members<T> = {}> {
            /**
             * Called with each live instance found with a ready-to-use `instance`
             * just as if you would have called `Java.cast()` with a raw handle to
             * this particular instance.
             *
             * May return `EnumerateAction.Stop` to stop the enumeration early.
             */
            // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
            onMatch: (instance: Wrapper<T>) => void | EnumerateAction;

            /**
             * Called when all instances have been enumerated.
             */
            onComplete: () => void;
        }

        /**
         * Options that may be passed to `Java.backtrace()`.
         */
        interface BacktraceOptions {
            /**
             * Limit how many frames up the stack to walk. Defaults to 16.
             */
            limit?: number;
        }

        /**
         * Backtrace returned by `Java.backtrace()`.
         */
        interface Backtrace {
            /**
             * ID that can be used for deduplicating identical backtraces.
             */
            id: string;

            /**
             * Stack frames.
             */
            frames: Frame[];
        }

        interface Frame {
            /**
             * Signature, e.g. `"Landroid/os/Looper;,loopOnce,(Landroid/os/Looper;JI)Z"`.
             */
            signature: string;

            /**
             * Where the code is from, i.e. the filesystem path to the `.dex` on Android.
             */
            origin: string;

            /**
             * Class name that method belongs to, e.g. `"android.os.Looper"`.
             */
            className: string;

            /**
             * Method name, e.g. `"loopOnce"`.
             */
            methodName: string;

            /**
             * Method flags. E.g. `Java.ACC_PUBLIC | Java.ACC_STATIC`.
             */
            methodFlags: number;

            /**
             * Source file name, e.g. `"Looper.java"`.
             */
            fileName: string;

            /**
             * Source line number, e.g. `201`.
             */
            lineNumber: number;
        }

        type Members<T> = Record<keyof T, MethodDispatcher | Field>;

        /**
         * Dynamically generated wrapper for any Java class, instance, or interface.
         */
        type Wrapper<T extends Members<T> = {}> =
            & {
                /**
                 * Automatically inject holder's type to all fields and methods
                 */
                [K in keyof T]: T[K] extends Field<infer Value> ? Field<Value, T> : MethodDispatcher<T>;
            }
            & {
                /**
                 * Allocates and initializes a new instance of the given class.
                 *
                 * Use this to create a new instance.
                 */
                $new: MethodDispatcher<T>;

                /**
                 * Allocates a new instance without initializing it.
                 *
                 * Call `$init()` to initialize it.
                 */
                $alloc: MethodDispatcher<T>;

                /**
                 * Initializes an instance that was allocated but not yet initialized.
                 * This wraps the constructor(s).
                 *
                 * Replace the `implementation` property to hook a given constructor.
                 */
                $init: MethodDispatcher<T>;

                /**
                 * Eagerly deletes the underlying JNI global reference without having to
                 * wait for the object to become unreachable and the JavaScript
                 * runtime's garbage collector to kick in (or script to be unloaded).
                 *
                 * Useful when a lot of short-lived objects are created in a loop and
                 * there's a risk of running out of global handles.
                 */
                $dispose(): void;

                /**
                 * Retrieves a `java.lang.Class` wrapper for the current class.
                 */
                class: Wrapper;

                /**
                 * Canonical name of class being wrapped.
                 */
                $className: string;

                /**
                 * Method and field names exposed by this object’s class, not including
                 * parent classes.
                 */
                $ownMembers: string[];

                /**
                 * Instance used for chaining up to super-class method implementations.
                 */
                $super: Wrapper;

                /**
                 * Methods and fields.
                 */
                [name: string]: any;
            };

        type IsEmptyArray<T extends any[]> = T extends [] ? true : false;

        type Overload<Identifiers extends Array<string> = [], Types extends Array<any> = [], Return = any> = [Identifiers, Types, Return];

        type OverloadsMethods<
            Holder extends Members<Holder> = {},
            OLs extends ReadonlyArray<Overload<any, any, any>> = []
        > = {
                [K in keyof OLs]:
                OLs[K] extends Overload<any, infer A extends any[], infer R>
                ? Method<Holder, A, R>
                : never
            };

        interface MethodDispatcher<Holder extends Members<Holder> = {}, Overloads extends Array<Overload<Array<any>, Array<any>, any>> = []> extends Method<Holder> {
            /**
             * Available overloads.
             */
            overloads: IsEmptyArray<Overloads> extends true ? Array<Method<Holder>> : OverloadsMethods<Holder, Overloads>;

            /**
             * Obtains a specific overload.
             *
             * @param args Signature of the overload to obtain.
             *             For example: `"java.lang.String", "int"`.
             */
            overload(...args: string[]): Method<Holder>;
        }

        interface Method<Holder extends Members<Holder> = {}, Params extends any[] = any[], Return = any> {
            (...params: Params): Return;

            /**
             * Name of this method.
             */
            methodName: string;

            /**
             * Class that this method belongs to.
             */
            holder: Wrapper<Holder>;

            /**
             * What kind of method this is, i.e. constructor vs static vs instance.
             */
            type: MethodType;

            /**
             * Pointer to the VM's underlying method object.
             */
            handle: NativePointer;

            /**
             * Implementation. Assign a new implementation to this property to
             * replace the original implementation. Assign `null` at a future point
             * to revert back to the original implementation.
             */
            implementation: MethodImplementation<Holder, Params, Return> | null;

            /**
             * Method return type.
             */
            returnType: Type;

            /**
             * Method argument types.
             */
            argumentTypes: Type[];

            /**
             * Queries whether the method may be invoked with a given argument list.
             */
            canInvokeWith: (...args: any[]) => boolean;

            /**
             * Makes a new method wrapper with custom NativeFunction options.
             *
             * Useful for e.g. setting `traps: "all"` to perform execution tracing
             * in conjunction with Stalker.
             */
            clone: (options: NativeFunctionOptions) => Method<Holder, Params, Return>;
        }

        type MethodImplementation<This extends Members<This> = {}, Params extends any[] = any[], Return = any> = (this: Wrapper<This>, ...params: Params) => Return;

        interface Field<Value = any, Holder extends Members<Holder> = {}> {
            /**
             * Current value of this field. Assign to update the field's value.
             */
            value: Value;

            /**
             * Class that this field belongs to.
             */
            holder: Wrapper<Holder>;

            /**
             * What kind of field this is, i.e. static vs instance.
             */
            fieldType: FieldType;

            /**
             * Type of value.
             */
            fieldReturnType: Type;
        }

        // eslint-disable-next-line @definitelytyped/no-const-enum
        const enum MethodType {
            Constructor = 1,
            Static = 2,
            Instance = 3,
        }

        // eslint-disable-next-line @definitelytyped/no-const-enum
        const enum FieldType {
            Static = 1,
            Instance = 2,
        }

        interface Type {
            /**
             * VM type name. For example `I` for `int`.
             */
            name: string;

            /**
             * Frida type name. For example `pointer` for a handle.
             */
            type: string;

            /**
             * Size in words.
             */
            size: number;

            /**
             * Size in bytes.
             */
            byteSize: number;

            /**
             * Class name, if applicable.
             */
            className?: string | undefined;

            /**
             * Checks whether a given JavaScript `value` is compatible.
             */
            isCompatible: (value: any) => boolean;

            /**
             * Converts `value` from a JNI value to a JavaScript value.
             */
            fromJni?: ((value: any) => any) | undefined;

            /**
             * Converts `value` from a JavaScript value to a JNI value.
             */
            toJni?: ((value: any) => any) | undefined;

            /**
             * Reads a value from memory.
             */
            read?: ((address: NativePointerValue) => any) | undefined;

            /**
             * Writes a value to memory.
             */
            write?: ((address: NativePointerValue, value: any) => void) | undefined;
        }

        interface DexFile {
            /**
             * Loads the contained classes into the VM.
             */
            load(): void;

            /**
             * Determines available class names.
             */
            getClassNames(): string[];
        }

        interface ClassSpec {
            /**
             * Name of the class.
             */
            name: string;

            /**
             * Super-class. Omit to inherit from `java.lang.Object`.
             */
            superClass?: Wrapper | undefined;

            /**
             * Interfaces implemented by this class.
             */
            implements?: Wrapper[] | undefined;

            /**
             * Name and type of each field to expose.
             */
            fields?: {
                [name: string]: string;
            } | undefined;

            /**
             * Methods to implement. Use the special name `$init` to define one or more constructors.
             */
            methods?: {
                [name: string]: MethodImplementation | MethodSpec | MethodSpec[];
            } | undefined;
        }

        interface MethodSpec {
            /**
             * Return type. Defaults to `void` if omitted.
             */
            returnType?: string | undefined;

            /**
             * Argument types. Defaults to `[]` if omitted.
             */
            argumentTypes?: string[] | undefined;

            /**
             * Implementation.
             */
            implementation: MethodImplementation;
        }

        interface VM {
            /**
             * Ensures that the current thread is attached to the VM and calls `fn`.
             * (This isn't necessary in callbacks from Java.)
             *
             * @param fn Function to run while attached to the VM.
             */
            perform(fn: () => void): void;

            /**
             * Gets a wrapper for the current thread's `JNIEnv`.
             *
             * Throws an exception if the current thread is not attached to the VM.
             */
            getEnv(): Env;

            /**
             * Tries to get a wrapper for the current thread's `JNIEnv`.
             *
             * Returns `null` if the current thread is not attached to the VM.
             */
            tryGetEnv(): Env | null;
        }

        type Env = any;

        class ClassFactory {
            /**
             * Gets the class factory instance for a given class loader, or the
             * default factory when passing `null`.
             *
             * The default class factory used behind the scenes only interacts
             * with the application's main class loader. Other class loaders
             * can be discovered through APIs such as `Java.enumerateMethods()` and
             * `Java.enumerateClassLoaders()`, and subsequently interacted with
             * through this API.
             */
            static get(classLoader: Wrapper | null): ClassFactory;

            /**
             * Class loader currently being used. For the default class factory this
             * is updated by the first call to `Java.perform()`.
             */
            readonly loader: Wrapper | null;

            /**
             * Path to cache directory currently being used. For the default class
             * factory this is updated by the first call to `Java.perform()`.
             */
            cacheDir: string;

            /**
             * Naming convention to use for temporary files.
             *
             * Defaults to `{ prefix: "frida", suffix: "dat" }`.
             */
            tempFileNaming: TempFileNaming;

            /**
             * Dynamically generates a JavaScript wrapper for `className` that you can
             * instantiate objects from by calling `$new()` on to invoke a constructor.
             * Call `$dispose()` on an instance to clean it up explicitly, or wait for
             * the JavaScript object to get garbage-collected, or script to get
             * unloaded. Static and non-static methods are available, and you can even
             * replace method implementations.
             *
             * @param className Canonical class name to get a wrapper for.
             */
            use<T extends Members<T> = {}>(className: string): Wrapper<T>;

            /**
             * Opens the .dex file at `filePath`.
             *
             * @param filePath Path to .dex to open.
             */
            openClassFile(filePath: string): DexFile;

            /**
             * Enumerates live instances of the `className` class by scanning the Java
             * VM's heap.
             *
             * @param className Name of class to enumerate instances of.
             * @param callbacks Object with callbacks.
             */
            choose<T extends Members<T> = {}>(className: string, callbacks: ChooseCallbacks<T>): void;

            /**
             * Duplicates a JavaScript wrapper for later use outside replacement method.
             *
             * @param obj An existing wrapper retrieved from `this` in replacement method.
             */
            retain<T extends Members<T> = {}>(obj: Wrapper<T>): Wrapper<T>;

            /**
             * Creates a JavaScript wrapper given the existing instance at `handle` of
             * given class `klass` as returned from `Java.use()`.
             *
             * @param handle An existing wrapper or a JNI handle.
             * @param klass Class wrapper for type to cast to.
             */
            cast<From extends Members<From> = {}, To extends Members<To> = {}>(
                handle: Wrapper<From> | NativePointerValue,
                klass: Wrapper<To>,
            ): Wrapper<To>;

            /**
             * Creates a Java array with elements of the specified `type`, from a
             * JavaScript array `elements`. The resulting Java array behaves like
             * a JS array, but can be passed by reference to Java APIs in order to
             * allow them to modify its contents.
             *
             * @param type Type name of elements.
             * @param elements Array of JavaScript values to use for constructing the
             *                 Java array.
             */
            array(type: string, elements: any[]): any[];

            /**
             * Creates a new Java class.
             *
             * @param spec Object describing the class to be created.
             */
            registerClass(spec: ClassSpec): Wrapper;
        }

        interface TempFileNaming {
            /**
             * File name prefix to use.
             *
             * For example: `frida`.
             */
            prefix: string;

            /**
             * File name suffix to use.
             *
             * For example: `dat`.
             */
            suffix: string;
        }
    }

    export default Java;
}
