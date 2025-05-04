import Env from './env.js';

const JNILocalRefType = 1;

let vm = null;

let primitiveArrayHandler = null;

export function initialize (_vm) {
  vm = _vm;
}

/*
 * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
 * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
 */
export function getType (typeName, unbox, factory) {
  let type = getPrimitiveType(typeName);
  if (type === null) {
    if (typeName.indexOf('[') === 0) {
      type = getArrayType(typeName, unbox, factory);
    } else {
      if (typeName[0] === 'L' && typeName[typeName.length - 1] === ';') {
        typeName = typeName.substring(1, typeName.length - 1);
      }
      type = getObjectType(typeName, unbox, factory);
    }
  }

  return Object.assign({ className: typeName }, type);
}

const primitiveTypes = {
  boolean: {
    name: 'Z',
    type: 'uint8',
    size: 1,
    byteSize: 1,
    defaultValue: false,
    isCompatible (v) {
      return typeof v === 'boolean';
    },
    fromJni (v) {
      return !!v;
    },
    toJni (v) {
      return v ? 1 : 0;
    },
    read (address) {
      return address.readU8();
    },
    write (address, value) {
      address.writeU8(value);
    },
    toString () {
      return this.name;
    }
  },
  byte: {
    name: 'B',
    type: 'int8',
    size: 1,
    byteSize: 1,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -128 && v <= 127;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS8();
    },
    write (address, value) {
      address.writeS8(value);
    },
    toString () {
      return this.name;
    }
  },
  char: {
    name: 'C',
    type: 'uint16',
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible (v) {
      if (typeof v !== 'string' || v.length !== 1) {
        return false;
      }

      const code = v.charCodeAt(0);
      return code >= 0 && code <= 65535;
    },
    fromJni (c) {
      return String.fromCharCode(c);
    },
    toJni (s) {
      return s.charCodeAt(0);
    },
    read (address) {
      return address.readU16();
    },
    write (address, value) {
      address.writeU16(value);
    },
    toString () {
      return this.name;
    }
  },
  short: {
    name: 'S',
    type: 'int16',
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -32768 && v <= 32767;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS16();
    },
    write (address, value) {
      address.writeS16(value);
    },
    toString () {
      return this.name;
    }
  },
  int: {
    name: 'I',
    type: 'int32',
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS32();
    },
    write (address, value) {
      address.writeS32(value);
    },
    toString () {
      return this.name;
    }
  },
  long: {
    name: 'J',
    type: 'int64',
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number' || v instanceof Int64;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS64();
    },
    write (address, value) {
      address.writeS64(value);
    },
    toString () {
      return this.name;
    }
  },
  float: {
    name: 'F',
    type: 'float',
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number';
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readFloat();
    },
    write (address, value) {
      address.writeFloat(value);
    },
    toString () {
      return this.name;
    }
  },
  double: {
    name: 'D',
    type: 'double',
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number';
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readDouble();
    },
    write (address, value) {
      address.writeDouble(value);
    },
    toString () {
      return this.name;
    }
  },
  void: {
    name: 'V',
    type: 'void',
    size: 0,
    byteSize: 0,
    defaultValue: undefined,
    isCompatible (v) {
      return v === undefined;
    },
    fromJni () {
      return undefined;
    },
    toJni () {
      return NULL;
    },
    toString () {
      return this.name;
    }
  }
};

const primitiveTypesNames = new Set(Object.values(primitiveTypes).map(t => t.name));

export function getPrimitiveType (name) {
  const result = primitiveTypes[name];
  return (result !== undefined) ? result : null;
}

function getObjectType (typeName, unbox, factory) {
  const cache = factory._types[unbox ? 1 : 0];

  let type = cache[typeName];
  if (type !== undefined) {
    return type;
  }

  if (typeName === 'java.lang.Object') {
    type = getJavaLangObjectType(factory);
  } else {
    type = getAnyObjectType(typeName, unbox, factory);
  }

  cache[typeName] = type;

  return type;
}

function getJavaLangObjectType (factory) {
  return {
    name: 'Ljava/lang/Object;',
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (v === undefined) {
        return false;
      }

      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return true;
      }

      return typeof v === 'string';
    },
    fromJni (h, env, owned) {
      if (h.isNull()) {
        return null;
      }

      return factory.cast(h, factory.use('java.lang.Object'), owned);
    },
    toJni (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$h;
    }
  };
}

function getAnyObjectType (typeName, unbox, factory) {
  let cachedClass = null;
  let cachedIsInstance = null;
  let cachedIsDefaultString = null;

  function getClass () {
    if (cachedClass === null) {
      cachedClass = factory.use(typeName).class;
    }
    return cachedClass;
  }

  function isInstance (v) {
    const klass = getClass();

    if (cachedIsInstance === null) {
      cachedIsInstance = klass.isInstance.overload('java.lang.Object');
    }

    return cachedIsInstance.call(klass, v);
  }

  function typeIsDefaultString () {
    if (cachedIsDefaultString === null) {
      const x = getClass();
      cachedIsDefaultString = factory.use('java.lang.String').class.isAssignableFrom(x);
    }
    return cachedIsDefaultString;
  }

  return {
    name: makeJniObjectTypeName(typeName),
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (v === undefined) {
        return false;
      }

      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return isInstance(v);
      }

      return typeof v === 'string' && typeIsDefaultString();
    },
    fromJni (h, env, owned) {
      if (h.isNull()) {
        return null;
      }

      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }

      return factory.cast(h, factory.use(typeName), owned);
    },
    toJni (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$h;
    },
    toString () {
      return this.name;
    }
  };
}

const primitiveArrayTypes = [
  ['Z', 'boolean'],
  ['B', 'byte'],
  ['C', 'char'],
  ['D', 'double'],
  ['F', 'float'],
  ['I', 'int'],
  ['J', 'long'],
  ['S', 'short']
]
  .reduce((result, [shorty, name]) => {
    result['[' + shorty] = makePrimitiveArrayType('[' + shorty, name);
    return result;
  }, {});

function makePrimitiveArrayType (shorty, name) {
  const envProto = Env.prototype;

  const nameTitled = toTitleCase(name);
  const spec = {
    typeName: name,
    newArray: envProto['new' + nameTitled + 'Array'],
    setRegion: envProto['set' + nameTitled + 'ArrayRegion'],
    getElements: envProto['get' + nameTitled + 'ArrayElements'],
    releaseElements: envProto['release' + nameTitled + 'ArrayElements']
  };

  return {
    name: shorty,
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni (h, env, owned) {
      return fromJniPrimitiveArray(h, spec, env, owned);
    },
    toJni (arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}

export function getArrayType (typeName, unbox, factory) {
  const primitiveType = primitiveArrayTypes[typeName];
  if (primitiveType !== undefined) {
    return primitiveType;
  }

  if (typeName.indexOf('[') !== 0) {
    throw new Error('Unsupported type: ' + typeName);
  }

  let elementTypeName = typeName.substring(1);
  const elementType = getType(elementTypeName, unbox, factory);

  let numInternalArrays = 0;
  const end = elementTypeName.length;
  while (numInternalArrays !== end && elementTypeName[numInternalArrays] === '[') {
    numInternalArrays++;
  }
  elementTypeName = elementTypeName.substring(numInternalArrays);

  if (elementTypeName[0] === 'L' && elementTypeName[elementTypeName.length - 1] === ';') {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }

  // The type name we get is not always the correct representation of the type so we make it so here.
  let internalElementTypeName = elementTypeName.replace(/\./g, '/');
  if (primitiveTypesNames.has(internalElementTypeName)) {
    internalElementTypeName = '['.repeat(numInternalArrays) + internalElementTypeName;
  } else {
    internalElementTypeName = '['.repeat(numInternalArrays) + 'L' + internalElementTypeName + ';';
  }
  const internalTypeName = '[' + internalElementTypeName;
  elementTypeName = '['.repeat(numInternalArrays) + elementTypeName;

  return {
    name: typeName.replace(/\./g, '/'),
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (typeof v !== 'object' || v.length === undefined) {
        return false;
      }

      return v.every(function (element) {
        return elementType.isCompatible(element);
      });
    },
    fromJni (arr, env, owned) {
      if (arr.isNull()) {
        return null;
      }

      const result = [];

      const n = env.getArrayLength(arr);
      for (let i = 0; i !== n; i++) {
        const element = env.getObjectArrayElement(arr, i);
        try {
          // We'll ignore the owned hint as we might otherwise run out of local references.
          result.push(elementType.fromJni(element, env));
        } finally {
          env.deleteLocalRef(element);
        }
      }

      try {
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      } catch (e) {
        // We need to load the array type before using it.
        factory.use('java.lang.reflect.Array').newInstance(factory.use(elementTypeName).class, 0);
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      }

      result.$dispose = disposeObjectArray;

      return result;
    },
    toJni (elements, env) {
      if (elements === null) {
        return NULL;
      }

      if (!(elements instanceof Array)) {
        throw new Error('Expected an array');
      }

      const wrapper = elements.$w;
      if (wrapper !== undefined) {
        return wrapper.$h;
      }

      const n = elements.length;

      const klassObj = factory.use(elementTypeName);
      const classHandle = klassObj.$borrowClassHandle(env);
      try {
        const result = env.newObjectArray(n, classHandle.value, NULL);
        env.throwIfExceptionPending();

        for (let i = 0; i !== n; i++) {
          const handle = elementType.toJni(elements[i], env);
          try {
            env.setObjectArrayElement(result, i, handle);
          } finally {
            if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
              env.deleteLocalRef(handle);
            }
          }
          env.throwIfExceptionPending();
        }

        return result;
      } finally {
        classHandle.unref(env);
      }
    }
  };
}

function disposeObjectArray () {
  const n = this.length;

  for (let i = 0; i !== n; i++) {
    const obj = this[i];

    if (obj === null) {
      continue;
    }

    const dispose = obj.$dispose;
    if (dispose === undefined) {
      break;
    }
    dispose.call(obj);
  }

  this.$w.$dispose();
}

function fromJniPrimitiveArray (arr, spec, env, owned) {
  if (arr.isNull()) {
    return null;
  }

  const type = getPrimitiveType(spec.typeName);
  const length = env.getArrayLength(arr);

  return new PrimitiveArray(arr, spec, type, length, env, owned);
}

function toJniPrimitiveArray (arr, spec, env) {
  if (arr === null) {
    return NULL;
  }

  const handle = arr.$h;
  if (handle !== undefined) {
    return handle;
  }

  const length = arr.length;
  const type = getPrimitiveType(spec.typeName);
  const result = spec.newArray.call(env, length);
  if (result.isNull()) {
    throw new Error('Unable to construct array');
  }

  if (length > 0) {
    const elementSize = type.byteSize;
    const writeElement = type.write;
    const unparseElementValue = type.toJni;

    const elements = Memory.alloc(length * type.byteSize);
    for (let index = 0; index !== length; index++) {
      writeElement(elements.add(index * elementSize), unparseElementValue(arr[index]));
    }
    spec.setRegion.call(env, result, 0, length, elements);
    env.throwIfExceptionPending();
  }

  return result;
}

function isCompatiblePrimitiveArray (value, typeName) {
  if (value === null) {
    return true;
  }

  if (value instanceof PrimitiveArray) {
    return value.$s.typeName === typeName;
  }

  const isArrayLike = typeof value === 'object' && value.length !== undefined;
  if (!isArrayLike) {
    return false;
  }

  const elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, element => elementType.isCompatible(element));
}

function PrimitiveArray (handle, spec, type, length, env, owned = true) {
  if (owned) {
    const h = env.newGlobalRef(handle);
    this.$h = h;
    this.$r = Script.bindWeak(this, env.vm.makeHandleDestructor(h));
  } else {
    this.$h = handle;
    this.$r = null;
  }

  this.$s = spec;
  this.$t = type;

  this.length = length;

  return new Proxy(this, primitiveArrayHandler);
}

primitiveArrayHandler = {
  has (target, property) {
    if (property in target) {
      return true;
    }

    return target.tryParseIndex(property) !== null;
  },
  get (target, property, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      return target[property];
    }

    return target.readElement(index);
  },
  set (target, property, value, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      target[property] = value;
      return true;
    }

    target.writeElement(index, value);
    return true;
  },
  ownKeys (target) {
    const keys = [];

    const { length } = target;
    for (let i = 0; i !== length; i++) {
      const key = i.toString();
      keys.push(key);
    }

    keys.push('length');

    return keys;
  },
  getOwnPropertyDescriptor (target, property) {
    const index = target.tryParseIndex(property);
    if (index !== null) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    }

    return Object.getOwnPropertyDescriptor(target, property);
  }
};

Object.defineProperties(PrimitiveArray.prototype, {
  $dispose: {
    enumerable: true,
    value () {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }
    }
  },
  $clone: {
    value (env) {
      return new PrimitiveArray(this.$h, this.$s, this.$t, this.length, env);
    }
  },
  tryParseIndex: {
    value (rawIndex) {
      if (typeof rawIndex === 'symbol') {
        return null;
      }

      const index = parseInt(rawIndex);
      if (isNaN(index) || index < 0 || index >= this.length) {
        return null;
      }

      return index;
    }
  },
  readElement: {
    value (index) {
      return this.withElements(elements => {
        const type = this.$t;
        return type.fromJni(type.read(elements.add(index * type.byteSize)));
      });
    }
  },
  writeElement: {
    value (index, value) {
      const { $h: handle, $s: spec, $t: type } = this;
      const env = vm.getEnv();

      const element = Memory.alloc(type.byteSize);
      type.write(element, type.toJni(value));
      spec.setRegion.call(env, handle, index, 1, element);
    }
  },
  withElements: {
    value (perform) {
      const { $h: handle, $s: spec } = this;
      const env = vm.getEnv();

      const elements = spec.getElements.call(env, handle);
      if (elements.isNull()) {
        throw new Error('Unable to get array elements');
      }

      try {
        return perform(elements);
      } finally {
        spec.releaseElements.call(env, handle, elements);
      }
    }
  },
  toJSON: {
    value () {
      const { length, $t: type } = this;
      const { byteSize: elementSize, fromJni, read } = type;

      return this.withElements(elements => {
        const values = [];
        for (let i = 0; i !== length; i++) {
          const value = fromJni(read(elements.add(i * elementSize)));
          values.push(value);
        }
        return values;
      });
    }
  },
  toString: {
    value () {
      return this.toJSON().toString();
    }
  }
});

export function makeJniObjectTypeName (typeName) {
  return 'L' + typeName.replace(/\./g, '/') + ';';
}

function toTitleCase (str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function identity (value) {
  return value;
}
