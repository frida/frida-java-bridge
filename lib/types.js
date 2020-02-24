const Env = require('./env');

const JNILocalRefType = 1;

/*
 * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
 * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
 */
function getType (typeName, unbox, factory) {
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

  return Object.assign({className: typeName}, type);
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
    }
  },
  char: {
    name: 'C',
    type: 'uint16',
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= 0 && v <= 65535;
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
    isCompatible (v) {
      return v === undefined;
    }
  },
};

function getPrimitiveType (name) {
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
    fromJni (h, env) {
      if (h.isNull()) {
        return null;
      }

      return factory.cast(h, factory.use('java.lang.Object'));
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
    fromJni (h, env) {
      if (h.isNull()) {
        return null;
      }

      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }

      return factory.cast(h, factory.use(typeName));
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

const primitiveArrayTypes = [
    ['Z', 'boolean'],
    ['B', 'byte'],
    ['C', 'char'],
    ['D', 'double'],
    ['F', 'float'],
    ['I', 'int'],
    ['J', 'long'],
    ['S', 'short'],
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
    releaseElements: envProto['release' + nameTitled + 'ArrayElements'],
  };

  return {
    name: shorty,
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni (h, env) {
      return fromJniPrimitiveArray(h, spec, env);
    },
    toJni (arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}

function getArrayType (typeName, unbox, factory) {
  const primitiveType = primitiveArrayTypes[typeName];
  if (primitiveType !== undefined) {
    return primitiveType;
  }

  if (typeName.indexOf('[') !== 0) {
    throw new Error('Unsupported type: ' + typeName);
  }

  let elementTypeName = typeName.substring(1);
  const elementType = getType(elementTypeName, unbox, factory);

  if (elementTypeName[0] === 'L' && elementTypeName[elementTypeName.length - 1] === ';') {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }

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
    fromJni (arr, env) {
      return fromJniObjectArray(arr, env, function (self, elem) {
        return elementType.fromJni(elem, env);
      });
    },
    toJni (elements, env) {
      const klassObj = factory.use(elementTypeName);

      const classHandle = klassObj.$borrowClassHandle(env);
      try {
        return toJniObjectArray(elements, env, classHandle.value,
          function (i, result) {
            const handle = elementType.toJni(elements[i], env);
            try {
              env.setObjectArrayElement(result, i, handle);
            } finally {
              if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
                env.deleteLocalRef(handle);
              }
            }
          });
      } finally {
        classHandle.unref(env);
      }
    }
  };
}

function fromJniObjectArray (arr, env, convertFromJniFunc) {
  if (arr.isNull()) {
    return null;
  }
  const result = [];
  const length = env.getArrayLength(arr);
  for (let i = 0; i !== length; i++) {
    const elemHandle = env.getObjectArrayElement(arr, i);

    // Maybe ArrayIndexOutOfBoundsException: if 'i' does not specify a valid index in the array - should not be the case
    env.throwIfExceptionPending();
    try {
      result.push(convertFromJniFunc(this, elemHandle));
    } finally {
      env.deleteLocalRef(elemHandle);
    }
  }
  return result;
}

function toJniObjectArray (arr, env, classHandle, setObjectArrayFunc) {
  if (arr === null) {
    return NULL;
  }

  if (!(arr instanceof Array)) {
    throw new Error('Expected an array');
  }

  const length = arr.length;
  const result = env.newObjectArray(length, classHandle, NULL);
  env.throwIfExceptionPending();
  if (result.isNull()) {
    return NULL;
  }
  for (let i = 0; i !== length; i++) {
    setObjectArrayFunc.call(env, i, result);
    env.throwIfExceptionPending();
  }
  return result;
}

class PrimitiveArray {
  constructor(handle, type, length) {
    this.$h = handle;
    this.type = type;
    this.length = length;
  }
}

function fromJniPrimitiveArray (arr, spec, env) {
  if (arr.isNull()) {
    return null;
  }

  const typeName = spec.typeName;
  const type = getPrimitiveType(typeName);
  const elementSize = type.byteSize;
  const readElement = type.read;
  const writeElement = type.write;
  const parseElementValue = type.fromJni || identity;
  const unparseElementValue = type.toJni || identity;

  const handle = env.newGlobalRef(arr);
  const length = env.getArrayLength(handle);
  const vm = env.vm;

  const storage = new PrimitiveArray(handle, typeName, length);

  let wrapper = new Proxy(storage, {
    has (target, property) {
      return hasProperty.call(target, property);
    },
    get (target, property, receiver) {
      switch (property) {
        case 'hasOwnProperty':
          return hasProperty.bind(target);
        case 'toJSON':
          return toJSON;
        default:
          if (typeof property === 'symbol') {
            return target[property];
          }
          const index = tryParseIndex(property);
          if (index === null) {
            return target[property];
          }
          return withElements(elements => {
            return parseElementValue(readElement(elements.add(index * elementSize)));
          });
      }
    },
    set (target, property, value, receiver) {
      const index = tryParseIndex(property);
      if (index === null) {
        target[property] = value;
        return true;
      }

      const env = vm.getEnv();

      const element = Memory.alloc(elementSize);
      writeElement(element, unparseElementValue(value));
      spec.setRegion.call(env, handle, index, 1, element);

      return true;
    },
    ownKeys (target) {
      const keys = [ '$h', 'type', 'length' ];
      for (let index = 0; index !== length; index++) {
        keys.push(index.toString());
      }
      return keys;
    },
    getOwnPropertyDescriptor (target, property) {
      return {
        writable: false,
        configurable: true,
        enumerable: true
      };
    },
  });

  WeakRef.bind(wrapper, vm.makeHandleDestructor(handle));
  Script.nextTick(() => { wrapper = null; });

  env = null;

  return wrapper;

  function tryParseIndex (rawIndex) {
    const index = parseInt(rawIndex);
    if (isNaN(index) || index < 0 || index >= length) {
      return null;
    }
    return index;
  }

  function withElements (perform) {
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

  function hasProperty (property) {
    const index = tryParseIndex(property);
    if (index === null) {
      return this.hasOwnProperty(property);
    }
    return true;
  }

  function toJSON () {
    return withElements(elements => {
      const values = [];
      for (let index = 0; index !== length; index++) {
        const value = parseElementValue(readElement(elements.add(index * elementSize)));
        values.push(value);
      }
      return values;
    });
  }
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
    const unparseElementValue = type.toJni || identity;

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
    return value.type === typeName;
  }

  const isArrayLike = typeof value === 'object' && value.length !== undefined;
  if (!isArrayLike) {
    return false;
  }

  const elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, element => elementType.isCompatible(element));
}

function makeJniObjectTypeName (typeName) {
  return 'L' + typeName.replace(/\./g, '/') + ';';
}

function toTitleCase (str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function identity (value) {
  return value;
}

module.exports = {
  getType,
  getPrimitiveType,
  getArrayType,
  makeJniObjectTypeName,
};
