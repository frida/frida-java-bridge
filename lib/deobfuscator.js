// const Java = require('./lib/class-factory');

class UnexpectedPropertyError extends Error {
}

class Deobfuscator {
  #mapping;
  #reverseMapping;

  constructor (mapping) {
    if (mapping instanceof Map) {
      this.#mapping = mapping;
    } else {
      const o = Object.entries(mapping).map(e => [e[0], {
        realSpecifier: e[1].realSpecifier,
        fields: new Map(Object.entries(e[1].fields)),
        methods: new Map(Object.entries(e[1].methods))
      }]);
      this.#mapping = new Map(o);
    }

    this.#reverseMapping = new Map();
    for (const [key, value] of this.#mapping.entries()) {
      this.#reverseMapping.set(value.realSpecifier, key);
    }
  }

  #getRealSpecifier (deobfuscatedSpecifier) {
    const specifierMapping = this.#mapping.get(deobfuscatedSpecifier);
    return specifierMapping?.realSpecifier;
  }

  use (deobfuscatedSpecifier) {
    const realSpecifier = this.#getRealSpecifier(deobfuscatedSpecifier) ?? deobfuscatedSpecifier;
    const realUse = Java.use(realSpecifier);
    return this.wrap(realUse);
  }

  choose (deobfuscatedSpecifier, callbacks) {
    const realSpecifier = this.#getRealSpecifier(deobfuscatedSpecifier) ?? deobfuscatedSpecifier;
    Java.choose(realSpecifier, {
      onMatch: instance => callbacks.onMatch(this.wrap(instance)),
      onComplete: () => callbacks.onComplete()
    });
  }

  cast (obj, klass, owned) {
    const casted = Java.cast(obj, klass, owned);
    return this.wrap(casted);
  }

  wrap (wrapper) {
    const realSpecifier = wrapper.$n;
    const deobfuscatedSpecifier = this.#reverseMapping.get(realSpecifier) ?? realSpecifier;

    const methodsMapping = this.#mapping.get(deobfuscatedSpecifier)?.methods ?? new Map();
    const fieldsMapping = this.#mapping.get(deobfuscatedSpecifier)?.fields ?? new Map();

    return new Proxy(wrapper, {
      get: (target, prop, receiver) => {
        if ((methodProp = methodsMapping.get(prop)) !== undefined) {
          const result = Reflect.get(target, methodProp, receiver);
          if (!(result instanceof Function)) {
            throw new UnexpectedPropertyError(`Mapped property was expected to be a method, got ${result} of type ${typeof result} instead`);
          }
          return this.#wrapMethod(target, result)
        }

        if ((fieldProp = fieldsMapping.get(prop)) !== undefined) {
          let result = Reflect.get(target, realProp, receiver);
          while (result instanceof Function) {
            fieldProp = "_" + fieldProp;
            result = Reflect.get(target, realProp, receiver);
          }

          if (!(obj.value && obj.value.$className)) {
            throw new UnexpectedPropertyError(`Mapped property was expected to be a field, got ${result} of type ${typeof result} instead`);
          }

          return this.#wrapField(result)
        }

        const result = Reflect.get(target, prop, receiver);
        return this.#wrapUnknown(target, result);
      }
    });
  }

  #wrapUnknown(target, obj) {
    if (obj) {
      if (obj.value && obj.value.$className) {
        return this.#wrapField(obj);
      }

      if (obj instanceof Function) {
        return this.#wrapMethod(target, obj);
      }
    }

    // This code path should never be reached, however, returning it makes sure to have some sort of forward compatability.
    return obj;
  }

  #wrapField (field) {
    return new Proxy(field, {
      get: (target, prop, receiver) => {
        if (prop === 'value') {
          return this.wrap(target.value);
        }
        return Reflect.get(target, prop, receiver);
      }
    });
  }

  #wrapMethod (wrapper, method) {
    return new Proxy(method, {
      apply: (_, thisArg, argumentsList) => {
        const result = method.apply(thisArg, argumentsList);
        if (result && result.$className) {
          return this.wrap(result);
        }
        return result;
      },
      set: (target, prop, newValue, receiver) => {
        if (prop === 'implementation') {
          return Reflect.set(target, prop, newValue.bind(wrapper), receiver);
        }

        return Reflect.set(target, prop, newValue, receiver);
      }
    });
  }
}

module.exports = Deobfuscator;
