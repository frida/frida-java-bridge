const ClassFactory = require('./lib/class-factory');

class Deobfuscator {
  #mapping;
  #reverseMapping;

  constructor (mapping) {
    if (mapping instanceof Map) {
      this.#mapping = mapping;
    } else {
      const o = Object.entries(mapping).map(e => [e[0], {
        realSpecifier: e[1].realSpecifier,
        properties: new Map(Object.entries(e[1].properties))
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
    const realSpecifier = this.#getRealSpecifier(deobfuscatedSpecifier) || deobfuscatedSpecifier;
    const realUse = ClassFactory.use(realSpecifier);
    return this.wrap(realUse);
  }

  choose (deobfuscatedSpecifier, callbacks) {
    const realSpecifier = this.#getRealSpecifier(deobfuscatedSpecifier) || deobfuscatedSpecifier;
    ClassFactory.choose(realSpecifier, {
      onMatch: instance => callbacks.onMatch(this.wrap(instance)),
      onComplete: () => callbacks.onComplete()
    });
  }

  cast (obj, klass, owned) {
    const casted = ClassFactory.cast(obj, klass, owned);
    return this.wrap(casted);
  }

  wrap (wrapper) {
    const realSpecifier = wrapper.$n;
    const deobfuscatedSpecifier = this.#reverseMapping.get(realSpecifier) || realSpecifier;
    const propertiesMapping = this.#mapping.get(deobfuscatedSpecifier)?.properties || new Map();

    return new Proxy(wrapper, {
      get: (target, prop, receiver) => {
        const realProp = propertiesMapping.get(prop) || prop;
        const result = Reflect.get(target, realProp, receiver);

        if (result) {
          if (result.value && result.value.$className) {
            return this.#wrapField(result);
          }

          if (result instanceof Function) {
            return this.#wrapMethod(target, result);
          }
        }

        // This code path should never be reached, however, returning it makes sure to have some sort of forward compatability.
        return result;
      }
    });
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
