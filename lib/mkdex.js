'use strict';

module.exports = mkdex;

const SHA1 = require('jssha/src/sha1');

const kAccPublic = 0x0001;
const kAccNative = 0x0100;

const kAccConstructor = 0x00010000;

const kEndianTag = 0x12345678;

const kClassDefSize = 32;
const kProtoIdSize = 12;
const kMethodIdSize = 8;
const kTypeIdSize = 4;
const kStringIdSize = 4;
const kMapItemSize = 12;

const TYPE_HEADER_ITEM = 0;
const TYPE_STRING_ID_ITEM = 1;
const TYPE_TYPE_ID_ITEM = 2;
const TYPE_PROTO_ID_ITEM = 3;
const TYPE_METHOD_ID_ITEM = 5;
const TYPE_CLASS_DEF_ITEM = 6;
const TYPE_MAP_LIST = 0x1000;
const TYPE_TYPE_LIST = 0x1001;
const TYPE_CLASS_DATA_ITEM = 0x2000;
const TYPE_CODE_ITEM = 0x2001;
const TYPE_STRING_DATA_ITEM = 0x2002;
const TYPE_DEBUG_INFO_ITEM = 0x2003;

const kDefaultConstructorSize = 24;
const kDefaultConstructorDebugInfo = Buffer.from([ 0x03, 0x00, 0x07, 0x0e, 0x00 ]);

const kNullTerminator = Buffer.from([0]);

function mkdex (spec) {
  const builder = new DexBuilder();

  const fullSpec = Object.assign({}, spec);
  fullSpec.methods.splice(0, 0, ['<init>', 'V', []]);
  builder.addClass(fullSpec);

  return builder.build();
}

class DexBuilder {
  constructor () {
    this.classes = [];
  }

  addClass (spec) {
    this.classes.push(spec);
  }

  build () {
    const model = computeModel(this.classes);

    const {classes, interfaces, methods, protos, parameters, types, strings} = model;

    let offset = 0;

    const headerOffset = 0;
    const checksumOffset = 8;
    const signatureOffset = 12;
    const signatureSize = 20;
    const headerSize = 0x70;
    offset += headerSize;

    const stringIdsOffset = offset;
    const stringIdsSize = strings.length * kStringIdSize;
    offset += stringIdsSize;

    const typeIdsOffset = offset;
    const typeIdsSize = types.length * kTypeIdSize;
    offset += typeIdsSize;

    const protoIdsOffset = offset;
    const protoIdsSize = protos.length * kProtoIdSize;
    offset += protoIdsSize;

    const fieldIdsOffset = 0;
    const fieldIdsCount = 0;

    const methodIdsOffset = offset;
    const methodIdsSize = methods.length * kMethodIdSize;
    offset += methodIdsSize;

    const classDefsOffset = offset;
    const classDefsSize = classes.length * kClassDefSize;
    offset += classDefsSize;

    const dataOffset = offset;

    const constructorOffsets = classes.map(klass => {
      const ctorOffset = offset;
      offset += kDefaultConstructorSize;
      return ctorOffset;
    });

    const interfaceOffsets = interfaces.map(iface => {
      const alignment = 4;
      const alignmentDelta = offset % alignment;
      if (alignmentDelta !== 0) {
        offset += alignment - alignmentDelta;
      }

      const ifaceOffset = offset;
      iface.offset = ifaceOffset;

      offset += 4 + (2 * iface.types.length);

      return ifaceOffset;
    });

    const parameterOffsets = parameters.map(param => {
      const alignment = 4;
      const alignmentDelta = offset % alignment;
      if (alignmentDelta !== 0) {
        offset += alignment - alignmentDelta;
      }

      const paramOffset = offset;
      param.offset = paramOffset;

      offset += 4 + (2 * param.types.length);

      return paramOffset;
    });

    const stringChunks = [];
    const stringOffsets = strings.map(str => {
      const strOffset = offset;

      const header = Buffer.from(createUleb128(str.length));
      const data = Buffer.from(str, 'utf8');
      const chunk = Buffer.concat([header, data, kNullTerminator]);

      stringChunks.push(chunk);

      offset += chunk.length;

      return strOffset;
    });

    const debugInfoOffsets = classes.map(klass => {
      const debugOffset = offset;
      offset += kDefaultConstructorDebugInfo.length;
      return debugOffset;
    });

    const classDataBlobs = [];
    classes.forEach((klass, index) => {
      const [, , , , , classData] = klass;

      classData.offset = offset;

      const data = makeClassData(klass, constructorOffsets[index]);
      classDataBlobs.push(data);

      offset += data.length;
    });

    const linkSize = 0;
    const linkOffset = 0;

    const mapOffset = offset;
    const mapNumItems = 8 + (4 * classes.length);
    const mapSize = 4 + (mapNumItems * kMapItemSize);
    offset += mapSize;

    const dataSize = offset - dataOffset;

    const fileSize = offset;

    const dex = Buffer.alloc(fileSize);

    dex.write('dex\n035');

    dex.writeUInt32LE(fileSize, 0x20);
    dex.writeUInt32LE(headerSize, 0x24);
    dex.writeUInt32LE(kEndianTag, 0x28);
    dex.writeUInt32LE(linkSize, 0x2c);
    dex.writeUInt32LE(linkOffset, 0x30);
    dex.writeUInt32LE(mapOffset, 0x34);
    dex.writeUInt32LE(strings.length, 0x38);
    dex.writeUInt32LE(stringIdsOffset, 0x3c);
    dex.writeUInt32LE(types.length, 0x40);
    dex.writeUInt32LE(typeIdsOffset, 0x44);
    dex.writeUInt32LE(protos.length, 0x48);
    dex.writeUInt32LE(protoIdsOffset, 0x4c);
    dex.writeUInt32LE(fieldIdsCount, 0x50);
    dex.writeUInt32LE(fieldIdsOffset, 0x54);
    dex.writeUInt32LE(methods.length, 0x58);
    dex.writeUInt32LE(methodIdsOffset, 0x5c);
    dex.writeUInt32LE(classes.length, 0x60);
    dex.writeUInt32LE(classDefsOffset, 0x64);
    dex.writeUInt32LE(dataSize, 0x68);
    dex.writeUInt32LE(dataOffset, 0x6c);

    stringOffsets.forEach((offset, index) => {
      dex.writeUInt32LE(offset, stringIdsOffset + (index * kStringIdSize));
    });

    types.forEach((id, index) => {
      dex.writeUInt32LE(id, typeIdsOffset + (index * kTypeIdSize));
    });

    protos.forEach((proto, index) => {
      const [shortyIndex, returnTypeIndex, params] = proto;

      const protoOffset = protoIdsOffset + (index * kProtoIdSize);
      dex.writeUInt32LE(shortyIndex, protoOffset);
      dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
      dex.writeUInt32LE((params !== null) ? params.offset : 0, protoOffset + 8);
    });

    methods.forEach((method, index) => {
      const [classIndex, protoIndex, nameIndex] = method;

      const methodOffset = methodIdsOffset + (index * kMethodIdSize);
      dex.writeUInt16LE(classIndex, methodOffset);
      dex.writeUInt16LE(protoIndex, methodOffset + 2);
      dex.writeUInt32LE(nameIndex, methodOffset + 4);
    });

    classes.forEach((klass, index) => {
      const [classIndex, accessFlags, superClassIndex, ifaceList, sourceFileIndex, classData] = klass;
      const annotationsOffset = 0;
      const staticValuesOffset = 0;

      const classOffset = classDefsOffset + (index * kClassDefSize);
      dex.writeUInt32LE(classIndex, classOffset);
      dex.writeUInt32LE(accessFlags, classOffset + 4);
      dex.writeUInt32LE(superClassIndex, classOffset + 8);
      dex.writeUInt32LE(ifaceList.offset, classOffset + 12);
      dex.writeUInt32LE(sourceFileIndex, classOffset + 16);
      dex.writeUInt32LE(annotationsOffset, classOffset + 20);
      dex.writeUInt32LE(classData.offset, classOffset + 24);
      dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
    });

    constructorOffsets.forEach((constructorOffset, index) => {
      const registersSize = 1;
      const insSize = 1;
      const outsSize = 1;
      const triesSize = 0;
      const insnsSize = 4;

      dex.writeUInt16LE(registersSize, constructorOffset);
      dex.writeUInt16LE(insSize, constructorOffset + 2);
      dex.writeUInt16LE(outsSize, constructorOffset + 4);
      dex.writeUInt16LE(triesSize, constructorOffset + 6);
      dex.writeUInt32LE(debugInfoOffsets[index], constructorOffset + 8);
      dex.writeUInt32LE(insnsSize, constructorOffset + 12);
      dex.writeUInt16LE(0x1070, constructorOffset + 16);
      dex.writeUInt16LE(0x0000, constructorOffset + 18);
      dex.writeUInt16LE(0x0000, constructorOffset + 20);
      dex.writeUInt16LE(0x000e, constructorOffset + 22);
    });

    interfaces.forEach((iface, ifaceIndex) => {
      const ifaceOffset = interfaceOffsets[ifaceIndex];

      dex.writeUInt32LE(iface.types.length, ifaceOffset);
      iface.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, ifaceOffset + 4 + (typeIndex * 2));
      });
    });

    parameters.forEach((param, paramIndex) => {
      const paramOffset = parameterOffsets[paramIndex];

      dex.writeUInt32LE(param.types.length, paramOffset);
      param.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, paramOffset + 4 + (typeIndex * 2));
      });
    });

    stringChunks.forEach((chunk, chunkIndex) => {
      chunk.copy(dex, stringOffsets[chunkIndex]);
    });

    debugInfoOffsets.forEach(debugInfoOffset => {
      kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
    });

    classDataBlobs.forEach((classDataBlob, index) => {
      const [, , , , , classData] = classes[index];

      classDataBlob.copy(dex, classData.offset);
    });

    dex.writeUInt32LE(mapNumItems, mapOffset);
    const mapItems = [
      [TYPE_HEADER_ITEM, 1, headerOffset],
      [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset],
      [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset],
      [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset],
      [TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset],
      [TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset],
    ];
    classes.forEach((klass, index) => {
      mapItems.push([TYPE_CODE_ITEM, 1, constructorOffsets[index]]);
    });
    interfaces.forEach(iface => {
      mapItems.push([TYPE_TYPE_LIST, 2, iface.offset]);
    });
    mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
    debugInfoOffsets.forEach(debugInfoOffset => {
      mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
    });
    classes.forEach(klass => {
      const [, , , , , classData] = klass;
      mapItems.push([TYPE_CLASS_DATA_ITEM, 1, classData.offset]);
    });
    mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
    mapItems.forEach((item, index) => {
      const [type, size, offset] = item;

      const itemOffset = mapOffset + 4 + (index * kMapItemSize);
      dex.writeUInt16LE(type, itemOffset);
      dex.writeUInt32LE(size, itemOffset + 4);
      dex.writeUInt32LE(offset, itemOffset + 8);
    });

    const hash = new SHA1('SHA-1', 'ARRAYBUFFER');
    hash.update(dex.slice(signatureOffset + signatureSize));
    Buffer.from(hash.getHash('ARRAYBUFFER')).copy(dex, signatureOffset);

    dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);

    return dex;
  }
}

function makeClassData (klass, constructorCodeOffset) {
  const [, , , , , classData] = klass;

  const {constructorMethod, virtualMethods} = classData;

  const staticFieldsSize = 0;
  const instanceFieldsSize = 0;
  const directMethodsSize = 1;

  const [constructorIndex, constructorAccessFlags] = constructorMethod;

  return Buffer.from([
      staticFieldsSize,
      instanceFieldsSize,
      directMethodsSize,
    ]
    .concat(createUleb128(virtualMethods.length))
    .concat(createUleb128(constructorIndex))
    .concat(createUleb128(constructorAccessFlags))
    .concat(createUleb128(constructorCodeOffset))
    .concat(virtualMethods.reduce((result, [indexDiff, accessFlags]) => {
      const codeOffset = 0;
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags))
        .concat([codeOffset]);
    }, [])));
}

function computeModel (classes) {
  const strings = new Set();
  const types = new Set();
  const protos = {};
  const methods = [];
  const superConstructors = new Set();

  classes.forEach(klass => {
    const {name, superClass, sourceFileName} = klass;

    strings.add(name);
    types.add(name);

    strings.add(superClass);
    types.add(superClass);

    strings.add(sourceFileName);

    klass.interfaces.forEach(iface => {
      strings.add(iface);
      types.add(iface);
    });

    klass.methods.forEach(method => {
      const [methodName, retType, argTypes] = method;

      strings.add(methodName);

      const protoId = addProto(retType, argTypes);

      methods.push([klass.name, protoId, methodName]);

      if (methodName === '<init>') {
        const superConstructorId = superClass + '|' + protoId;
        if (!superConstructors.has(superConstructorId)) {
          methods.push([superClass, protoId, methodName]);
          superConstructors.add(superConstructorId);
        }
      }
    });
  });

  function addProto (retType, argTypes) {
    const signature = [retType].concat(argTypes);

    const id = signature.join('|');
    if (protos[id] !== undefined) {
      return id;
    }

    strings.add(retType);
    types.add(retType);
    argTypes.forEach(argType => {
      strings.add(argType);
      types.add(argType);
    });

    const shorty = signature.map(typeToShorty).join('');
    strings.add(shorty);

    protos[id] = [id, shorty, retType, argTypes];

    return id;
  }

  const stringItems = Array.from(strings);
  stringItems.sort();
  const stringToIndex = stringItems.reduce((result, string, index) => {
    result[string] = index;
    return result;
  }, {});

  const typeItems = Array.from(types).map(name => stringToIndex[name]);
  typeItems.sort(compareNumbers);
  const typeToIndex = typeItems.reduce((result, stringIndex, typeIndex) => {
    result[stringItems[stringIndex]] = typeIndex;
    return result;
  }, {});

  const literalProtoItems = Object.keys(protos).map(id => protos[id]);
  literalProtoItems.sort(compareProtoItems);
  const parameters = {};
  const protoItems = literalProtoItems.map(item => {
    const [, shorty, retType, argTypes] = item;

    let params;
    if (argTypes.length > 0) {
      const argTypesSig = argTypes.join('|');
      params = parameters[argTypesSig];
      if (params === undefined) {
        params = {
          types: argTypes.map(type => typeToIndex[type]),
          offset: -1
        };
        parameters[argTypesSig] = params;
      }
    } else {
      params = null;
    }

    return [
      stringToIndex[shorty],
      typeToIndex[retType],
      params
    ];
  });
  const protoToIndex = literalProtoItems.reduce((result, item, index) => {
    const [id] = item;
    result[id] = index;
    return result;
  }, {});
  const parameterItems = Object.keys(parameters).map(id => parameters[id]);

  const methodItems = methods.map(method => {
    const [klass, protoId, name] = method;
    return [
      typeToIndex[klass],
      protoToIndex[protoId],
      stringToIndex[name],
    ];
  });
  methodItems.sort(compareMethodItems);

  const interfaceLists = {};
  const classItems = classes.map(klass => {
    const classIndex = typeToIndex[klass.name];
    const accessFlags = kAccPublic;
    const superClassIndex = typeToIndex[klass.superClass];

    const ifaces = klass.interfaces.map(type => typeToIndex[type]);
    ifaces.sort(compareNumbers);
    const ifacesId = ifaces.join('|');
    let ifaceList = interfaceLists[ifacesId];
    if (ifaceList === undefined) {
      ifaceList = {
        types: ifaces,
        offset: -1
      };
      interfaceLists[ifacesId] = ifaceList;
    }

    const sourceFileIndex = stringToIndex[klass.sourceFileName];

    const classMethods = methodItems
      .map((method, index) => [index].concat(method))
      .filter(method => {
        const [, holder] = method;
        return holder === classIndex;
      })
      .map(method => {
        const [index, , , name] = method;
        return [index, name];
      });

    const constructorNameIndex = stringToIndex['<init>'];
    const constructorMethod = classMethods
      .filter(([, name]) => name === constructorNameIndex)
      .map(([index]) => {
        return [index, kAccPublic | kAccConstructor];
      })
      [0];
    const virtualMethods = compressClassMethodIndexes(classMethods
      .filter(([, name]) => name !== constructorNameIndex)
      .map(([index]) => {
        return [index, kAccPublic | kAccNative];
      }));

    const classData = {
      constructorMethod,
      virtualMethods,
      offset: -1
    };

    return [
      classIndex,
      accessFlags,
      superClassIndex,
      ifaceList,
      sourceFileIndex,
      classData
    ];
  });
  const interfaceItems = Object.keys(interfaceLists).map(id => interfaceLists[id]);

  return {
    classes: classItems,
    interfaces: interfaceItems,
    methods: methodItems,
    protos: protoItems,
    parameters: parameterItems,
    types: typeItems,
    strings: stringItems
  };
}

function compressClassMethodIndexes (items) {
  let previousIndex = 0;
  return items.map(([index, accessFlags], elementIndex) => {
    let result;
    if (elementIndex === 0) {
      result = [index, accessFlags];
    } else {
      result = [index - previousIndex, accessFlags];
    }
    previousIndex = index;
    return result;
  });
}

function compareNumbers (a, b) {
  return a - b;
}

function compareProtoItems (a, b) {
  const [, , aRetType, aArgTypes] = a;
  const [, , bRetType, bArgTypes] = b;

  if (aRetType < bRetType) {
    return -1;
  }
  if (aRetType > bRetType) {
    return 1;
  }

  const aArgTypesSig = aArgTypes.join('|');
  const bArgTypesSig = bArgTypes.join('|');
  if (aArgTypesSig < bArgTypesSig) {
    return -1;
  }
  if (aArgTypesSig > bArgTypesSig) {
    return 1;
  }
  return 0;
}

function compareMethodItems (a, b) {
  const [aClass, aProto, aName] = a;
  const [bClass, bProto, bName] = b;

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aProto - bProto;
}

function typeToShorty (type) {
  return (type[0] === 'L') ? 'L' : type;
}

function createUleb128 (value) {
  if (value <= 0x7f) {
    return [value];
  }

  const result = [];
  let moreSlicesNeeded = false;

  do {
    let slice = value & 0x7f;

    value >>= 7;
    moreSlicesNeeded = value !== 0;

    if (moreSlicesNeeded) {
      slice |= 0x80;
    }

    result.push(slice);
  } while (moreSlicesNeeded);

  return result;
}

function adler32 (buffer, offset) {
  let a = 1;
  let b = 0;

  const length = buffer.length;
  for (let i = offset; i < length; i++) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }

  return ((b << 16) | a) >>> 0;
}
