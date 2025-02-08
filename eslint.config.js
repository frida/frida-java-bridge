import pluginJs from "@eslint/js";


/** @type {import('eslint').Linter.Config[]} */
export default [
  pluginJs.configs.recommended,
  {
    rules:{
      'no-unused-vars': 'off',
    },
    languageOptions: {
      globals: {
        "Arm64Relocator": "readonly",
        "Arm64Writer": "readonly",
        "Checksum": "readonly",
        "CModule": "readonly",
        "DebugSymbol": "readonly",
        "File": "readonly",
        "Instruction": "readonly",
        "Int64": "readonly",
        "Interceptor": "readonly",
        "MatchPattern": "readonly",
        "Memory": "readonly",
        "Module": "readonly",
        "NULL": "readonly",
        "NativeCallback": "readonly",
        "NativeFunction": "readonly",
        "NativePointer": "readonly",
        "Process": "readonly",
        "Script": "readonly",
        "Thread": "readonly",
        "ThumbRelocator": "readonly",
        "ThumbWriter": "readonly",
        "UnixInputStream": "readonly",
        "UnixOutputStream": "readonly",
        "X86Relocator": "readonly",
        "X86Writer": "readonly",
        "ptr": "readonly",
        "int64": "readonly",
        "uint64": "readonly",
      },
    }
  }
];