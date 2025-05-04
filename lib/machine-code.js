export function parseInstructionsAt (address, tryParse, { limit }) {
  let cursor = address;
  let prevInsn = null;

  for (let i = 0; i !== limit; i++) {
    const insn = Instruction.parse(cursor);

    const value = tryParse(insn, prevInsn);
    if (value !== null) {
      return value;
    }

    cursor = insn.next;
    prevInsn = insn;
  }

  return null;
}
