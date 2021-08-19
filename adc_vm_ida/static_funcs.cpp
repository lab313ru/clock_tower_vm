#include "adc.hpp"

ea_t get_var_addr(uint16 ref) {
  auto type = ref >> 12;
  auto index = (ref & 0x3FF) << 1;

  switch (type) {
  case 0x00: return VAR_BASE + VAR_D_BASE + index;
  default: return VAR_BASE + type * 0x1000 + index;
  }
}

ea_t get_jump_call_addr(uint16 idx) {
  uint16 offset = get_word(REF_BASE + idx * 4 + 0);
  uint16 index = get_word(REF_BASE + idx * 4 + 2);
  return ((index * 0x8000) | offset) + 2;
}

bool is_var(uint16 ref) {
  return
    (ref >= 0xF000 && ref <= 0xF1FF) ||
    (ref >= 0xE000 && ref <= 0xE1FF) ||
    (ref >= 0xD000 && ref <= 0xD1FF) ||
    (ref >= 0xC000 && ref <= 0xC1FF);
}

bool is_jump_call_insn(uint16 itype) {
  return (
    itype == ADCVM_jmp ||
    itype == ADCVM_call ||
    itype == ADCVM_endwhile ||
    itype == ADCVM_else
    );
}

bool is_cond_insn(uint16 itype) {
  return (
    itype == ADCVM_if ||
    itype == ADCVM_while
    );
}

bool is_cond_opcode(uint16 opcode) {
  return (
    opcode == 0xFF11 || // EQU
    opcode == 0xFF12 || // NEQ
    opcode == 0xFF13 || // GRE
    opcode == 0xFF14 || // LWR
    opcode == 0xFF15 || // GEQ
    opcode == 0xFF16    // LEQ
    );
}

bool is_skippable_insn(uint16 itype) {
  return (
    itype == ADCVM_endif
    );
}
