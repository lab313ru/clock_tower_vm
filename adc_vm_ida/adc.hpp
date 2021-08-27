#pragma once

#include "idaidp.hpp"
#include "ins.hpp"

struct adcvm_t : public procmod_t {
  std::map<uint16, ea_t> whiles;
  std::map<uint16, ea_t> ifs;

  ea_t cmp_dest;

  adcvm_t();

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  int idaapi ana(insn_t* _insn);
  int idaapi emu(const insn_t& insn) const;
  void handle_operand(const insn_t& insn, const op_t& op, bool isload) const;
  void handle_bgspranim(const insn_t& insn, const op_t& op, bool isload) const;
  void handle_if_while_cond(const insn_t& insn, const op_t& op) const;
  void handle_evdef(const insn_t& insn) const;

  void op_cond(insn_t& insn, op_t& x) const;
};

const ea_t VAR_BASE = 0x01000000;
const uint16 VAR_C_BASE = 0xC000;
const uint16 VAR_D_BASE = 0xD000;
const uint16 VAR_E_BASE = 0xE000;
const uint16 VAR_F_BASE = 0xF000;
const uint16 VARS_SIZE = 0x0800;
const ea_t REF_BASE = 0x02000000;

ea_t get_var_addr(uint16 ref);
ea_t get_jump_call_addr(uint16 idx);
bool is_var(uint16 ref);
bool is_jump_call_insn(uint16 itype);
bool is_cond_insn(uint16 itype);
bool is_cond_opcode(uint16 opcode);
