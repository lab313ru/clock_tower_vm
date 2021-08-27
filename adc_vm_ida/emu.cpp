#include "adc.hpp"

void adcvm_t::handle_operand(const insn_t& insn, const op_t& op, bool isload) const {
  switch (op.type) {
  case o_imm: { // val
    set_immd(insn.ea);
    op_num(insn.ea, op.n);
  } break;
  case o_mem: { // var
    insn.create_op_data(op.addr, op);
    insn.add_dref(op.addr, op.offb, isload ? dr_R : dr_W);
  } break;
  case o_near: {
    if (is_jump_call_insn(insn.itype)) {
      switch (insn.itype) {
      case ADCVM_call: {
        insn.add_cref(op.addr, op.offb, fl_CN);
      } break;
      case ADCVM_jmp: {
        insn_t next;
        if (decode_insn(&next, insn.ea + insn.size)) {
          if (next.itype == ADCVM_endif || next.itype == ADCVM_else) { // to jmp + endif/else
            auto_make_code(next.ea);
          }
        }
      }
      default: {
        insn.add_cref(op.addr, op.offb, fl_JN);
      }
      }
    }
    else if (is_cond_insn(insn.itype)) {
      insn.add_cref(op.addr, op.offb, fl_JN);
    }
    else {
      insn.add_dref(op.addr, op.offb, dr_O);
    }

    if (insn.itype == ADCVM_evdef) {
      auto_make_proc(op.addr);
    }
  } break;
  }
}

void adcvm_t::handle_bgspranim(const insn_t& insn, const op_t& op, bool isload) const {
  if (insn.itype != ADCVM_bgspranim || op.n != 7) {
    return;
  }
  
  bool isvar = is_var(op.specval_shorts.low);

  if (isvar) {
    ea_t var_addr = get_var_addr(op.specval_shorts.low);
    insn.create_op_data(var_addr, op.offb + 2, dt_word);
    insn.add_dref(var_addr, op.offb + 2, dr_R);
  }
  else {
    set_immd(insn.ea);
  }
}

void adcvm_t::handle_evdef(const insn_t& insn) const {
  if (insn.itype != ADCVM_evdef) {
    return;
  }

  qstring name;
  if (!has_name(get_flags(insn.Op1.addr)) && insn.Op1.value != 0xFF1F) {
    name.sprnt("evt_%d_func_%0X", insn.Op2.value, insn.Op1.addr);
    set_name(insn.Op1.addr, name.c_str());
  }
}

void adcvm_t::handle_if_while_cond(const insn_t& insn, const op_t& op) const {
  if (!is_cond_insn(insn.itype) || op.n != 1) {
    return;
  }

  for (auto i = 0; i < (uint8)op.reg; ++i) {
    uint16 cond = (uint16)insn.ops[op.n + i].value;
    uint16 var = insn.ops[op.n + i].addr_shorts.high;
    uint16 var_or_val = insn.ops[op.n + i].addr_shorts.low;

    uint16 off = op.offb + i * 3 * 2;

    ea_t var_addr = get_var_addr(var);
    insn.create_op_data(var_addr, off + 2, dt_word);
    insn.add_dref(var_addr, off + 2, dr_R);

    bool isvar = is_var(var_or_val);

    if (isvar) {
      var_addr = get_var_addr(var);
      insn.create_op_data(var_addr, off + 4, dt_word);
      insn.add_dref(var_addr, off + 4, dr_R);
    }
    else {
      set_immd(insn.ea);
    }
  }
}

int adcvm_t::emu(const insn_t& insn) const {
  uint32 feature = insn.get_canon_feature(ph);
  bool flow = ((feature & CF_STOP) == 0);

  if (feature & CF_USE1) handle_operand(insn, insn.Op1, 1);
  if (feature & CF_USE2) handle_operand(insn, insn.Op2, 1);
  if (feature & CF_USE3) handle_operand(insn, insn.Op3, 1);
  if (feature & CF_USE4) handle_operand(insn, insn.Op4, 1);
  if (feature & CF_USE5) handle_operand(insn, insn.Op5, 1);
  if (feature & CF_USE6) handle_operand(insn, insn.Op6, 1);
  if (feature & CF_USE7) handle_operand(insn, insn.Op7, 1);
  if (feature & CF_USE8) handle_operand(insn, insn.Op8, 1);
  if (feature & CF_USE8) handle_bgspranim(insn, insn.Op8, 1);

  if (feature & CF_CHG1) handle_operand(insn, insn.Op1, 0);
  if (feature & CF_CHG2) handle_operand(insn, insn.Op2, 0);
  if (feature & CF_CHG3) handle_operand(insn, insn.Op3, 0);
  if (feature & CF_CHG4) handle_operand(insn, insn.Op4, 0);
  if (feature & CF_CHG5) handle_operand(insn, insn.Op5, 0);
  if (feature & CF_CHG6) handle_operand(insn, insn.Op6, 0);
  if (feature & CF_CHG7) handle_operand(insn, insn.Op7, 0);
  if (feature & CF_CHG8) handle_operand(insn, insn.Op8, 0);
  if (feature & CF_USE8) handle_bgspranim(insn, insn.Op8, 0);

  handle_if_while_cond(insn, insn.Op2);
  handle_evdef(insn);

  bool spec_jump = (insn.Op1.specflag1 & 0x100);

  if (flow) {
    if (!spec_jump) {
      add_cref(insn.ea, insn.ea + insn.size, fl_F);
    }
    else {
      add_cref(insn.ea, insn.Op1.specval, fl_F);
    }
  }

  return 1;
}
