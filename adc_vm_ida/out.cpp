#include "adc.hpp"

class out_adcvm_t : public outctx_t {
  out_adcvm_t(void) = delete; // not used
public:
  bool out_operand(const op_t& x);
  void out_str_ascii(const op_t& x);
  void out_str_sjis(const op_t& x);
  void out_insn(void);
  void out_setmark(const op_t& x);
  void out_var(uint16 ref);
  void out_var_or_val(ea_t addr);
  void out_var_or_val_by_ref(uint16 ref);
  void out_val16(ea_t addr);
  void out_var_or_val_array(const op_t& x);
  void out_condition(const op_t& x);
};
CASSERT(sizeof(out_adcvm_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_adcvm_t);

bool out_adcvm_t::out_operand(const op_t& x) {
  switch (x.type) {
  case o_void: {
    return false;
  } break;
  case o_imm: {
    out_value(x, OOFS_IFSIGN | OOFW_IMM);
  } break;
  case o_near:
  case o_mem: {
    if (!out_name_expr(x, x.addr)) {
      out_tagon(COLOR_ERROR);
      out_btoa(x.addr, 16);
      out_tagoff(COLOR_ERROR);
      remember_problem(PR_NONAME, insn.ea);
    }
  } break;
  }

  return true;
}

void out_adcvm_t::out_str_ascii(const op_t& x) {
  out_symbol('"');
  out_tagon(COLOR_DSTR);

  for (auto i = 0; i < (uint16)x.value; ++i) {
    uchar b = get_byte(insn.ea + x.offb + i);
    if (b == '\0') {
      continue;
    }

    out_char(b);
  }

  out_tagoff(COLOR_DSTR);
  out_symbol('"');
}

void out_adcvm_t::out_str_sjis(const op_t& x) {
  out_symbol('"');
  out_tagon(COLOR_DSTR);

  bytevec_t in;

  for (auto i = 0; i < (uint16)x.value; ++i) {
    uchar b = get_byte(insn.ea + x.offb + i);
    if (b == '\0') {
      b = in.back();
      in.pop_back();

      if (b == '\n') {
        in.add('\\');
        b = 'n';
      }
    }

    in.add(b);
  }

  bytevec_t bytes;
  ssize_t conv = convert_encoding(&bytes, "Shift-JIS", "UTF8", &in);

  out_line((const char*)bytes.begin());

  out_tagoff(COLOR_DSTR);
  out_symbol('"');
}

void out_adcvm_t::out_var(uint16 ref) {
  op_t op;

  op.addr = op.value = get_var_addr(ref);
  op.dtype = dt_word;
  op.type = o_mem;

  out_operand(op);
}

void out_adcvm_t::out_var_or_val_by_ref(uint16 ref) {
  op_t op;
  op.value = ref;

  bool isvar = is_var(ref);

  if (isvar) {
    op.addr = op.value = get_var_addr(ref);
  }

  op.dtype = dt_word;
  op.type = isvar ? o_mem : o_imm;

  out_operand(op);
}

void out_adcvm_t::out_var_or_val(ea_t addr) {
  uint16 ref = get_word(addr);
  out_var_or_val_by_ref(ref);
}

void out_adcvm_t::out_val16(ea_t addr) {
  op_t op;
  op.value = get_word(addr);
  op.dtype = dt_word;
  op.type = o_imm;

  out_operand(op);
}

void out_adcvm_t::out_setmark(const op_t& x) {
  for (auto i = 0; i < (uint16)x.value; ++i) {
    out_symbol('{');

    out_var_or_val(insn.ea + x.offb + i * 5 * 2 + 0);
    out_symbol(',');

    out_var_or_val(insn.ea + x.offb + i * 5 * 2 + 2);
    out_symbol(',');

    out_var_or_val(insn.ea + x.offb + i * 5 * 2 + 4);
    out_symbol(',');

    out_var_or_val(insn.ea + x.offb + i * 5 * 2 + 6);
    out_symbol(',');

    out_val16(insn.ea + x.offb + i * 5 * 2 + 8);

    out_symbol('}');

    if (i + 1 < (uint16)x.value) {
      out_symbol(',');
      out_char(' ');
    }
  }
}

void out_adcvm_t::out_var_or_val_array(const op_t& x) {
  out_symbol('{');

  for (auto i = 0; i < (uint16)x.value; ++i) {
    out_var_or_val(insn.ea + x.offb + i * 2);

    if (i + 1 < (uint16)x.value) {
      out_symbol(',');
      out_char(' ');
    }
  }

  out_symbol('}');
}

void out_adcvm_t::out_condition(const op_t& op) {
  out_symbol('(');
  uint16 ands_count = (uint16)op.value;

  for (auto i = 0; i < (uint16)op.reg; ++i) {
    uint16 cond = (uint16)insn.ops[op.n + i].value;
    uint16 var = insn.ops[op.n + i].addr_shorts.high;
    uint16 var_or_val = insn.ops[op.n + i].addr_shorts.low;

    out_var(var);

    switch (cond) {
    case 0xFF11: { // EQU
      out_line("==", COLOR_SYMBOL);
    } break;
    case 0xFF12: { // NEQ
      out_line("!=", COLOR_SYMBOL);
    } break;
    case 0xFF13: { // GRE
      out_line(">", COLOR_SYMBOL);
    } break;
    case 0xFF14: { // LWR
      out_line("<", COLOR_SYMBOL);
    } break;
    case 0xFF15: { // GEQ
      out_line(">=", COLOR_SYMBOL);
    } break;
    case 0xFF16: { // LEQ
      out_line("<=", COLOR_SYMBOL);
    } break;
    }

    out_var_or_val_by_ref(var_or_val);

    if ((i + 1 < (uint16)op.reg)) {
      if (ands_count > 0) {
        out_line(" && ", COLOR_SYMBOL);
        ands_count--;
      }
      else {
        out_line(" || ", COLOR_SYMBOL);
      }
    }
  }

  out_symbol(')');
}

void out_adcvm_t::out_insn(void) {
  if (insn.itype == ADCVM_endif || insn.itype == ADCVM_else) {
    out_tagon(COLOR_AUTOCMT);
    out_line("// ");
    out_line(insn.get_canon_mnem(ph));
    out_line("(");
    out_btoa(insn.Op1.value, 16);
    out_line(")");
    out_tagoff(COLOR_AUTOCMT);
    flush_outbuf();
    return;
  }

  out_line(insn.get_canon_mnem(ph));

  out_symbol('(');

  int n = 0;
  while (n < UA_MAXOP) {
    if (!insn.ops[n].shown()) {
      n++;
      continue;
    }

    if (insn.ops[n].type == o_void) {
      break;
    }

    bool drawn = false;

    switch (insn.itype) {
    case ADCVM_bgload: 
    case ADCVM_palload:
    case ADCVM_bgmreq:
    case ADCVM_sereq:
    case ADCVM_sepan:
    case ADCVM_sevol: {
      if (n == 1) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_mapload: {
      if (n == 1 || n == 2) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_mapwrt: {
      if (n == 2) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_msgout: {
      if (n == 2) {
        out_str_sjis(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_sestop: {
      if (n == 0) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_sereqpv:
    case ADCVM_sereqspr: {
      if (n == 3) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_aviplay: {
      if (n == 5) {
        out_str_ascii(insn.ops[n]);
        drawn = true;
      }
    } break;
    }

    switch (insn.itype) {
    case ADCVM_setmark: {
      if (n == 0) {
        out_setmark(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_sclblock: {
      if (n == 0 || n == 1) {
        out_var_or_val_array(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_spcfunc: {
      if (n == 1) {
        out_var_or_val_array(insn.ops[n]);
        drawn = true;
      }
    } break;
    case ADCVM_bgspranim: {
      if (n == 7) {
        out_one_operand(n);

        out_symbol(',');
        out_char(' ');

        out_var_or_val(insn.ea + insn.ops[n].offb + 2);
        drawn = true;
      }
    } break;
    case ADCVM_if:
    case ADCVM_while: {
      if (n == 1) {
        out_condition(insn.ops[n]);
        drawn = true;
      }
    } break;
    }

    if (!drawn) {
      out_one_operand(n);
    }

    if (n + 1 < UA_MAXOP && insn.ops[n + 1].type != o_void) {
      out_symbol(',');
      out_char(' ');
    }

    n++;
  }

  out_symbol(')');

  flush_outbuf();
}
