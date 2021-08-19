#include <map>
#include "adc.hpp"

static void op_var(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  uint16 ref = insn.get_next_word();
  x.addr = x.value = get_var_addr(ref);
  x.dtype = dt_word;
  x.type = o_mem;
}

static void op_var_or_val(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  uint16 ref = x.value = insn.get_next_word();
  bool isvar = is_var(ref);

  if (isvar) {
    x.addr = x.value = get_var_addr(ref);
  }
  
  x.dtype = dt_word;
  x.type = isvar ? o_mem : o_imm;
}

static void op_val16(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = insn.get_next_word();
  x.dtype = dt_word;
  x.type = o_imm;
}

static void op_jump_call(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  uint16 ref = x.value = insn.get_next_word();
  x.dtype = dt_code;
  x.type = o_near;
  x.addr = get_jump_call_addr(ref);
}

static void op_evdef(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  uint16 ref = x.value = insn.get_next_word();

  if (ref == 0xFF1F) {
    x.dtype = dt_word;
    x.type = o_imm;
  }
  else {
    x.value &= 0xFFF;
    x.dtype = dt_code;
    x.type = o_near;
    x.addr = get_jump_call_addr(x.value);
  }
}

static ea_t find_if_end(uint16 idx, ea_t start) {
  ea_t off = 0;

  while (true) {
    uint16 word = get_word(start + off);
    off += 2;

    if (word == 0xFF2D || word == 0xFF2F) {
      uint16 if_idx = get_word(start + off);
      off += 2;

      if (if_idx == idx) {
        return start + off;
      }
    }
  }
}

static ea_t find_while_end(uint16 idx, ea_t start) {
  ea_t off = 0;

  while (true) {
    uint16 word = get_word(start + off);
    off += 2;

    if (word == 0xFF2E) {
      uint16 if_idx = get_word(start + off);
      off += 2;

      if (if_idx == idx) {
        return start + off;
      }
    }
  }
}

static ea_t find_else_end(uint16 idx, ea_t start) {
  ea_t off = 0;

  while (true) {
    uint16 word = get_word(start + off);
    off += 2;

    if (word == 0xFF2D) { // endif
      uint16 if_idx = get_word(start + off);
      off += 2;

      if (if_idx == idx) {
        return start + off;
      }
    }
  }
}

static uint16 find_str_ascii_end(insn_t& insn) {
  uint16 len = 0;

  while (true) {
    uint16 word = insn.get_next_word();

    if (word == 0x0000) {
      break;
    }

    len += 2;
  }

  return len;
}

static uint16 find_str_sjis_end(insn_t& insn) {
  uint16 len = 0;

  while (true) {
    uint16 word = insn.get_next_word();

    if (
      (word == 0xFF20) || // ALLEND
      (word == 0xFF28) || // END
      (word == 0xFF36)    // MSGWAIT
      ) {
      break;
    }

    len += 2;
  }

  return len;
}

static uint16 find_setmark_end(insn_t& insn) {
  uint16 len = 0;

  while (true) {
    uint16 v = insn.get_next_word();

    if (v == 0xFF28) { // vm_end
      break;
    }

    uint16 v1 = insn.get_next_word();
    uint16 v2 = insn.get_next_word();
    uint16 v3 = insn.get_next_word();
    uint16 v4 = insn.get_next_word();

    len++;
  }

  return len;
}

static void op_if(insn_t& insn, op_t& x, std::map<uint16, ea_t>& ifs) {
  x.offb = (char)insn.size;

  uint16 idx = x.value = insn.get_next_word();
  x.addr = find_if_end(idx, insn.ea + insn.size);
  x.dtype = dt_code;
  x.type = o_near;

  ifs[idx] = x.addr;
}

static uint8 find_if_while_end(insn_t& insn) {
  uint8 len = 0;
  uint16 n = 1;

  while (true) {
    uint16 opcode = insn.get_next_word();

    if (!is_cond_opcode(opcode)) {
      break;
    }

    if (n == UA_MAXOP) {
      error("Cannot handle more than 7 conditions!");
      return 0;
    }

    insn.ops[n].value = opcode;
    insn.ops[n].addr_shorts.high = insn.get_next_word();
    insn.ops[n].addr_shorts.low = insn.get_next_word();

    n++;
    len++;
  }

  return len;
}

static void op_if_while_cond(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = insn.get_next_word(); // ands_count
  x.reg = find_if_while_end(insn); // conditions count
  x.dtype = dt_word;
  x.type = o_imm;
}

static void op_endif(insn_t& insn, op_t& x, std::map<uint16, ea_t>& ifs) {
  x.offb = (char)insn.size;

  uint16 idx = x.value = insn.get_next_word();
  x.addr = ifs[idx];
  x.dtype = dt_word; // dt_code;
  x.type = o_imm; // o_near;
}

static void op_while(insn_t& insn, op_t& x, std::map<uint16, ea_t>& whiles) {
  x.offb = (char)insn.size;

  uint16 idx = x.value = insn.get_next_word();
  x.addr = find_while_end(idx, insn.ea + insn.size);
  x.dtype = dt_code;
  x.type = o_near;

  whiles[idx] = insn.ea;
}

static void op_endwhile(insn_t& insn, op_t& x, std::map<uint16, ea_t>& whiles) {
  x.offb = (char)insn.size;

  uint16 idx = x.value = insn.get_next_word();
  x.addr = whiles[idx];
  x.dtype = dt_code;
  x.type = o_near;
}

static void op_else(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  uint16 idx = x.value = insn.get_next_word();
  x.addr = find_else_end(idx, insn.ea + insn.size);
  x.dtype = dt_code;
  x.type = o_near;
}

static void op_str_ascii(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = find_str_ascii_end(insn); // string len
  x.dtype = dt_word;
  x.type = o_imm;
}

static void op_str_sjis(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = find_str_sjis_end(insn); // string len
  x.dtype = dt_word;
  x.type = o_imm;
}

static void op_setmark(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = find_setmark_end(insn); // items count
  x.dtype = dt_word;
  x.type = o_imm;
}

static void op_sclblock(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = insn.get_next_word();
  x.dtype = dt_word;
  x.type = o_imm;

  for (auto i = 0; i < (uint16)x.value; ++i) {
    insn.get_next_word();
  }
}

static void op_spcfunc(insn_t& insn, op_t& x) {
  x.offb = (char)insn.size;

  x.value = insn.get_next_word();
  x.dtype = dt_word;
  x.type = o_imm;

  for (auto i = 0; i < (uint16)x.value; ++i) {
    insn.get_next_word();
  }
}

void adcvm_t::op_cond(insn_t& insn, op_t& x) const {
  x.offb = 0;

  x.dtype = dt_code;
  x.type = o_near;
  x.addr = cmp_dest;
}

int idaapi adcvm_t::ana(insn_t* _insn) {
  if (_insn == NULL) {
    return 0;
  }

  insn_t& insn = *_insn;
  uint16 code = insn.get_next_word();

  switch (code) {
  case 0xFF00: {
    insn.itype = ADCVM_ret;
  } break;
  case 0xFF0A: {
    insn.itype = ADCVM_div;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF0B: {
    insn.itype = ADCVM_mul;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF0C: {
    insn.itype = ADCVM_sub;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF0D: {
    insn.itype = ADCVM_add;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF0E: {
    insn.itype = ADCVM_dec;
    op_var(insn, insn.Op1);
  } break;
  case 0xFF0F: {
    insn.itype = ADCVM_inc;
    op_var(insn, insn.Op1);
  } break;
  case 0xFF10: {
    insn.itype = ADCVM_mov;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF11: {
    insn.itype = ADCVM_equ;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF12: {
    insn.itype = ADCVM_neq;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF13: {
    insn.itype = ADCVM_gre;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF14: {
    insn.itype = ADCVM_lwr;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF15: {
    insn.itype = ADCVM_geq;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF16: {
    insn.itype = ADCVM_leq;
    op_var(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF1F: {
    insn.itype = ADCVM_cmp_end;
    op_cond(insn, insn.Op1);
  } break;
  case 0xFF20: {
    insn.itype = ADCVM_allend;
  } break;
  case 0xFF21: {
    insn.itype = ADCVM_jmp;
    op_jump_call(insn, insn.Op1);
  } break;
  case 0xFF22: {
    insn.itype = ADCVM_call;
    op_jump_call(insn, insn.Op1);
  } break;
  case 0xFF23: {
    insn.itype = ADCVM_evdef;
    op_evdef(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
  } break;
  case 0xFF28: {
    insn.itype = ADCVM_end;
  } break;
  case 0xFF29: {
    insn.itype = ADCVM_if;
    op_if(insn, insn.Op1, ifs);
    op_if_while_cond(insn, insn.Op2);
    cmp_dest = insn.Op1.addr;
  } break;
  case 0xFF2A: {
    insn.itype = ADCVM_while;
    op_while(insn, insn.Op1, whiles);
    op_if_while_cond(insn, insn.Op2);
    cmp_dest = insn.Op1.addr;
  } break;
  case 0xFF2B: {
    insn.itype = ADCVM_nop;
  } break;
  case 0xFF2D: {
    insn.itype = ADCVM_endif;
    op_endif(insn, insn.Op1, ifs);
  } break;
  case 0xFF2E: {
    insn.itype = ADCVM_endwhile;
    op_endwhile(insn, insn.Op1, whiles);
  } break;
  case 0xFF2F: {
    insn.itype = ADCVM_else;
    op_else(insn, insn.Op1);
  } break;
  case 0xFF30: {
    insn.itype = ADCVM_msginit;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF32: {
    insn.itype = ADCVM_msgattr;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
  } break;
  case 0xFF33: {
    insn.itype = ADCVM_msgout;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_str_sjis(insn, insn.Op3);
  } break;
  case 0xFF34: {
    insn.itype = ADCVM_setmark;
    op_setmark(insn, insn.Op1);
  } break;
  case 0xFF36: {
    insn.itype = ADCVM_msgwait;
  } break;
  case 0xFF37: {
    insn.itype = ADCVM_evstart;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF39: {
    insn.itype = ADCVM_bgload;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF3A: {
    insn.itype = ADCVM_palload;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF3B: {
    insn.itype = ADCVM_bgmreq;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF3C: {
    insn.itype = ADCVM_sprclr;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF3D: {
    insn.itype = ADCVM_absobjanim;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
  } break;
  case 0xFF3E: {
    insn.itype = ADCVM_objanim;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
  } break;
  case 0xFF3F: {
    insn.itype = ADCVM_allsprclr;
  } break;
  case 0xFF40: {
    insn.itype = ADCVM_msgclr;
  } break;
  case 0xFF41: {
    insn.itype = ADCVM_screenclr;
  } break;
  case 0xFF42: {
    insn.itype = ADCVM_screenon;
  } break;
  case 0xFF43: {
    insn.itype = ADCVM_screenoff;
  } break;
  case 0xFF44: {
    insn.itype = ADCVM_screenin;
  } break;
  case 0xFF45: {
    insn.itype = ADCVM_screenout;
  } break;
  case 0xFF46: {
    insn.itype = ADCVM_bgdisp;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF47: {
    insn.itype = ADCVM_bganim;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
  } break;
  case 0xFF48: {
    insn.itype = ADCVM_bgscroll;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF49: {
    insn.itype = ADCVM_palset;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF4A: {
    insn.itype = ADCVM_bgwait;
  } break;
  case 0xFF4B: {
    insn.itype = ADCVM_wait;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF4C: {
    insn.itype = ADCVM_bwait;
  } break;
  case 0xFF4D: {
    insn.itype = ADCVM_boxfill;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
  } break;
  case 0xFF4E: {
    insn.itype = ADCVM_bgclr;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF4F: {
    insn.itype = ADCVM_setbkcol;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
  } break;
  case 0xFF50: {
    insn.itype = ADCVM_msgcol;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF51: {
    insn.itype = ADCVM_msgspd;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF52: {
    insn.itype = ADCVM_mapinit;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF53: {
    insn.itype = ADCVM_mapload;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
    op_str_ascii(insn, insn.Op3);
  } break;
  case 0xFF54: {
    insn.itype = ADCVM_mapdisp;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF55: {
    insn.itype = ADCVM_sprent;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
  } break;
  case 0xFF56: {
    insn.itype = ADCVM_setproc;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF57: {
    insn.itype = ADCVM_sceinit;
  } break;
  case 0xFF58: {
    insn.itype = ADCVM_userctl;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF59: {
    insn.itype = ADCVM_mapattr;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF5A: {
    insn.itype = ADCVM_mappos;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
  } break;
  case 0xFF5B: {
    insn.itype = ADCVM_sprpos;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
  } break;
  case 0xFF5C: {
    insn.itype = ADCVM_spranim;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
  } break;
  case 0xFF5D: {
    insn.itype = ADCVM_sprdir;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF5E: {
    insn.itype = ADCVM_gameinit;
  } break;
  case 0xFF5F: {
    insn.itype = ADCVM_continit;
  } break;
  case 0xFF60: {
    insn.itype = ADCVM_sceend;
  } break;
  case 0xFF61: {
    insn.itype = ADCVM_mapscroll;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
  } break;
  case 0xFF62: {
    insn.itype = ADCVM_sprlmt;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
  } break;
  case 0xFF63: {
    insn.itype = ADCVM_sprwalkx;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF64: {
    insn.itype = ADCVM_allsprdisp;
  } break;
  case 0xFF65: {
    insn.itype = ADCVM_mapwrt;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_str_ascii(insn, insn.Op3);
  } break;
  case 0xFF66: {
    insn.itype = ADCVM_sprwait;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF67: {
    insn.itype = ADCVM_sereq;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF68: {
    insn.itype = ADCVM_sndstop;
  } break;
  case 0xFF69: {
    insn.itype = ADCVM_sestop;
    op_str_ascii(insn, insn.Op1);
  } break;
  case 0xFF6A: {
    insn.itype = ADCVM_bgmstop;
  } break;
  case 0xFF6B: {
    insn.itype = ADCVM_doornoset;
  } break;
  case 0xFF6C: {
    insn.itype = ADCVM_rand;
    op_val16(insn, insn.Op1);
    op_val16(insn, insn.Op2);
    op_var(insn, insn.Op3);
  } break;
  case 0xFF6D: {
    insn.itype = ADCVM_btwait;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF6E: {
    insn.itype = ADCVM_fawait;
  } break;
  case 0xFF6F: {
    insn.itype = ADCVM_sclblock;
    op_sclblock(insn, insn.Op1);
    op_sclblock(insn, insn.Op2);
  } break;
  case 0xFF70: {
    insn.itype = ADCVM_evstop;
  } break;
  case 0xFF71: {
    insn.itype = ADCVM_sereqpv;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_str_ascii(insn, insn.Op4);
  } break;
  case 0xFF72: {
    insn.itype = ADCVM_sereqspr;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_str_ascii(insn, insn.Op4);
  } break;
  case 0xFF73: {
    insn.itype = ADCVM_scereset;
  } break;
  case 0xFF74: {
    insn.itype = ADCVM_bgsprent;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF75: {
    insn.itype = ADCVM_bgsprpos;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
  } break;
  case 0xFF76: {
    insn.itype = ADCVM_bgsprset;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF77: {
    insn.itype = ADCVM_slantset;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
  } break;
  case 0xFF78: {
    insn.itype = ADCVM_slantclr;
  } break;
  case 0xFF79: {
    insn.itype = ADCVM_dummy;
  } break;
  case 0xFF7A: {
    insn.itype = ADCVM_spcfunc;
    op_var_or_val(insn, insn.Op1);
    op_spcfunc(insn, insn.Op2);
  } break;
  case 0xFF7B: {
    insn.itype = ADCVM_sepan;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF7C: {
    insn.itype = ADCVM_sevol;
    op_var_or_val(insn, insn.Op1);
    op_str_ascii(insn, insn.Op2);
  } break;
  case 0xFF7D: {
    insn.itype = ADCVM_bgdisptrn;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
  } break;
  case 0xFF7E: {
    insn.itype = ADCVM_debug;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF7F: {
    insn.itype = ADCVM_trace;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF80: {
    insn.itype = ADCVM_tmwait;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF81: {
    insn.itype = ADCVM_bgspranim;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
    insn.Op8.specval_shorts.low = insn.get_next_word(); // Op9
  } break;
  case 0xFF82: {
    insn.itype = ADCVM_abssprent;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
    op_var_or_val(insn, insn.Op7);
    op_var_or_val(insn, insn.Op8);
  } break;
  case 0xFF83: {
    insn.itype = ADCVM_nextcom;
    op_var_or_val(insn, insn.Op1);
  } break;
  case 0xFF84: {
    insn.itype = ADCVM_workclr;
  } break;
  case 0xFF85: {
    insn.itype = ADCVM_bgbufclr;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  case 0xFF86: {
    insn.itype = ADCVM_absbgsprent;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_var_or_val(insn, insn.Op6);
  } break;
  case 0xFF87: {
    insn.itype = ADCVM_aviplay;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
    op_str_ascii(insn, insn.Op6);
  } break;
  case 0xFF88: {
    insn.itype = ADCVM_avistop;
  } break;
  case 0xFF89: {
    insn.itype = ADCVM_sprmark;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
    op_var_or_val(insn, insn.Op3);
    op_var_or_val(insn, insn.Op4);
    op_var_or_val(insn, insn.Op5);
  } break;
  case 0xFF8A: {
    insn.itype = ADCVM_bgmattr;
    op_var_or_val(insn, insn.Op1);
    op_var_or_val(insn, insn.Op2);
  } break;
  default:
    return 0;
  }

  return insn.size;
}