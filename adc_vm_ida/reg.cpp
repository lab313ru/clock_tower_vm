#include "adc.hpp"
#include <diskio.hpp>

static const char* const regnames[] = {
  "cs", "ds"
};

static enum adcvm_regs {
  rVcs, rVds
};

static const asm_t adcasm = {
  AS_COLON | ASH_HEXF3,
  0,
  "Clock Tower Virtual Machine Bytecode",
  0,
  NULL,         // header lines
  "org",        // org
  "end",        // end

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  "dc",         // ascii string directive
  "dcb",        // byte directive
  "dc",         // word directive
  NULL,         // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  "bs#s(c,) #d, #v", // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  "*",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  "global",     // "public" name keyword
  NULL,         // "weak"   name keyword
  "xref",       // "extrn"  name keyword
                // .extern directive requires an explicit object size
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  NULL,         // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  "<<",         // shl
  ">>",         // shr
  "sizeof",         // sizeof
  AS2_BYTE1CHAR,// One symbol per processor byte
};

static int data_id;

ssize_t idaapi notify(void* user_data, int notification_code, va_list va) {
  if (notification_code == processor_t::ev_get_procmod) {
    data_id = 0;
    return size_t(SET_MODULE_DATA(adcvm_t));
  }

  return 0;
}

static void load_adt(char* ado_name) {
  auto flen = strlen(ado_name);

  if (flen == 0) {
    return;
  }

  ado_name[flen - 1] = 'T';

  auto* li = open_linput(ado_name, false);

  if (li == nullptr) {
    return;
  }

  auto li_size = qlsize(li);

  add_segm(0, REF_BASE, (ea_t)(REF_BASE + li_size), "refs", "CONST");
  file2base(li, 0, REF_BASE, (ea_t)(REF_BASE + li_size), FILEREG_NOTPATCHABLE);

  close_linput(li);
}

static void create_var_segments() {
  add_segm(0, VAR_BASE + VAR_C_BASE, VAR_BASE + VAR_C_BASE + VARS_SIZE, "varsc", "DATA");
  auto* s = getseg(VAR_BASE + VAR_C_BASE);
  s->perm = SEGPERM_READ | SEGPERM_WRITE;

  add_segm(0, VAR_BASE + VAR_D_BASE, VAR_BASE + VAR_D_BASE + VARS_SIZE, "varsd", "DATA");
  s = getseg(VAR_BASE + VAR_D_BASE);
  s->perm = SEGPERM_READ | SEGPERM_WRITE;

  add_segm(0, VAR_BASE + VAR_E_BASE, VAR_BASE + VAR_E_BASE + VARS_SIZE, "varse", "DATA");
  s = getseg(VAR_BASE + VAR_E_BASE);
  s->perm = SEGPERM_READ | SEGPERM_WRITE;

  add_segm(0, VAR_BASE + VAR_F_BASE, VAR_BASE + VAR_F_BASE + VARS_SIZE, "varsf", "DATA");
  s = getseg(VAR_BASE + VAR_F_BASE);
  s->perm = SEGPERM_READ | SEGPERM_WRITE;
}

ssize_t idaapi adcvm_t::on_event(ssize_t msgid, va_list va) {
  int retcode = 1;

  switch (msgid) {
  case processor_t::ev_init: {
    inf_set_be(false);
    inf_set_gen_lzero(true);
  } break;
  case processor_t::ev_term: {
    clr_module_data(data_id);
  } break;
  case processor_t::ev_newfile: { // catch ADO load and load ADT too
    auto* adoname = va_arg(va, char*);
    load_adt(adoname);
    create_var_segments();
  } break;
  case processor_t::ev_is_cond_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return is_cond_insn(insn->itype);
  } break;
  case processor_t::ev_is_ret_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return (insn->itype == ADCVM_ret) ? 1 : -1;
  } break;
  case processor_t::ev_is_call_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return (insn->itype == ADCVM_call) ? 1 : -1;
  } break;
  case processor_t::ev_ana_insn: {
    auto* out = va_arg(va, insn_t*);
    return ana(out);
  } break;
  case processor_t::ev_emu_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return emu(*insn);
  } break;
  case processor_t::ev_out_insn: {
    auto* ctx = va_arg(va, outctx_t*);
    out_insn(*ctx);
  } break;
  case processor_t::ev_out_operand: {
    auto* ctx = va_arg(va, outctx_t*);
    const auto* op = va_arg(va, const op_t*);
    return out_opnd(*ctx, *op) ? 1 : -1;
  } break;
  default:
    return 0;
  }

  return retcode;
}

adcvm_t::adcvm_t() {
  ifs.clear();
  whiles.clear();
  cmp_dest = 0;
}

static const asm_t* const asms[] = { &adcasm, NULL };
static const char* const shnames[] = { "ADCVM", NULL };
static const char* const lnames[] = { "Clock Tower: Clock Tower ADC VM", NULL };

static const uchar retcode[] = { 0x00, 0xFF };

static const bytes_t retcodes[] = {
  { sizeof(retcode), retcode },
  { 0, NULL }
};

processor_t LPH = {
  IDP_INTERFACE_VERSION,
  0x8000 + 666,
  PR_USE32 | PR_DEFSEG32 | PRN_HEX | PR_WORD_INS | PR_BINMEM | PR_NO_SEGMOVE | PR_CNDINSNS,
  0,
  8, 8,
  shnames,
  lnames,
  asms,

  notify,

  regnames,
  qnumber(regnames),

  rVcs, rVds,
  0,
  rVcs, rVds,

  NULL,
  retcodes,

  0, ADCVM_last,
  Instructions,
};
