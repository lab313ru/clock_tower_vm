#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <restclient-cpp/restclient.h>

#include "ida_plugin.h"


static bool init_plugin(void) {
  return (ph.id == (0x8000 + 666));
}

static void print_version()
{
  static const char format[] = NAME " debugger plugin v%s;\nAuthor: DrMefistO [Lab 313] <newinferno@gmail.com>.";
  info(format, VERSION);
  msg(format, VERSION);
}

static const char form_name[] = "ADC VM Debugger";

#pragma push(pack, 1)
typedef struct vm_state_t {
  uint32_t pc;
  union {
    struct {
      uint16_t varsd[0x200];
      uint16_t varsf[0x40];
      uint16_t varse[0x40];
      uint16_t varsc[0x80];
    };
    uint8_t full[0x400 + 0x80 + 0x80 + 0x100];
  } workmem;
} vm_state_t;
#pragma pop(pack)

struct vars_chooser_t : public chooser_t {
  int base, count;
  uint32_t* pc;
  uint16_t* buffer;

public:
  vars_chooser_t(const char* name, uint32_t* pc, int base_, uint16_t* buffer_, int count_);

  virtual bool idaapi init();
  virtual size_t idaapi get_count() const override;
  virtual void idaapi get_row(qstrvec_t* out, int* out_icon, chooser_item_attrs_t* out_attrs, size_t n) const override;
  virtual cbret_t idaapi edit(size_t n) override {
    return cbret_t();
  }
  virtual cbret_t idaapi refresh(ssize_t n) override {
    get_buffer();
    return cbret_t(n);
  }

  bool get_buffer();
};

struct plugin_ctx_t : public plugmod_t {
  TWidget* editor_widget = nullptr;
  ea_t pc;
  uint16_t varsd[0x200];
  uint16_t varsf[0x40];
  uint16_t varse[0x40];
  uint16_t varsc[0x80];

  qtimer_t tim;
  vars_chooser_t ch_pc = vars_chooser_t("pc chooser", &pc, -1, nullptr, 1);
  sizevec_t ch_pc_sel;
  vars_chooser_t ch_d = vars_chooser_t("varsd chooser", &pc, 0x0D, varsd, qnumber(varsd));
  sizevec_t ch_d_sel;
  vars_chooser_t ch_f = vars_chooser_t("varsf chooser", &pc, 0x0F, varsf, qnumber(varsf));
  sizevec_t ch_f_sel;
  vars_chooser_t ch_e = vars_chooser_t("varse chooser", &pc, 0x0E, varse, qnumber(varse));
  sizevec_t ch_e_sel;
  vars_chooser_t ch_c = vars_chooser_t("varsc chooser", &pc, 0x0C, varsc, qnumber(varsc));
  sizevec_t ch_c_sel;

public:
  virtual bool idaapi run(size_t arg) override;
  void open_debugger_form(int options = 0);
  void close_debugger_form();
  int editor_modcb(int fid, form_actions_t& fa);
};

static int idaapi editor_modcb_(int fid, form_actions_t& fa) {
  plugin_ctx_t& ctx = *(plugin_ctx_t*)fa.get_ud();
  return ctx.editor_modcb(fid, fa);
}

int plugin_ctx_t::editor_modcb(int fid, form_actions_t& fa) {
  switch (fid) {
  case CB_INIT: {

  } break;
  case CB_CLOSE: {
    editor_widget = nullptr;
  } break;
  }

  return 1;
}

bool vars_chooser_t::get_buffer() {
  RestClient::Response r = RestClient::get("http://127.0.0.1:8080/api/v1/vm/state");

  if (r.code == -1) {
    return false;
  }

  *pc = reinterpret_cast<vm_state_t*>(const_cast<char*>(r.body.data()))->pc;

  switch (base) {
  case 0x0D: {
    memcpy((uint8_t*)buffer, reinterpret_cast<vm_state_t*>(const_cast<char*>(r.body.data()))->workmem.varsd, sizeof(vm_state_t::workmem.varsd));
  } break;
  case 0x0F: {
    memcpy((uint8_t*)buffer, reinterpret_cast<vm_state_t*>(const_cast<char*>(r.body.data()))->workmem.varsf, sizeof(vm_state_t::workmem.varsf));
  } break;
  case 0x0E: {
    memcpy((uint8_t*)buffer, reinterpret_cast<vm_state_t*>(const_cast<char*>(r.body.data()))->workmem.varse, sizeof(vm_state_t::workmem.varse));
  } break;
  case 0x0C: {
    memcpy((uint8_t*)buffer, reinterpret_cast<vm_state_t*>(const_cast<char*>(r.body.data()))->workmem.varsc, sizeof(vm_state_t::workmem.varsc));
  } break;
  }

  return true;
}

vars_chooser_t::vars_chooser_t(const char* name, uint32_t* pc_, int base_, uint16_t* buffer_, int count_) : chooser_t(), pc(pc_), base(base_), buffer(buffer_), count(count_) {
  columns = 2;
  static const int widths_[] = { 10, 10 };
  static const char* const header_[] = { "Var", "Value" };
  widths = widths_;
  header = header_;
  title = name;
}

bool idaapi vars_chooser_t::init() {
  get_buffer();
  return true;
}

size_t idaapi vars_chooser_t::get_count() const {
  return count;
}

void idaapi vars_chooser_t::get_row(qstrvec_t* out, int* out_icon, chooser_item_attrs_t* out_attrs, size_t n) const {
  if (base == -1) {
    (*out)[0].sprnt("0");
    (*out)[1].sprnt("%06X", *pc);
  }
  else {
    (*out)[0].sprnt("%X%03X", base, n * 2);
    (*out)[1].sprnt("%04X", buffer[n]);
  }
}

void plugin_ctx_t::open_debugger_form(int options) {
  qstring formdef;
  formdef.sprnt("BUTTON NO NONE\n"
    "BUTTON YES NONE\n"
    "BUTTON CANCEL NONE\n"
    "%s\n", form_name);
  formdef.append(
    "\n"
    "%/%*"
    "\n"
    "<~P~ause/Run:B:1:::><Step ~i~nto:B:2:::><Step ~o~ver:B:3:::>\n"
    "<~A~dd breakpoint:B:4:::><~D~elete breakpoint:B:5:::>\n"
    "<PC:E0:0:40:::>\n"
    "<VarsD:E6:0:40:::>\n<VarsF:E7:0:40:::>\n<VarsE:E8:0:40:::>\n<VarsC:E9:0:40:::>\n");

  formdef.append("\n");

  pc = 0;
  memset(varsd, 0, sizeof(varsd));
  memset(varsf, 0, sizeof(varsf));
  memset(varse, 0, sizeof(varse));
  memset(varsc, 0, sizeof(varsc));

  ch_pc_sel.push_back(0);
  ch_d_sel.push_back(0);
  ch_f_sel.push_back(0);
  ch_e_sel.push_back(0);
  ch_c_sel.push_back(0);

  editor_widget = open_form(
    formdef.c_str(), options,
    editor_modcb_, this,
    editor_modcb_, editor_modcb_, editor_modcb_, editor_modcb_, editor_modcb_,
    &ch_pc, &ch_pc_sel,
    &ch_d, &ch_d_sel, &ch_f, &ch_f_sel, &ch_e, &ch_e_sel, &ch_c, &ch_c_sel
    );

  set_dock_pos(form_name, "IDA View-A", DP_RIGHT, 0, 0, 50, 100);

  tim = register_timer(100, [](void* ud) -> int {
    refresh_chooser("pc chooser");
    refresh_chooser("varsd chooser");
    //refresh_chooser("varsf");
    //refresh_chooser("varse");
    //refresh_chooser("varsc");
    return 100;
    }, this);
}

void plugin_ctx_t::close_debugger_form() {
  close_widget(editor_widget, WCLS_CLOSE_LATER);
  editor_widget = nullptr;
  unregister_timer(tim);
}

bool idaapi plugin_ctx_t::run(size_t arg) {
  open_debugger_form(WOPN_RESTORE);
  
  return true;
}

static plugmod_t* idaapi init(void) {
  if (init_plugin()) {
    print_version();
    return new plugin_ctx_t;
  }

  return PLUGIN_SKIP;
}

char comment[] = NAME " debugger plugin by DrMefistO.";

char help[] =
NAME " debugger plugin by DrMefistO.\n"
"\n"
"This module lets you debug Clock Tower VM (ADCVM) in IDA.\n";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    comment,
    help,
    NAME " debugger plugin",
    ""
};