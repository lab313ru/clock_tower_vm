#pragma once

extern const instruc_t Instructions[];

enum nameNum {
  ADCVM_null = 0,
  ADCVM_ret,
  ADCVM_div,
  ADCVM_mul,
  ADCVM_sub,
  ADCVM_add,
  ADCVM_dec,
  ADCVM_inc,
  ADCVM_mov,
  ADCVM_equ,
  ADCVM_neq,
  ADCVM_gre,
  ADCVM_lwr,
  ADCVM_geq,
  ADCVM_leq,
  ADCVM_cmp_end,
  ADCVM_allend,
  ADCVM_jmp,
  ADCVM_call,
  ADCVM_evdef,
  ADCVM_end,
  ADCVM_if,
  ADCVM_while,
  ADCVM_nop,
  ADCVM_endif,
  ADCVM_endwhile,
  ADCVM_else,
  ADCVM_msginit,
  ADCVM_msgattr,
  ADCVM_msgout,
  ADCVM_setmark,
  ADCVM_msgwait,
  ADCVM_evstart,
  ADCVM_bgload,
  ADCVM_palload,
  ADCVM_bgmreq,
  ADCVM_sprclr,
  ADCVM_absobjanim,
  ADCVM_objanim,
  ADCVM_allsprclr,
  ADCVM_msgclr,
  ADCVM_screenclr,
  ADCVM_screenon,
  ADCVM_screenoff,
  ADCVM_screenin,
  ADCVM_screenout,
  ADCVM_bgdisp,
  ADCVM_bganim,
  ADCVM_bgscroll,
  ADCVM_palset,
  ADCVM_bgwait,
  ADCVM_wait,
  ADCVM_bwait,
  ADCVM_boxfill,
  ADCVM_bgclr,
  ADCVM_setbkcol,
  ADCVM_msgcol,
  ADCVM_msgspd,
  ADCVM_mapinit,
  ADCVM_mapload,
  ADCVM_mapdisp,
  ADCVM_sprent,
  ADCVM_setproc,
  ADCVM_sceinit,
  ADCVM_userctl,
  ADCVM_mapattr,
  ADCVM_mappos,
  ADCVM_sprpos,
  ADCVM_spranim,
  ADCVM_sprdir,
  ADCVM_gameinit,
  ADCVM_continit,
  ADCVM_sceend,
  ADCVM_mapscroll,
  ADCVM_sprlmt,
  ADCVM_sprwalkx,
  ADCVM_allsprdisp,
  ADCVM_mapwrt,
  ADCVM_sprwait,
  ADCVM_sereq,
  ADCVM_sndstop,
  ADCVM_sestop,
  ADCVM_bgmstop,
  ADCVM_doornoset,
  ADCVM_rand,
  ADCVM_btwait,
  ADCVM_fawait,
  ADCVM_sclblock,
  ADCVM_evstop,
  ADCVM_sereqpv,
  ADCVM_sereqspr,
  ADCVM_scereset,
  ADCVM_bgsprent,
  ADCVM_bgsprpos,
  ADCVM_bgsprset,
  ADCVM_slantset,
  ADCVM_slantclr,
  ADCVM_dummy,
  ADCVM_spcfunc,
  ADCVM_sepan,
  ADCVM_sevol,
  ADCVM_bgdisptrn,
  ADCVM_debug,
  ADCVM_trace,
  ADCVM_tmwait,
  ADCVM_bgspranim,
  ADCVM_abssprent,
  ADCVM_nextcom,
  ADCVM_workclr,
  ADCVM_bgbufclr,
  ADCVM_absbgsprent,
  ADCVM_aviplay,
  ADCVM_avistop,
  ADCVM_sprmark,
  ADCVM_bgmattr,
  ADCVM_last,
};
