#include "adc.hpp"

const instruc_t Instructions[] = {
  { "", 0 },
  { "ret", CF_STOP }, // RA -> PC
  { "div", CF_USE1 | CF_USE2 | CF_CHG1 }, // V = V / VAR_OR_VAL
  { "mul", CF_USE1 | CF_USE2 | CF_CHG1 }, // V = V * VAR_OR_VAL
  { "sub", CF_USE1 | CF_USE2 | CF_CHG1 }, // V = V - VAR_OR_VAL
  { "add", CF_USE1 | CF_USE2 | CF_CHG1 }, // V = V + VAR_OR_VAL
  { "dec", CF_USE1 | CF_CHG1 }, // V--
  { "inc", CF_USE1 | CF_CHG1 }, // V++
  { "mov", CF_CHG1 | CF_USE2 }, // V = VAR_OR_VAL
  { "equ", CF_USE1 | CF_USE2 | CF_USE3 }, // V == VAR_OR_VAL
  { "neq", CF_USE1 | CF_USE2 | CF_USE3 }, // V != VAR_OR_VAL
  { "gre", CF_USE1 | CF_USE2 | CF_USE3 }, // V > VAR_OR_VAL
  { "lwr", CF_USE1 | CF_USE2 | CF_USE3 }, // V < VAR_OR_VAL
  { "geq", CF_USE1 | CF_USE2 | CF_USE3 }, // V >= VAR_OR_VAL
  { "leq", CF_USE1 | CF_USE2 | CF_USE3 }, // V <= VAR_OR_VAL
  { "cmp_end", CF_USE1 }, // compare block end
  { "allend", CF_STOP }, // terminate
  { "jmp", CF_USE1 | CF_JUMP | CF_STOP }, // jump
  { "call", CF_USE1 | CF_JUMP | CF_CALL }, // call
  { "evdef", CF_USE1 | CF_USE2 | CF_USE3 }, // define an event
  { "end", 0 }, // end
  { "if", CF_USE1 | CF_USE2 }, // if block start
  { "while", CF_USE1 | CF_USE2 }, // while block start
  { "nop", 0 }, // just nop
  { "endif", CF_USE1 }, // if block end
  { "endwhile", CF_USE1 | CF_JUMP | CF_STOP }, // while block end
  { "else", CF_USE1 | CF_JUMP | CF_STOP }, // else
  { "msginit", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // init message
  { "msgattr", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // message attributes
  { "msgout", CF_USE1 | CF_USE2 | CF_USE3 }, //output message
  { "setmark", CF_USE1 }, // set mark (can have many V,V1-V4 things), count in .value
  { "msgwait", 0 }, // wait for message
  { "evstart", CF_USE1 | CF_USE2 }, // start event
  { "bgload", CF_USE1 | CF_USE2 }, // load background
  { "palload", CF_USE1 | CF_USE2 }, // load palette
  { "bgmreq", CF_USE1 | CF_USE2 }, // request music file
  { "sprclr", CF_USE1 }, // clear sprite
  { "absobjanim", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // absolute object animation
  { "objanim", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // object animation
  { "allsprclr", 0 }, // clear all sprites
  { "msgclr", 0 }, // clear message
  { "screenclr", 0 }, // clear screen
  { "screenon", 0 }, // enable screen
  { "screenoff", 0 }, // disable screen
  { "screenin", 0 }, // enter screen
  { "screenout", 0 }, // exit screen
  { "bgdisp", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // display background
  { "bganim", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 }, // animate background
  { "bgscroll", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // scroll background
  { "palset", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // setup palette
  { "bgwait", 0 }, // wait for background
  { "wait", CF_USE1 | CF_USE2 }, // wait
  { "bwait", 0 }, // wait for b? :)
  { "boxfill", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 }, // fill a rectangle
  { "bgclr", CF_USE1 }, // clear background
  { "setbkcol", CF_USE1 | CF_USE2 | CF_USE3 }, // set background color
  { "msgcol", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // set message color
  { "msgspd", CF_USE1 }, // set message speed
  { "mapinit", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // init a map
  { "mapload", CF_USE1 | CF_USE2 | CF_USE3 }, // load a map
  { "mapdisp", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // display a map
  { "sprent", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // sprite enter ?
  { "setproc", CF_USE1 }, // set procedure ?
  { "sceinit", 0 }, // Sony Computer Entertainment init ?
  { "userctl", CF_USE1 }, // user control
  { "mapattr", CF_USE1 }, // map attribute
  { "mappos", CF_USE1 | CF_USE2 | CF_USE3 }, // set map position
  { "sprpos", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // set sprite position
  { "spranim", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // animate a sprite
  { "sprdir", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // direct a sprite
  { "gameinit", 0 }, // init the game
  { "continit", 0 }, // init continue
  { "sceend", 0 }, // Sony Computer Entertainment end ?
  { "mapscroll", CF_USE1 | CF_USE2 | CF_USE3 }, // scroll a map
  { "sprlmt", CF_USE1 | CF_USE2 | CF_USE3 }, // limit a sprite
  { "sprwalkx", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // walk a sprite by x
  { "allsprdisp", 0 }, // display all sprites
  { "mapwrt", CF_USE1 | CF_USE2 | CF_USE3 }, // write to a map
  { "sprwait", CF_USE1 }, // wait for a sprite
  { "sereq", CF_USE1 | CF_USE2 }, // request a sound effect
  { "sndstop", 0 }, // stop sound
  { "sestop", CF_USE1 }, // stop a sound effect
  { "bgmstop", 0 }, // stop a background music
  { "doornoset", 0 }, // door not set ?
  { "rand", CF_USE1 | CF_USE2 | CF_USE3 }, // generate a random value(s)
  { "btwait", CF_USE1 }, // wait for a bt ? :)
  { "fawait", 0 }, // for for a fa ? :)
  { "sclblock", CF_USE1 | CF_USE2 }, // sequel block ?
  { "evstop", 0 }, // stop an event
  { "sereqpv", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // request a pv sound effect
  { "sereqspr", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // request a sprite sound effect
  { "scereset", 0 }, // Sony Computer Entertainment reset ?
  { "bgsprent", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // background sprite enter
  { "bgsprpos", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // set a background sprite position
  { "bgsprset", CF_USE1 | CF_USE2 }, // set a background sprite
  { "slantset", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 }, // set a slant
  { "slantclr", 0 }, // clear a slant
  { "dummy", 0 }, // just a dummy opcode
  { "spcfunc", CF_USE1 | CF_USE2 }, // call a special func
  { "sepan", CF_USE1 | CF_USE2 }, // pan a sound effect
  { "sevol", CF_USE1 | CF_USE2 }, // volume a sound effect
  { "bgdisptrn", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 }, // display a background pattern ?
  { "debug", CF_USE1 }, // enable/disable debugging mode
  { "trace", CF_USE1 }, // enable/disable trace mode
  { "tmwait", CF_USE1 | CF_USE2 }, // wait for a timer
  { "bgspranim", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // animate a background sprite
  { "abssprent", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 | CF_USE7 | CF_USE8 }, // enter an absolute sprite
  { "nextcom", CF_USE1 }, // next command ?
  { "workclr", 0 }, // clear all memory variables
  { "bgbufclr", CF_USE1 | CF_USE2 }, // clear a background buffer
  { "absbgsprent", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // enter an absolute background sprite
  { "aviplay", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6 }, // play an avi file
  { "avistop", 0 }, // stop an avi file
  { "sprmark", CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 }, // mark a sprite
  { "bgmattr", CF_USE1 | CF_USE2 }, // background m attribute
};

CASSERT(qnumber(Instructions) == ADCVM_last);
