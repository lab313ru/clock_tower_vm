import sys
import struct
from typing import Callable


def check_ado(data):
    return data[:16] == b'ADC Object File\x00'


def read_dword(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


class AdoVm:
    VM_BLOCKS = 5

    def __init__(self, ado_data, adt_data):
        self.OPCODES = {
            0xFF00: ('VM_RET', self.vm_empty),
            0xFF01: ('VM_1', None),
            0xFF02: ('VM_2', None),
            0xFF03: ('VM_3', None),
            0xFF04: ('VM_4', None),
            0xFF05: ('VM_5', None),
            0xFF06: ('VM_6', None),
            0xFF07: ('VM_7', None),
            0xFF08: ('VM_8', None),
            0xFF09: ('VM_9', None),
            0xFF0A: ('VM_DIV', self.vm_div),
            0xFF0B: ('VM_MUL', self.vm_mul),
            0xFF0C: ('VM_SUB', self.vm_sub),
            0xFF0D: ('VM_ADD', self.vm_add),
            0xFF0E: ('VM_DEC', self.vm_dec),
            0xFF0F: ('VM_INC', self.vm_inc),
            0xFF10: ('VM_MOV', self.vm_mov),
            0xFF11: ('VM_EQU', None),
            0xFF12: ('VM_NEQ', None),
            0xFF13: ('VM_GRE', None),
            0xFF14: ('VM_LWR', None),
            0xFF15: ('VM_GEQ', None),
            0xFF16: ('VM_LEQ', None),
            0xFF17: ('VM_17', None),
            0xFF18: ('VM_18', None),
            0xFF19: ('VM_19', None),
            0xFF1A: ('VM_1A', None),
            0xFF1B: ('VM_1B', None),
            0xFF1C: ('VM_1C', None),
            0xFF1D: ('VM_1D', None),
            0xFF1E: ('VM_1E', None),
            0xFF1F: ('VM_1F', None),
            0xFF20: ('VM_ALLEND', self.vm_allend),
            0xFF21: ('VM_JMP', self.vm_jmp_call),
            0xFF22: ('VM_CALL', self.vm_jmp_call),
            0xFF23: ('VM_EVDEF', self.vm_evdef),
            0xFF24: ('VM_STRANGE1', None),
            0xFF25: ('VM_STRANGE2', None),
            0xFF26: ('VM_STRANGE3', None),
            0xFF27: ('VM_STRANGE4', None),
            0xFF28: ('VM_END', self.vm_end),
            0xFF29: ('VM_IF', self.vm_if_while),
            0xFF2A: ('VM_WHILE', self.vm_if_while),
            0xFF2B: ('VM_NOP', self.vm_nop),
            0xFF2C: ('VM_BREAK', None),
            0xFF2D: ('VM_ENDIF', self.vm_endif),
            0xFF2E: ('VM_ENDWHILE', self.vm_endwhile),
            0xFF2F: ('VM_ELSE', self.vm_else),
            0xFF30: ('VM_MSGINIT', self.vm_msginit),
            0xFF31: ('VM_MSGTYPE', None),
            0xFF32: ('VM_MSGATTR', self.vm_msgattr),
            0xFF33: ('VM_MSGOUT', self.vm_msgout),
            0xFF34: ('VM_SETMARK', self.vm_setmark),
            0xFF35: ('VM_SETWAIT', None),
            0xFF36: ('VM_MSGWAIT', self.vm_msgwait),
            0xFF37: ('VM_EVSTART', self.vm_evstart),
            0xFF38: ('VM_BGFILEDISP', None),
            0xFF39: ('VM_BGLOAD', self.vm_bgload),
            0xFF3A: ('VM_PALLOAD', self.vm_palload),
            0xFF3B: ('VM_BGMREQ', self.vm_bgmreq),
            0xFF3C: ('VM_SPRCLR', self.vm_sprclr),
            0xFF3D: ('VM_ABSOBJANIM', None),
            0xFF3E: ('VM_OBJANIM', None),
            0xFF3F: ('VM_ALLSPRCLR', self.vm_allsprclr),
            0xFF40: ('VM_MSGCLR', self.vm_msgclr),
            0xFF41: ('VM_SCREENCLR', self.vm_screenclr),
            0xFF42: ('VM_SCREENON', self.vm_screenon),
            0xFF43: ('VM_SCREENOFF', self.vm_screenoff),
            0xFF44: ('VM_SCREENIN', None),
            0xFF45: ('VM_SCREENOUT', None),
            0xFF46: ('VM_BGDISP', self.vm_bgdisp),
            0xFF47: ('VM_BGANIM', self.vm_bganim),
            0xFF48: ('VM_BGSCROLL', self.vm_bgscroll),
            0xFF49: ('VM_PALSET', self.vm_palset),
            0xFF4A: ('VM_BGWAIT', self.vm_bgwait),
            0xFF4B: ('VM_WAIT', self.vm_wait),
            0xFF4C: ('VM_BWAIT', None),
            0xFF4D: ('VM_BOXFILL', self.vm_boxfill),
            0xFF4E: ('VM_BGCLR', None),
            0xFF4F: ('VM_SETBKCOL', self.vm_setbkcol),
            0xFF50: ('VM_MSGCOL', None),
            0xFF51: ('VM_MSGSPD', self.vm_msgspd),
            0xFF52: ('VM_MAPINIT', self.vm_mapinit),
            0xFF53: ('VM_MAPLOAD', self.vm_mapload),
            0xFF54: ('VM_MAPDISP', None),
            0xFF55: ('VM_SPRENT', self.vm_sprent_abssprent),
            0xFF56: ('VM_SETPROC', self.vm_setproc),
            0xFF57: ('VM_SCEINIT', self.vm_sceinit),
            0xFF58: ('VM_USERCTL', self.vm_userctl),
            0xFF59: ('VM_MAPATTR', self.vm_mapattr),
            0xFF5A: ('VM_MAPPOS', self.vm_mappos),
            0xFF5B: ('VM_SPRPOS', self.vm_sprpos),
            0xFF5C: ('VM_SPRANIM', self.vm_spranim),
            0xFF5D: ('VM_SPRDIR', self.vm_sprdir),
            0xFF5E: ('VM_GAMEINIT', self.vm_gameinit),
            0xFF5F: ('VM_CONTINIT', self.vm_continit),
            0xFF60: ('VM_SCEEND', self.vm_sceend),
            0xFF61: ('VM_MAPSCROLL', self.vm_mapscroll),
            0xFF62: ('VM_SPRLMT', self.vm_sprlmt),
            0xFF63: ('VM_SPRWALKX', self.vm_sprwalkx),
            0xFF64: ('VM_ALLSPRDISP', None),
            0xFF65: ('VM_MAPWRT', None),
            0xFF66: ('VM_SPRWAIT', self.vm_sprwait),
            0xFF67: ('VM_SEREQ', self.vm_sereq),
            0xFF68: ('VM_SNDSTOP', self.vm_sndstop),
            0xFF69: ('VM_SESTOP', self.vm_sestop),
            0xFF6A: ('VM_BGMSTOP', self.vm_bgmstop),
            0xFF6B: ('VM_DOORNOSET', self.vm_doornoset),
            0xFF6C: ('VM_RAND', self.vm_rand),
            0xFF6D: ('VM_BTWAIT', self.vm_btwait),
            0xFF6E: ('VM_FAWAIT', self.vm_fawait),
            0xFF6F: ('VM_SCLBLOCK', self.vm_sclblock),
            0xFF70: ('VM_EVSTOP', None),
            0xFF71: ('VM_SEREQPV', self.vm_sereqpv_sereqspr),
            0xFF72: ('VM_SEREQSPR', self.vm_sereqpv_sereqspr),
            0xFF73: ('VM_SCERESET', self.vm_scereset),
            0xFF74: ('VM_BGSPRENT', self.vm_bgsprent_absbgsprent),
            0xFF75: ('VM_BGSPRPOS', None),
            0xFF76: ('VM_BGSPRSET', None),
            0xFF77: ('VM_SLANTSET', self.vm_slantset),
            0xFF78: ('VM_SLANTCLR', self.vm_slantclr),
            0xFF79: ('VM_DUMMY', None),
            0xFF7A: ('VM_SPCFUNC', self.vm_spcfunc),
            0xFF7B: ('VM_SEPAN', self.vm_sepan),
            0xFF7C: ('VM_SEVOL', self.vm_sevol),
            0xFF7D: ('VM_BGDISPTRN', self.vm_bgdisptrn),
            0xFF7E: ('VM_DEBUG', None),
            0xFF7F: ('VM_TRACE', None),
            0xFF80: ('VM_TMWAIT', self.vm_tmwait),
            0xFF81: ('VM_BGSPRANIM', self.vm_bgspranim),
            0xFF82: ('VM_ABSSPRENT', self.vm_sprent_abssprent),
            0xFF83: ('VM_NEXTCOM', self.vm_nextcom),
            0xFF84: ('VM_WORKCLR', self.vm_workclr),
            0xFF85: ('VM_BGBUFCLR', self.vm_bgbufclr),
            0xFF86: ('VM_ABSBGSPRENT', self.vm_bgsprent_absbgsprent),
            0xFF87: ('VM_AVIPLAY', self.vm_aviplay),
            0xFF88: ('VM_AVISTOP', self.vm_avistop),
            0xFF89: ('VM_SPRMARK', self.vm_sprmark),
            0xFF8A: ('VM_BGMATTR', self.vm_bgmattr),
            0xFFFF: ('VM_BAD_OPC', None)
        }

        self.SET_OPCODES = ['VM_DIV', 'VM_MUL', 'VM_SUB', 'VM_ADD', 'VM_DEC', 'VM_INC', 'VM_MOV']
        self.CMP_OPCODES = ['VM_EQU', 'VM_NEQ', 'VM_GRE', 'VM_LWR', 'VM_GEQ', 'VM_LEQ']

        self.OPCODE_DATA_SIZE = [  # starting 0xFF00
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 1, 3, 0, 0, 0, 0,
            0, 1, 1, 0, 0, 0, 0, 0, 5, 2,
            8, 2, 0, 1, 0, 2, 2, 1, 1, 1,
            1, 6, 6, 0, 0, 0, 0, 0, 1, 1,
            6, 7, 5, 5, 0, 2, 1, 7, 1, 3,
            6, 1, 6, 1, 6, 8, 1, 0, 1, 1,
            3, 4, 4, 5, 0, 0, 0, 3, 3, 5,
            0, 3, 1, 1, 0, 0, 0, 0, 2, 1,
            0, 0, 0, 3, 3, 0, 6, 4, 2, 4,
            0, 6, 1, 1, 1, 7, 1, 1, 2, 9,
            8, 1, 0, 2, 6, 5, 0, 5, 2, 0
        ]

        self.ado_data = ado_data
        self.block_offsets = list()
        self.block_indices = list()
        self.block_index = 0

        for i in range(AdoVm.VM_BLOCKS):
            self.block_offsets.append(0x100)

        for i in range(AdoVm.VM_BLOCKS):
            self.block_indices.append(0)

        self.refs = list()
        self.__parse_adt(adt_data)

        self.if_while_id = 0

        self.__last_opcode = 0xFF00

    @staticmethod
    def read_word(data, offset):
        return struct.unpack_from('<H', data, offset)[0]

    def set_current_offset(self, offset):
        self.block_offsets[self.block_index] = offset

    def set_current_index(self, index):
        self.block_indices[self.block_index] = index

    def goto_next_word(self):
        index = self.get_current_index()
        offset = self.get_current_offset() + 2

        if offset & 0x8000:
            index += 1
            offset = 0

        self.set_current_offset(offset)
        self.set_current_index(index)

    def get_current_index(self):
        return self.block_indices[self.block_index]

    def get_current_offset(self):
        return self.block_offsets[self.block_index]

    def __parse_adt(self, data):
        count = len(data) // 4

        for i in range(count):
            offset = AdoVm.read_word(data, i * 4 + 0)
            index = AdoVm.read_word(data, i * 4 + 2)
            self.refs.append((offset, index))

    def get_var_with_inc(self):
        token = self.read_word_no_inc()
        var_type = token >> 12
        var_index = token & 0x3FF

        name = '0x%02X' % token

        if (0xF000 <= token <= 0xF1FF) or \
           (0xE000 <= token <= 0xE1FF) or \
           (0xD000 <= token <= 0xD1FF) or \
           (0xC000 <= token <= 0xC1FF):
            name = self.__get_var_name(var_type, var_index)

        self.goto_next_word()
        return name

    def read_word_no_inc(self):
        offset = self.convert_io_to_addr(self.get_current_index(), self.get_current_offset())
        word = AdoVm.read_word(self.ado_data, offset)
        return word

    def read_word_with_inc(self):
        word = self.read_word_no_inc()
        self.goto_next_word()
        return word

    def parse(self):
        while True:
            curr = AdoVm.convert_io_to_addr(self.get_current_index(), self.get_current_offset())
            print('%05X: ' % curr, end='')

            opcode = self.read_word_no_inc()
            self.__last_opcode = opcode

            if opcode not in self.OPCODES:
                raise Exception('Wrong opcode % 0x04X' % opcode)

            item: tuple[str, Callable[[], None]] = self.OPCODES[opcode]

            print('\t%s ' % item[0], end='')

            if item[1] is not None:
                item[1]()
            else:
                raise Exception('No handler specified!')

            if item[0] == 'VM_ALLEND':
                break

    def read_reference(self, index):
        return self.refs[index]

    @staticmethod
    def convert_io_to_addr(index, offset):
        return (index * 0x8000) | offset

    def vm_allend(self):
        self.goto_next_word()
        print()

    def vm_jmp_call(self):
        self.goto_next_word()

        ref = self.read_word_with_inc()

        try:
            adt_off, adt_idx = self.read_reference(ref)
        except Exception:
            print('Unkn_target_0x%03X' % (ref & 0xFFF))
            return

        dest = AdoVm.convert_io_to_addr(adt_idx, adt_off) + 2

        # print('[0x%04X] -> (index = 0x%X, offset = 0x%X) => FUNC_%05X' % (ref, adt_idx, adt_off, dest))
        print('FUNC_%05X' % dest)

    def vm_evdef(self):
        self.goto_next_word()

        v1 = self.read_word_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()

        print('(%02X, %s, %s)' % (v1, v2, v3))

    def get_var_dest(self, token):
        var_type = token >> 12
        var_index = token & 0x3FF

        name = AdoVm.__get_var_name(var_type, var_index)
        return name

    @staticmethod
    def __get_var_name(var_type, var_index):
        if var_type == 0xC:
            return 'varC_%d' % var_index
        elif var_type == 0xE:
            return 'varE_%d' % var_index
        elif var_type == 0xF:
            return 'varF_%d' % var_index
        else:
            return 'varD_%d' % var_index

    def __get_opcode_name(self, opcode):
        if opcode in self.OPCODES:
            return self.OPCODES[opcode][0]
        return None

    @staticmethod
    def __word_to_bytes(word):
        return struct.pack('<H', word)

    def read_string(self):
        res = b''

        while True:
            w = self.read_word_with_inc()

            if w == 0x0000:
                break

            res += AdoVm.__word_to_bytes(w)

        return res.rstrip(b'\x00').decode()

    def read_msg_string(self):
        res = b''

        while True:
            w = self.read_word_with_inc()
            name = self.__get_opcode_name(w)

            if name in ['VM_ALLEND', 'VM_END', 'VM_MSGWAIT']:
                break

            res += AdoVm.__word_to_bytes(w)

        return res.rstrip(b'\x00').decode('shift-jis')

    def vm_palload(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        p = self.read_string()

        print('(%s, "%s")' % (v, p))

    def vm_bgmreq(self):
        self.goto_next_word()

        val = self.read_word_with_inc()
        p = self.read_string()

        print('(%d, "%s")' % (val, p))

    def vm_sprclr(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_msgwait(self):
        self.goto_next_word()
        print()

    def vm_evstart(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        print('(%s, %s)' % (v1, v2))

    def vm_bgload(self):
        self.goto_next_word()
        val = self.read_word_with_inc()
        p = self.read_string()

        print('(%d, "%s")' % (val, p))

    def vm_sprwait(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_sereq(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        p = self.read_string()

        print('%s, "%s"' % (v, p))

    def vm_sndstop(self):
        self.goto_next_word()
        print()

    def vm_sestop(self):
        self.goto_next_word()

        p = self.read_string()
        print('("%s")' % p)

    def vm_bgmstop(self):
        self.goto_next_word()
        print()

    def vm_doornoset(self):
        self.goto_next_word()
        print()

    def vm_rand(self):
        self.goto_next_word()

        v_min = self.read_word_with_inc()
        v_max = self.read_word_with_inc()

        v = self.read_word_with_inc()
        name = self.get_var_dest(v)

        print('(%s = random(min=%d, max=%d))' % (name, v_min, v_max))

    def vm_btwait(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_fawait(self):
        self.goto_next_word()
        print()

    def vm_sclblock(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v1 = int(v1, 16)

        vals1 = list()
        for i in range(v1):
            vals1.append(self.get_var_with_inc())

        v2 = self.get_var_with_inc()
        v2 = int(v2, 16)

        vals2 = list()
        for i in range(v2):
            vals2.append(self.get_var_with_inc())

        print('\n\t(', end='')
        print(', '.join(vals1), end='')
        print('), ', end='')

        print('\n\t(', end='')
        print(', '.join(vals2), end='')
        print(')')

    def vm_allsprclr(self):
        self.goto_next_word()
        print()

    def vm_msgclr(self):
        self.goto_next_word()
        print()

    def vm_screenclr(self):
        self.goto_next_word()
        print()

    def vm_screenon(self):
        self.goto_next_word()
        print()

    def vm_screenoff(self):
        self.goto_next_word()
        print()

    def vm_bgdisp(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        v3 = self.get_var_with_inc()

        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5, v6))

    def vm_bganim(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()
        v7 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s, %s)', (v1, v2, v3, v4, v5, v6, v7))

    def vm_div(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var1 = self.read_word_with_inc()

        name1 = self.get_var_dest(var1)
        name2 = self.get_var_with_inc()

        print('(%s /= %s)' % (name1, name2))

    def vm_mul(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var1 = self.read_word_with_inc()

        name1 = self.get_var_dest(var1)
        name2 = self.get_var_with_inc()

        print('(%s *= %s)' % (name1, name2))

    def vm_sub(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var1 = self.read_word_with_inc()

        name1 = self.get_var_dest(var1)
        name2 = self.get_var_with_inc()

        print('(%s -= %s)' % (name1, name2))

    def vm_add(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var1 = self.read_word_with_inc()

        name1 = self.get_var_dest(var1)
        name2 = self.get_var_with_inc()

        print('(%s += %s)' % (name1, name2))

    def vm_dec(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var = self.read_word_with_inc()
        name = self.get_var_dest(var)

        print('(%s -= 1)' % name)

    def vm_inc(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var = self.read_word_with_inc()
        name = self.get_var_dest(var)

        print('(%s += 1)' % name)

    def vm_mov(self):
        self.goto_next_word()

        opcode_name = self.__get_opcode_name(self.__last_opcode)
        if opcode_name not in self.SET_OPCODES:
            print()
            return

        var1 = self.read_word_with_inc()

        name1 = self.get_var_dest(var1)
        name2 = self.get_var_with_inc()

        print('(%s = %s)' % (name1, name2))

    def _vm_compare(self, multi):
        pairs_read = 0
        pairs_compared = 0

        conditions = list()

        while True:
            opcode = self.read_word_with_inc()
            opcode_name = self.__get_opcode_name(opcode)

            if opcode_name not in self.CMP_OPCODES:
                break

            var1_token = self.read_word_with_inc()

            name1 = self.get_var_dest(var1_token)
            name2 = self.get_var_with_inc()

            pairs_read += 1

            if opcode_name == 'VM_EQU':
                conditions.append('(%s == %s)' % (name1, name2))
            elif opcode_name == 'VM_NEQ':
                conditions.append('(%s != %s)' % (name1, name2))
            elif opcode_name == 'VM_GRE':
                conditions.append('(%s > %s)' % (name1, name2))
            elif opcode_name == 'VM_LWR':
                conditions.append('(%s < %s)' % (name1, name2))
            elif opcode_name == 'VM_GEQ':
                conditions.append('(%s >= %s)' % (name1, name2))
            elif opcode_name == 'VM_LEQ':
                conditions.append('(%s <= %s)' % (name1, name2))

            pairs_compared += 1

        print(' and '.join(conditions))

        if multi and (pairs_compared != pairs_read):
            return False

        return pairs_compared != 0

    def vm_end(self):
        self.goto_next_word()
        print()

    def vm_if_while(self):
        self.goto_next_word()
        self.if_while_id = self.read_word_with_inc()
        print('(%d) ' % self.if_while_id, end='')

        multi = self.read_word_with_inc()

        res = self._vm_compare(multi)

        if res:
            return

        # while True:
        #     next_opcode = self.read_word_with_inc()
        #     next_opcode_name = self.__get_opcode_name(next_opcode)
        #
        #     new_val = self.read_word_with_inc()
        #     if next_opcode_name in ['VM_ENDIF', 'VM_ELSE'] and self.if_while_id == new_val:
        #         break

    def vm_empty(self):
        self.goto_next_word()
        print()

    def vm_endif(self):
        self.goto_next_word()
        val = self.read_word_with_inc()
        print('(%d)' % val)

    def vm_endwhile(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_else(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_bgscroll(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()

        v5 = self.get_var_with_inc()
        v5 = int(v5, 16)

        print('(%s, %s, %s, %s, frames=%s)' % (v1, v2, v3, v4, v5))

    def vm_palset(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5))

    def vm_bgwait(self):
        self.goto_next_word()
        print()

    def vm_wait(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        print('(%s, %s)' % (v1, v2))

    def vm_boxfill(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()
        v7 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5, v6, v7))

    def vm_nop(self):
        self.goto_next_word()
        print()

    def __read_and_print_multiple_params(self):
        count = self.OPCODE_DATA_SIZE[self.__last_opcode - 0xFF00]

        print('(', end='')

        vals = list()
        for i in range(count):
            v = self.get_var_with_inc()
            vals.append(v)

        print(', '.join(vals), end='')
        print(')')

    def vm_msgattr(self):
        self.goto_next_word()
        self.__read_and_print_multiple_params()

    def vm_msgout(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        p = self.read_msg_string()

        print('(%s, %s, "%s")' % (v1, v2, p))

    def vm_setmark(self):
        self.goto_next_word()

        print('(')
        print('\t', end='')

        vals = list()
        while True:
            v = self.get_var_with_inc()

            try:
                opcode = int(v, 16)
            except Exception:
                opcode = 0

            name = self.__get_opcode_name(opcode)

            if name == 'VM_END':
                break

            v1 = self.get_var_with_inc()
            v2 = self.get_var_with_inc()
            v3 = self.get_var_with_inc()
            v4 = self.read_word_with_inc()

            vals.append('(%s, %s, %s, %s)' % (v1, v2, v3, v4))

        print(', \n\t'.join(vals), end='')
        print('\n)')

    def vm_msginit(self):
        self.goto_next_word()
        self.__read_and_print_multiple_params()

    def vm_msgspd(self):
        self.goto_next_word()
        self.__read_and_print_multiple_params()

    def vm_mapinit(self):
        self.goto_next_word()
        self.__read_and_print_multiple_params()

    def vm_mapload(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        str1 = self.read_string()
        str2 = self.read_string()

        print('(%s) ("%s", "%s")' % (v, str1, str2))

    def vm_bgspranim(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()
        v7 = self.get_var_with_inc()
        v8 = self.get_var_with_inc()
        v9 = self.get_var_with_inc()

        print('%s, %s, %s, %s, %s, %s, %s, %s, %s' % (v1, v2, v3, v4, v5, v6, v7, v8, v9))

    def vm_sprent_abssprent(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()
        v7 = self.get_var_with_inc()
        v8 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5, v6, v7, v8))

    def vm_setproc(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_sceinit(self):
        self.goto_next_word()
        print()

    def vm_userctl(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_mapattr(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        print('(%s)' % v)

    def vm_mappos(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()

        print('(%s, %s, %s)' % (v1, v2, v3))

    def vm_sprpos(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()

        print('(%s, %s, %s, %s)' % (v1, v2, v3, v4))

    def vm_spranim(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()

        print('(%s, %s, %s, %s)' % (v1, v2, v3, v4))

    def vm_sprdir(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5))

    def vm_gameinit(self):
        self.goto_next_word()
        print()

    def vm_continit(self):
        self.goto_next_word()
        print()

    def vm_sceend(self):
        self.goto_next_word()
        print()

    def vm_mapscroll(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()

        print('(%s, %s, %s)' % (v1, v2, v3))

    def vm_sprlmt(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()

        print('(%s, %s, %s)' % (v1, v2, v3))

    def vm_sprwalkx(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5))

    def vm_setbkcol(self):
        self.goto_next_word()
        self.__read_and_print_multiple_params()

    def vm_sereqpv_sereqspr(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        p = self.read_string()

        print('(%s, %s, %s, "%s")' % (v1, v2, v3, p))

    def vm_scereset(self):
        self.goto_next_word()
        print()

    def vm_spcfunc(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        count = int(v2, 16)

        vals = list()
        for i in range(count):
            v = self.get_var_with_inc()
            vals.append(v)

        print('(%s) (' % v1, end='')
        print(', '.join(vals), end='')
        print(')')

    def vm_sepan(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        p = self.read_string()
        print('(%s, "%s")' % (v, p))

    def vm_sevol(self):
        self.goto_next_word()

        v = self.get_var_with_inc()
        p = self.read_string()
        print('(%s, "%s")' % (v, p))

    def vm_bgdisptrn(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()
        v7 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5, v6, v7))

    def vm_tmwait(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        print('(%s, %s)' % (v1, v2))

    def vm_nextcom(self):
        self.goto_next_word()

        val = self.read_word_with_inc()
        print('(%d)' % val)

    def vm_workclr(self):
        self.goto_next_word()
        print()

    def vm_bgbufclr(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        print('(%s, %s)' % (v1, v2))

    def vm_bgsprent_absbgsprent(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()
        v6 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5, v6))

    def vm_slantset(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()

        print('(%s, %s, %s, %s)' % (v1, v2, v3, v4))

    def vm_slantclr(self):
        self.goto_next_word()
        print()

    def vm_aviplay(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()

        p = self.read_string()

        print('(%s, %s, %s, %s, %s, "%s")' % (v1, v2, v3, v4, v5, p))

    def vm_avistop(self):
        self.goto_next_word()
        print()

    def vm_sprmark(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()
        v3 = self.get_var_with_inc()
        v4 = self.get_var_with_inc()
        v5 = self.get_var_with_inc()

        print('(%s, %s, %s, %s, %s)' % (v1, v2, v3, v4, v5))

    def vm_bgmattr(self):
        self.goto_next_word()

        v1 = self.get_var_with_inc()
        v2 = self.get_var_with_inc()

        print('(%s, %s)' % (v1, v2))


def main(path_ado, path_adt):
    f = open(path_ado, 'rb')
    ado_data = f.read()
    f.close()

    f = open(path_adt, 'rb')
    adt_data = f.read()
    f.close()

    if not check_ado(ado_data):
        return

    vm = AdoVm(ado_data, adt_data)
    vm.parse()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('No args specified: ADO_PATH ADT_PATH.')
        sys.exit(-1)

    main(sys.argv[1], sys.argv[2])
