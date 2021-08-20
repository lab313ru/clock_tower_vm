import ida_idp
import idaapi


FILE_OFFSET = 0x100


def accept_file(li, filename):
    li.seek(0)
    tag = li.read(16)

    if tag == b'ADC Object File\x00':
        return {'format': 'ADC Object file', 'processor': 'adcvm'}

    return 0


def load_file(li, neflags, format):
    idaapi.set_processor_type('adcvm', ida_idp.SETPROC_LOADER)

    idaapi.cvar.inf.af = idaapi.AF_CODE | idaapi.AF_USED | idaapi.AF_UNK | idaapi.AF_PROC | idaapi.AF_ANORET | \
        idaapi.AF_MEMFUNC | idaapi.AF_TRFUNC | idaapi.AF_FIXUP | idaapi.AF_JFUNC | idaapi.AF_NULLSUB

    li.seek(FILE_OFFSET)
    data = li.read(li.size() - FILE_OFFSET)

    idaapi.mem2base(data, FILE_OFFSET, FILE_OFFSET)

    idaapi.add_segm(0, FILE_OFFSET, FILE_OFFSET + len(data), 'ROM', 'CODE')

    idaapi.add_entry(FILE_OFFSET, FILE_OFFSET, "start", 1)

    return 1
