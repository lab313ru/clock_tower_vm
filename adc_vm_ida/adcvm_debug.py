import struct

import requests
import ida_kernwin
import idaapi
from PyQt5 import QtWidgets
from PyQt5.QtCore import QTimer, Qt


class AdcVmDebugPluginFormClass(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.timer = None
        self.parent = None
        self.edit_pc = None
        self.vars_d = None
        self.vars_f = None
        self.vars_e = None
        self.vars_c = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.timer = self.create_timer()
        self.PopulateForm()
        self.start_timer()

    def create_table(self, base, count):
        tbl = QtWidgets.QTableWidget(count, 2)
        tbl.verticalHeader().setVisible(False)

        for i in range(count):
            name = QtWidgets.QTableWidgetItem('%03X' % (base * 0x1000 + i * 2))
            name.setFlags(name.flags() & ~Qt.ItemIsEditable)

            val = QtWidgets.QTableWidgetItem('0000')
            tbl.setItem(i, 0, name)
            tbl.setItem(i, 1, val)

        head_name = QtWidgets.QTableWidgetItem('Name')
        head_value = QtWidgets.QTableWidgetItem('Value')
        tbl.setHorizontalHeaderItem(0, head_name)
        tbl.setHorizontalHeaderItem(1, head_value)

        return tbl

    def PopulateForm(self):
        layout = QtWidgets.QGridLayout()

        lb_pc = QtWidgets.QLabel('PC')
        self.edit_pc = QtWidgets.QLineEdit('0x000000')
        btn_pause_run = QtWidgets.QPushButton('Pause/Run')
        btn_step_into = QtWidgets.QPushButton('Step Into')
        btn_step_over = QtWidgets.QPushButton('Step Over')
        btn_add_bp = QtWidgets.QPushButton('Add BP')
        btn_del_bp = QtWidgets.QPushButton('Del BP')

        line1 = QtWidgets.QGridLayout()
        line1.addWidget(lb_pc, 0, 0)
        line1.addWidget(self.edit_pc, 0, 1)
        line1.addWidget(btn_pause_run, 0, 2)
        line1.addWidget(btn_step_into, 0, 3)
        line1.addWidget(btn_step_over, 0, 4)
        line1.addWidget(btn_add_bp, 0, 5)
        line1.addWidget(btn_del_bp, 0, 6)

        self.vars_d = self.create_table(0x0D, 0x200)
        self.vars_f = self.create_table(0x0F, 0x40)
        self.vars_e = self.create_table(0x0E, 0x40)
        self.vars_c = self.create_table(0x0C, 0x80)

        splitter = QtWidgets.QSplitter(Qt.Horizontal)
        splitter.addWidget(self.vars_d)
        splitter.addWidget(self.vars_f)
        splitter.addWidget(self.vars_e)
        splitter.addWidget(self.vars_c)

        layout.addLayout(line1, 0, 0)
        layout.addWidget(splitter, 1, 0)

        self.parent.setLayout(layout)

    def start_timer(self):
        self.timer.start(100)

    def __get_dword(self, data, offset):
        return struct.unpack_from('<I', data, offset)[0], offset + 4

    def __get_vars_data(self, data, offset, count):
        fmt = '<%dH' % count
        return struct.unpack_from(fmt, data, offset), offset + count * 2

    def __set_table_data(self, tbl, data):
        for i, ditem in enumerate(data):
            item = tbl.item(i, 1)
            item.setText('%04X' % ditem)
            tbl.setItem(i, 1, item)

    def get_state(self):
        r = requests.get('http://127.0.0.1:8080/api/v1/vm/state')

        off = 0

        pc, off = self.__get_dword(r.content, off)
        data_d, off = self.__get_vars_data(r.content, off, 0x200)
        data_f, off = self.__get_vars_data(r.content, off, 0x40)
        data_e, off = self.__get_vars_data(r.content, off, 0x40)
        data_c, off = self.__get_vars_data(r.content, off, 0x80)

        self.edit_pc.setText('%06X' % pc)
        ida_kernwin.jumpto(pc)

        self.__set_table_data(self.vars_d, data_d)
        self.__set_table_data(self.vars_f, data_f)
        self.__set_table_data(self.vars_e, data_e)
        self.__set_table_data(self.vars_c, data_c)

    def create_timer(self):
        timer = QTimer(self.parent)
        timer.timeout.connect(self.get_state)
        return timer


class AdcvmDebugPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Clock Tower VM debugger"
    help = ""
    wanted_name = "ADC VM Debugger Plugin"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        plg = AdcVmDebugPluginFormClass()
        plg.Show('ADC VM Debugger')

    def term(self):
        pass


def PLUGIN_ENTRY():
    return AdcvmDebugPlugin()
