"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from monitor import linux_monitor

# TODO include me :-)
class freebsd_monitor(linux_monitor):
    def __init__(self, qemu, filename):
        self.qemu = qemu
        super(linux_monitor, self).__init__(qemu, filename)

    def monitor(self, title):
        _tmp = super(linux_monitor, self).__monitor(title)
        if "Automatic reboot in " in _tmp[1]:
            self.qemu.repair_image()
        return _tmp[0]