# pylibemu.pyx
#
# Copyright(c) 2011 Angelo Dell'Aera <buffer@antifork.org>
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

cimport pylibemu

# User hooks
cdef uint32_t URLDownloadToFile(c_emu_env *env, c_emu_env_hook *hook...):
    cdef va_list args
    cdef void   *pCaller
    cdef char   *szURL
    cdef char   *szFileName
    cdef int     dwReserved
    cdef void   *lpfnCB
    cdef void   *p

    va_start(args, <void*>hook)
    pCaller    = <void *>va_arg(args, void_ptr_type)
    szURL      = <char *>va_arg(args, char_ptr_type)
    szFileName = <char *>va_arg(args, char_ptr_type)
    dwReserved = <int>va_arg(args, int_type)
    lpfnCB     = <void *>va_arg(args, void_ptr_type)
    va_end(args) 
    
    print "Download %s -> %s\n" % (szURL, szFileName)
    return 0

cdef class Emulator:
    cdef c_emu *_emu

    def __cinit__(self):
        self.new()

    def __dealloc__(self):
        self.free()

    def free(self):
        if self._emu is not NULL:
            emu_free(self._emu)
            self._emu = NULL

    def new(self):
        self._emu = emu_new()

    def shellcode_getpc_test(self, shellcode):
        cdef char    *buffer
        cdef int32_t  offset = -1

        if self._emu is NULL:
            self.alloc()

        buffer = <char *>shellcode
        sclen  = len(bytes(shellcode))

        if buffer is NULL:
            return offset

        offset = emu_shellcode_test(self._emu, <uint8_t *>buffer, sclen)
        return offset

    def prepare(self, shellcode, offset):
        cdef c_emu_cpu      *_cpu
        cdef c_emu_memory   *_mem
        cdef char           *scode
        cdef int            j, static_offset

        if self._emu is NULL:
            self.new()

        _cpu = emu_cpu_get(self._emu)
        _mem = emu_memory_get(self._emu)

        for j in range(8):
            emu_cpu_reg32_set(_cpu, <c_emu_reg32>j, 0)

        emu_memory_write_dword(_mem, 0xef787c3c, 4711)
        emu_memory_write_dword(_mem, 0x0       , 4711)
        emu_memory_write_dword(_mem, 0x00416f9a, 4711)
        emu_memory_write_dword(_mem, 0x0044fcf7, 4711)
        emu_memory_write_dword(_mem, 0x00001265, 4711)
        emu_memory_write_dword(_mem, 0x00002583, 4711)
        emu_memory_write_dword(_mem, 0x00e000de, 4711)
        emu_memory_write_dword(_mem, 0x01001265, 4711)
        emu_memory_write_dword(_mem, 0x8a000066, 4711)

        # Set the flags 
        emu_cpu_eflags_set(_cpu, 0)

        # Write the code to the offset 
        scode = <char *>shellcode
        static_offset = 0x417000
        emu_memory_write_block(_mem, static_offset, scode, len(shellcode))

        # Set eip to the code 
        emu_cpu_eip_set(emu_cpu_get(self._emu), static_offset + offset)

        emu_memory_write_block(_mem, 0x0012fe98, scode, len(shellcode))
        emu_cpu_reg32_set(emu_cpu_get(self._emu), esp, 0x0012fe98)

    cpdef int test(self, steps = 1000000):
        cdef c_emu_cpu      *_cpu
        cdef c_emu_memory   *_mem
        cdef c_emu_env      *_env
        cdef uint32_t       eipsave
        cdef int            j
        cdef int            ret
        cdef c_emu_env_hook *hook

        if self._emu is NULL:
            return -1

        _cpu = emu_cpu_get(self._emu)
        _mem = emu_memory_get(self._emu)
        _env = emu_env_new(self._emu)
        if _env is NULL:
            print emu_strerror(self._emu)
            return -1

        _env.profile = emu_profile_new()

        # IAT for sqlslammer
        emu_memory_write_dword(_mem, 0x42ae1018, 0x7c801d77)
        emu_memory_write_dword(_mem, 0x42ae1010, 0x7c80ada0)
        emu_memory_write_dword(_mem, 0x7c80ada0, 0x51ec8b55)
        emu_memory_write_byte(_mem,  0x7c814eeb, 0xc3)

        emu_env_w32_load_dll(_env.env.win, "urlmon.dll")
        emu_env_w32_export_hook(_env, "URLDownloadToFileA", URLDownloadToFile,  NULL)

        eipsave = 0
        ret     = 0

        for j in range(steps):
            if not _cpu.repeat_current_instr:
                eipsave = emu_cpu_eip_get(emu_cpu_get(self._emu))

            hook = emu_env_w32_eip_check(_env)
            if hook is not NULL:
                if hook.hook.win.fnname is NULL:
                    print "Unhooked call to %s\n" % (hook.hook.win.fnname, )
                    break
            else:
                ret = emu_cpu_parse(emu_cpu_get(self._emu))
                hook = NULL
                if ret != -1:
                    hook = emu_env_linux_syscall_check(_env)
                    if hook is NULL:
                        ret = emu_cpu_step(emu_cpu_get(self._emu))
                    else:
                        print "Error"

                if ret == -1:
                    break

        emu_profile_debug(_env.profile)
        return 0


