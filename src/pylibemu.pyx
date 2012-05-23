#
# pylibemu.pyx
#
# Copyright(c) 2011-2012 Angelo Dell'Aera <buffer@antifork.org>
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

import sys
import socket
import urllib2
import hashlib
import logging

logging.basicConfig(format = '%(asctime)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]')

# export register numbers
class EMU_REGS:
    eax = 0
    ecx = 1
    edx = 2
    ebx = 3
    esp = 4
    ebp = 5
    esi = 6
    edi = 7

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

    logging.warning("Downloading %s (%s)" % (szURL, szFileName))
    try:
        url = urllib2.urlopen(szURL, timeout = 10)
        content = url.read()
    except:
        logging.warning("Error while downloading from %s" % (szURL, ))
        return 0x800C0008 # INET_E_DOWNLOAD_FAILURE

    m = hashlib.md5(content)
    with open(str(m.hexdigest()), mode = 'wb') as fd:
        fd.write(content)

    return 0


DEF OUTPUT_SIZE = 1024 * 1024 # 1MB
DEF SEP_SIZE    = 16
DEF S_SIZE      = 4096


cdef class EmuProfile:
    cdef char *sep[SEP_SIZE]
    cdef char *output
    cdef char *t
    cdef char *s
    cdef bint truncate
    cdef int  output_size

    def __cinit__(self, size_t output_size):
        self.truncate    = False
        self.output_size = output_size

        self.output = <char *>malloc(output_size)
        self.s      = <char *>malloc(S_SIZE)

        self.check_memalloc()
        memset(self.output, 0, output_size)
        memset(self.s     , 0, S_SIZE)
        self.build_sep()

    cdef check_memalloc(self):
        if self.output is NULL or self.s is NULL:
            logging.warning("Memory allocation error")
            sys._exit(-1)

    cdef concatenate(self, char *dst, char *src, int n):
        if self.truncate:
            return

        if len(dst) + len(src) > n - 1:
            self.truncate = True
            return

        strncat(dst, src, n)

    cdef build_sep(self):
        cdef char *ssep = '    '
        cdef int  counter
        cdef int  i
        cdef int  max_len

        max_len = len(ssep) * SEP_SIZE + 1

        for i in range(SEP_SIZE):
            counter = i
            t = <char *>malloc(max_len)

            if t is NULL:
                logging.warning("Memory allocation error")
                sys._exit(-1)

            memset(t, 0, sizeof(t))

            while counter:
                self.concatenate(t, ssep, max_len)
                counter -= 1

            self.sep[i] = t

    cdef log_function_header(self, c_emu_profile_function *function):
        snprintf(self.s,
                 S_SIZE,
                 "%s %s (\n",
                 function.return_value.argtype,
                 function.fnname)

        self.concatenate(self.output, self.s, self.output_size)

    cdef log_bracket_closed(self):
        cdef char *s = ")"

        self.concatenate(self.output, s, self.output_size)

    cdef log_array_start(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = [ \n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname)

        self.concatenate(self.output, self.s, self.output_size)

    cdef log_array_end(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s ];\n",
                 self.sep[indent])

        self.concatenate(self.output, self.s, self.output_size)

    cdef log_struct_start(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s struct %s %s = {\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname)

        self.concatenate(self.output, self.s, self.output_size)

    cdef log_struct_end(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s };\n",
                 self.sep[indent])

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_int(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = %i;\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname,
                 argument.value.tint)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_string(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = \"%s\";\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname,
                 argument.value.tchar)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_bytea(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = \".binary.\" (%i bytes);\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname,
                 argument.value.bytea.size)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_ptr(self, c_emu_profile_argument *argument, int is_struct, int indent):
        if is_struct:
            snprintf(self.s,
                     S_SIZE,
                     "%s struct %s %s = 0x%08x => \n",
                     self.sep[indent],
                     argument.argtype,
                     argument.argname,
                     argument.value.tptr.addr)
        else:
            snprintf(self.s,
                     S_SIZE,
                     "%s %s = 0x%08x => \n",
                     self.sep[indent],
                     argument.argtype,
                     argument.argname,
                     argument.value.tptr.addr)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_ip(self, c_emu_profile_argument *argument, int indent):
        cdef c_in_addr *addr
        cdef char      *host

        addr = <c_in_addr *>&argument.value.tint
        host = inet_ntoa(addr[0])

        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = %i (host=%s);\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname,
                 argument.value.tint,
                 host)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_port(self, c_emu_profile_argument *argument, int indent):
        cdef uint16_t port

        port = ntohs(<uint16_t>argument.value.tint)

        snprintf(self.s,
                 S_SIZE,
                 "%s %s %s = %i (port=%i);\n",
                 self.sep[indent],
                 argument.argtype,
                 argument.argname,
                 argument.value.tint,
                 port)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_render_none(self, c_emu_profile_argument *argument, int indent):
        snprintf(self.s,
                 S_SIZE,
                 "%s none;\n",
                 self.sep[indent])

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_function_render_none(self):
        return

    cdef emu_profile_function_render_int(self, int value):
        snprintf(self.s,
                 S_SIZE,
                 " =  %i;\n",
                 value)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_function_render_ptr(self, void* ptr):
        snprintf(self.s,
                 S_SIZE,
                 " = 0x%08x;\n",
                 ptr)

        self.concatenate(self.output, self.s, self.output_size)

    cdef emu_profile_argument_debug(self, c_emu_profile_argument *argument, int indent):
        cdef c_emu_profile_argument *argit
        cdef c_emu_profile_argument *argumentit
        cdef int                    is_struct

        if argument.render == render_struct:
            self.log_struct_start(argument, indent)

            argumentit = emu_profile_arguments_first(argument.value.tstruct.arguments)

            while not emu_profile_arguments_istail(argumentit):
                self.emu_profile_argument_debug(argumentit, indent + 1)
                argumentit = emu_profile_arguments_next(argumentit)

            self.log_struct_end(argument, indent)
            return

        if argument.render == render_array:
            self.log_array_start(argument, indent)

            argumentit = emu_profile_arguments_first(argument.value.tstruct.arguments)
            while not emu_profile_arguments_istail(argumentit):
                self.emu_profile_argument_debug(argumentit, indent + 1)
                argumentit = emu_profile_arguments_next(argumentit)

            self.log_array_end(argument, indent)
            return

        if argument.render == render_int:
            self.emu_profile_argument_render_int(argument, indent)
            return

        if argument.render == render_short:
            self.emu_profile_argument_render_int(argument, indent)
            return

        if argument.render == render_string:
            self.emu_profile_argument_render_string(argument, indent)
            return

        if argument.render == render_bytea:
            self.emu_profile_argument_render_bytea(argument, indent)
            return

        if argument.render == render_ptr:
            argit = argument

            while argit.render == render_ptr:
                argit = argit.value.tptr.ptr

            is_struct = 0
            if argit.render == render_struct:
                is_struct = 1

            self.emu_profile_argument_render_ptr(argument, is_struct, indent)
            self.emu_profile_argument_debug(argument.value.tptr.ptr, indent + 1)
            return

        if argument.render == render_ip:
            self.emu_profile_argument_render_ip(argument, indent)
            return

        if argument.render == render_port:
            self.emu_profile_argument_render_port(argument, indent)
            return

        if argument.render == render_none:
            self.emu_profile_argument_render_none(argument, indent)
            return

    cdef emu_profile_function_debug(self, c_emu_profile_function *function):
        self.log_function_header(function)

        argument = emu_profile_arguments_first(function.arguments)
        while not emu_profile_arguments_istail(argument):
            self.emu_profile_argument_debug(argument, 1)
            argument = emu_profile_arguments_next(argument)

        self.log_bracket_closed()

        render = function.return_value.render

        if render == render_none:
            self.emu_profile_function_render_none()

        if render == render_int:
            value = function.return_value.value.tint
            self.emu_profile_function_render_int(value)

        if render == render_ptr:
            ptr = function.return_value.value.tptr.addr
            self.emu_profile_function_render_int(ptr)

        self.emu_profile_function_render_none()

    cdef emu_profile_debug(self, c_emu_env *_env):
        function = emu_profile_functions_first(_env.profile.functions)

        while not emu_profile_functions_istail(function):
            self.emu_profile_function_debug(function)
            function = emu_profile_functions_next(function)


cdef class Emulator:
    cdef c_emu      *_emu
    cdef EmuProfile emu_profile
    cdef int32_t    _offset
    cdef size_t     output_size

    def __cinit__(self, output_size = OUTPUT_SIZE):
        self.output_size = output_size
        self.new()

    def __dealloc__(self):
        self.free()

    def free(self):
        if self._emu is not NULL:
            emu_free(self._emu)
            self._emu = NULL

    def new(self):
        self._emu        = emu_new()
        self.emu_profile = EmuProfile(self.output_size)

    def set_output_size(self, output_size):
        self.free()
        self.output_size = output_size
        self.new()

    def shellcode_getpc_test(self, shellcode):
        '''
        GetPC code is code that determines its own location in a process address
        space.  It is commonly used in code that needs to  reference itself, for
        instance in self-decoding and self-modifying code.  This method tries to
        identify GetPC within the shellcode.

        @type  shellcode: Binary string
        @param shellcode: Shellcode

        @rtype:     Integer
        @return:    If GetPC code is successfully identified the offset from the
                    start of the shellcode is returned, otherwise -1.
        '''
        cdef char *buffer

        if self._emu is NULL:
            self.new()

        buffer = <char *>shellcode
        sclen  = len(bytes(shellcode))

        if buffer is NULL:
            return -1

        self._offset = emu_shellcode_test(self._emu, <uint8_t *>buffer, sclen)
        return self._offset

    def prepare(self, shellcode, offset):
        '''
        Method used to prepare  the execution environment.  The offset parameter
        value should be determined by the `shellcode_getpc_test method'. If such
        method is not able  to identify  the GetPC code  (thus returning -1) the
        suggested value for offset parameter is 0.

        @type   shellcode: Binary string
        @param  shellcode: Shellcode
        @type   offset   : Integer
        @param  offset   : GetPC offset
        '''
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
        '''
        Method used to test and emulate the shellcode. The method must be always
        called after the `prepare' method.

        @type   steps:  Integer
        @param  steps:  Max number of steps to run
        '''
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
                    logging.warning("Unhooked call to %s\n" % (hook.hook.win.fnname, ))
                    break
            else:
                ret = emu_cpu_parse(emu_cpu_get(self._emu))
                hook = NULL
                if ret != -1:
                    hook = emu_env_linux_syscall_check(_env)
                    if hook is NULL:
                        ret = emu_cpu_step(emu_cpu_get(self._emu))
                    else:
                        logging.warning("Error")

                if ret == -1:
                    break

        self.emu_profile.emu_profile_debug(_env)
        return 0

    cpdef int run(self, shellcode):
        cdef int32_t offset

        offset = self.shellcode_getpc_test(shellcode)
        if offset < 0:
            offset = 0

        self.prepare(shellcode, offset)
        return self.test()

    @property
    def offset(self):
        return self._offset

    @property
    def emu_profile_output(self):
        return self.emu_profile.output

    @property
    def emu_profile_truncated(self):
        return self.emu_profile.truncate

    # CPU methods
    def cpu_reg32_get(self, c_emu_reg32 reg):
        ''' 
        Method used to get the 32-bit value stored in a register

        @type   reg:  Integer
        @param  reg:  Register index
                        eax = 0
                        ecx = 1
                        edx = 2
                        ebx = 3
                        esp = 4
                        ebp = 5
                        esi = 6
                        edi = 7

        @rtype:     uint32_t 
        @return:    32-bit value stored in the register

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        return <uint32_t>emu_cpu_reg32_get(_cpu, reg)

    def cpu_reg32_set(self, c_emu_reg32 reg, uint32_t val):
        ''' 
        Method used to set a register with a 32-bit value

        @type   reg:  Integer
        @param  reg:  Register index
                        eax = 0
                        ecx = 1
                        edx = 2
                        ebx = 3
                        esp = 4
                        ebp = 5
                        esi = 6
                        edi = 7

        @type   val:  uint32_t
        @param  val:  32-bit value

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_reg32_set(_cpu, reg, val)

    def cpu_reg16_get(self, c_emu_reg16 reg):
        ''' 
        Method used to get the 16-bit value stored in a register

        @type   reg:  Integer
        @param  reg:  Register index
                        ax = 0
                        cx = 1
                        dx = 2
                        bx = 3
                        sp = 4
                        bp = 5
                        si = 6
                        di = 7

        @rtype:     uint16_t 
        @return:    16-bit value stored in the register

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        return <uint16_t>emu_cpu_reg16_get(_cpu, reg)

    def cpu_reg16_set(self, c_emu_reg16 reg, uint16_t val):
        ''' 
        Method used to set a register with a 16-bit value

        @type   reg:  Integer
        @param  reg:  Register index
                        ax = 0
                        cx = 1
                        dx = 2
                        bx = 3
                        sp = 4
                        bp = 5
                        si = 6
                        di = 7

        @type   val:  uint16_t
        @param  val:  16-bit value

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_reg16_set(_cpu, reg, val)

    def cpu_reg8_get(self, c_emu_reg8 reg):
        ''' 
        Method used to get the 8-bit value stored in a register

        @type   reg:  Integer
        @param  reg:  Register index
                        al = 0
                        cl = 1
                        dl = 2
                        bl = 3
                        ah = 4
                        ch = 5
                        dh = 6
                        bh = 7

        @rtype:     uint8_t 
        @return:    8-bit value stored in the register

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu
    
        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')
    
        _cpu = emu_cpu_get(self._emu)
        return <uint8_t>emu_cpu_reg8_get(_cpu, reg)
    
    def cpu_reg8_set(self, c_emu_reg8 reg, uint8_t val):
        ''' 
        Method used to set a register with a 8-bit value

        @type   reg:  Integer
        @param  reg:  Register index
                        al = 0
                        cl = 1
                        dl = 2
                        bl = 3
                        ah = 4
                        ch = 5
                        dh = 6
                        bh = 7

        @type   val:  uint8_t
        @param  val:  8-bit value

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu
        
        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_reg8_set(_cpu, reg, val)

    def cpu_eflags_get(self):
        '''
        Method used to get the 32-bit value stored in the register eflags

        @rtype:     uint32_t 
        @return:    32-bit value stored in the register eflags

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        return <uint32_t>emu_cpu_eflags_get(_cpu)

    def cpu_eflags_set(self, uint32_t val):
        ''' 
        Method used to set the register eflags with a 32-bit value

        @type   val:  uint32_t
        @param  val:  32-bit value

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_eflags_set(_cpu, val)

    def cpu_eip_set(self, uint32_t eip):
        ''' 
        Method used to set the register eip with a 32-bit value

        @type   val:  uint32_t
        @param  val:  32-bit value

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_eip_set(_cpu, eip)

    def cpu_eip_get(self):
        '''
        Method used to get the 32-bit value stored in the register eip

        @rtype:     uint32_t 
        @return:    32-bit value stored in the register eip

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        return <uint32_t>emu_cpu_eip_get(_cpu)

    def cpu_parse(self):
        ''' 
        Method used to parse an instruction at eip

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')
    
        _cpu = emu_cpu_get(self._emu)
        return <int32_t>emu_cpu_parse(_cpu)

    def cpu_step(self):
        ''' 
        Method used to step the last instruction

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')
        
        _cpu = emu_cpu_get(self._emu)
        return <int32_t>emu_cpu_step(_cpu)

    def cpu_debugflag_set(self, uint8_t flag):
        ''' 
        Method used to set a cpu debug flag

        @type   flag:  uint8_t
        @param  flag:  flag to set

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_debugflag_set(_cpu, flag)

    def cpu_debugflag_unset(self, uint8_t flag):
        ''' 
        Method used to unset a cpu debug flag

        @type   flag:  uint8_t
        @param  flag:  flag to unset

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_cpu *_cpu

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _cpu = emu_cpu_get(self._emu)
        emu_cpu_debugflag_unset(_cpu, flag)

    # Memory methods
    def memory_write_byte(self, uint32_t addr, uint8_t byte):
        '''
        Method used to write a byte at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @type   byte:  uint8_t
        @param  byte:  byte to write

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        emu_memory_write_byte(_mem, addr, byte)

    def memory_write_word(self, uint32_t addr, uint16_t word):
        '''
        Method used to write a word at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @type   word:  uint16_t
        @param  word:  word to write

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        emu_memory_write_word(_mem, addr, word)

    def memory_write_dword(self, uint32_t addr, uint32_t dword):
        ''' 
        Method used to write a dword at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @type   dword:  uint32_t
        @param  dword:  dword to write

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        emu_memory_write_dword(_mem, addr, dword)

    def memory_write_block(self, uint32_t addr, src, size_t _len):
        ''' 
        Method used to write a block at a memory location

        @type   addr:   uint32_t
        @param  addr:   memory location address

        @type   src:    bytes
        @param  src:    block of data to write

        @type   _len:   size_t
        @param  _len:   block size

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        emu_memory_write_block(_mem, addr, <void *>src, _len)

    def memory_read_byte(self, uint32_t addr):
        ''' 
        Method used to read a byte at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @rtype:     uint8_t 
        @return:    byte at memory location address

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem
        cdef uint8_t      byte

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        if emu_memory_read_byte(_mem, addr, &byte):
            raise RuntimeError("Error while reading a byte at address 0x%x" % (addr, ))

        return byte

    def memory_read_word(self, uint32_t addr):
        ''' 
        Method used to read a word at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @rtype:     uint16_t 
        @return:    word at memory location address

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem
        cdef uint16_t     word

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        if emu_memory_read_word(_mem, addr, &word):
            raise RuntimeError("Error while reading a word at address 0x%x" % (addr, ))

        return word

    def memory_read_dword(self, uint32_t addr):
        ''' 
        Method used to read a dword at a memory location

        @type   addr:  uint32_t
        @param  addr:  memory location address

        @rtype:     uint32_t 
        @return:    word at memory location address

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem
        cdef uint32_t     dword

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        if emu_memory_read_dword(_mem, addr, &dword):
            raise RuntimeError("Error while reading a word at address 0x%x" % (addr, ))

        return dword

    def memory_read_block(self, uint32_t addr, size_t _len):
        '''  
        Method used to read a block at a memory location

        @type   addr:     uint32_t
        @param  addr:     memory location address

        @type   _len:  size_t
        @param  _len:  block size

        @rtype:     char * 
        @return:    block at memory location address

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem
        cdef void         *block

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')
        
        block = malloc(_len)
        if block is NULL:
            raise RuntimeError('Error while allocating memory')

        _mem = emu_memory_get(self._emu)
        if emu_memory_read_block(_mem, addr, block, _len):
            raise RuntimeError("Error while reading a dword at address 0x%x" % (addr, ))

        return <char *>block

    def memory_read_string(self, uint32_t addr, uint32_t maxsize):
        ''' 
        Method used to read a string at a memory location

        @type   addr:     uint32_t
        @param  addr:     memory location address

        @type   maxsize:  uint32_t
        @param  maxsize:  string max size

        @rtype:     char * 
        @return:    string at memory location address

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem
        cdef c_emu_string s

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        if emu_memory_read_string(_mem, addr, &s, maxsize):
            raise RuntimeError("Error while reading a string at address 0x%x" % (addr, ))

        return <char *>s.data

    def memory_segment_select(self, c_emu_segment segment):
        '''  
        Method used to select a segment

        @type   segment:    Integer
        @param  segment:    Segment index
                                s_cs = 0 
                                s_ss = 1 
                                s_ds = 2 
                                s_es = 3 
                                s_fs = 4 
                                s_gs = 5 

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        emu_memory_segment_select(_mem, segment)

    def memory_segment_get(self):
        '''  
        Method used to get the current segment

        @rtype   segment:     Integer
        @rparam  segment:     Segment index
                                s_cs = 0 
                                s_ss = 1 
                                s_ds = 2 
                                s_es = 3 
                                s_fs = 4 
                                s_gs = 5 

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_memory *_mem

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _mem = emu_memory_get(self._emu)
        return emu_memory_segment_get(_mem)

    # Win32 environment
    def env_w32_hook_check(self):
        '''
        Method used to check if a hooked Win32 API is at the
        current eip 

        @rtype      boolean
        @rparam     True if a hooked Win32 API is at the current
                    eip, False otherwise

        Raises RuntimeError if the Emulator is not initialized
        '''
        cdef c_emu_env      *_env

        if self._emu is NULL:
            raise RuntimeError('Emulator not initialized')

        _env = emu_env_new(self._emu)
        if _env is NULL:
            print emu_strerror(self._emu)
            raise RuntimeError('Emulator environment error')

        if emu_env_w32_eip_check(_env) is NULL:
            return False

        return True
