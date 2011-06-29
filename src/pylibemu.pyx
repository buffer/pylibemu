#
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

import sys
import socket
import urllib2
import hashlib
import logging

logging.basicConfig(format = '%(asctime)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]')

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
