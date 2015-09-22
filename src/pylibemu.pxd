# pylibemu.pxd
#
# Copyright(c) 2011-2015 Angelo Dell'Aera <buffer@antifork.org>
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


from libc.stdint cimport int16_t, int32_t, uint8_t, uint16_t, uint32_t
cimport cpython


cdef extern from *:
    ctypedef char* const_char_ptr "const char*"


cdef extern from "stdarg.h":
    ctypedef struct va_list:
        pass

    ctypedef struct fake_type:
        pass

    void  va_start(va_list, void *arg)
    void* va_arg(va_list, fake_type)
    void  va_end(va_list)

    fake_type void_ptr_type "void *"
    fake_type char_ptr_type "char *"
    fake_type int_type "int"


cdef extern from "stdio.h":
    int snprintf(char *, size_t, char *, ...)


cdef extern from "stdlib.h":
    void free(void* )
    void *malloc(size_t)


cdef extern from "string.h":
    char *strncat(char *, char *, size_t)
    void *memset(void *, int , size_t)


cdef extern from "netinet/in.h":
    ctypedef struct c_in_addr "struct in_addr":
        pass


cdef extern from "arpa/inet.h":
    uint16_t ntohs(uint16_t)
    char     *inet_ntoa(c_in_addr)


cdef extern from "emu/emu_string.h":
    ctypedef struct c_emu_string "struct emu_string":
        uint32_t    size
        void        *data
        uint32_t    allocated


cdef extern from "emu/emu_memory.h":
    ctypedef struct c_emu_memory "struct emu_memory":
        pass

    ctypedef enum c_emu_segment "enum emu_segment":
        s_cs = 0
        s_ss = 1
        s_ds = 2
        s_es = 3
        s_fs = 4
        s_gs = 5
        
    int32_t emu_memory_write_byte(c_emu_memory *m, uint32_t addr, uint8_t byte)
    int32_t emu_memory_write_word(c_emu_memory *m, uint32_t addr, uint16_t word)
    int32_t emu_memory_write_dword(c_emu_memory *m, uint32_t addr, uint32_t dword)
    int32_t emu_memory_write_block(c_emu_memory *m, uint32_t addr, void *src, size_t _len)

    int32_t emu_memory_read_byte(c_emu_memory *m, uint32_t addr, uint8_t *byte)
    int32_t emu_memory_read_word(c_emu_memory *m, uint32_t addr, uint16_t *word)
    int32_t emu_memory_read_dword(c_emu_memory *m, uint32_t addr, uint32_t *dword)
    int32_t emu_memory_read_block(c_emu_memory *m, uint32_t addr, void *dest, size_t _len)
    int32_t emu_memory_read_string(c_emu_memory *m, uint32_t addr, c_emu_string *s, uint32_t maxsize)

    void emu_memory_segment_select(c_emu_memory *m, c_emu_segment s)
    c_emu_segment emu_memory_segment_get(c_emu_memory *m)


cdef extern from "emu/environment/emu_profile.h":
    cdef enum emu_profile_argument_render:
        render_none
        render_ptr
        render_int
        render_short
        render_struct
        render_string
        render_bytea
        render_ip
        render_port
        render_array

    ctypedef enum c_emu_profile_argument_render "enum emu_profile_argument_render":
        pass

    ctypedef struct c_emu_profile_argument "struct emu_profile_argument"

    ctypedef struct c_emu_profile_argument_root "struct emu_profile_argument_root":
        pass

    ctypedef struct c_bytea:
        unsigned char                       *data
        uint32_t                            size

    ctypedef struct c_tstruct:
        c_emu_profile_argument_root         *arguments

    ctypedef struct c_tptr:
        c_emu_profile_argument              *ptr
        uint32_t                            addr

    ctypedef union c_emu_profile_argument_value:
        int32_t                             tint
        int16_t                             tshort
        char                                *tchar
        c_bytea                             bytea
        c_tstruct                           tstruct
        c_tptr                              tptr

    ctypedef struct c_emu_profile_argument "struct emu_profile_argument":
        emu_profile_argument_render         render
        c_emu_profile_argument_value        value
        char                                *argname
        char                                *argtype

    ctypedef struct c_emu_profile_function "struct emu_profile_function":
        emu_profile_argument_render         retval
        char                                *fnname
        c_emu_profile_argument_root         *arguments
        c_emu_profile_argument              *return_value

    ctypedef struct c_emu_profile_function_root "struct emu_profile_function_root":
        pass

    ctypedef struct c_emu_profile_function "struct emu_profile_function":
        pass

    ctypedef struct c_emu_profile "struct emu_profile":
        c_emu_profile_function_root *functions

    c_emu_profile            *emu_profile_new()
    void                     emu_profile_free(c_emu_profile *profile)
    void                     emu_profile_debug(c_emu_profile *profile)
    c_emu_profile_argument   *emu_profile_arguments_first(c_emu_profile_argument_root *root)
    c_emu_profile_argument   *emu_profile_arguments_next(c_emu_profile_argument *argument)
    bint                     emu_profile_arguments_istail(c_emu_profile_argument *argument)
    void                     emu_profile_argument_debug(c_emu_profile_argument *argument, int indent)
    c_emu_profile_function   *emu_profile_functions_first(c_emu_profile_function_root *root)
    c_emu_profile_function   *emu_profile_functions_next(c_emu_profile_function *function)
    bint                     emu_profile_functions_istail(c_emu_profile_function *function)
    void                     emu_profile_function_debug(c_emu_profile_function *function)


cdef extern from "emu/emu.h":
    ctypedef struct c_emu "struct emu":
        pass


cdef extern from "emu/emu_cpu_data.h":
    ctypedef struct c_emu_instruction "struct emu_instruction":
        pass

    ctypedef struct c_emu_cpu_instruction_info "struct emu_cpu_instruction_info":
        pass

    ctypedef struct c_emu_track_and_source "struct emu_track_and_source":
        pass

    ctypedef struct c_emu_cpu "struct emu_cpu":
        c_emu                       *emu
        c_emu_memory                *mem
        uint32_t                    debugflags
        uint32_t                    eip
        uint32_t                    eflags
        uint32_t                    reg[8]
        uint16_t                    *reg16[8]
        uint8_t                     *reg8[8]
        c_emu_instruction           instr
        c_emu_cpu_instruction_info  *cpu_instr_info
        uint32_t                    last_fpu_instr[2]
        char                        *instr_string
        bint                        repeat_current_instr
        c_emu_track_and_source      *tracking


cdef extern from "emu/emu.h":
    ctypedef struct c_emu_logging "struct emu_logging":
        pass

    ctypedef struct c_emu_fpu "struct emu_fpu":
        pass

    c_emu           *emu_new()
    void            emu_free(c_emu *e)
    c_emu_memory    *emu_memory_get(c_emu *e)
    c_emu_logging   *emu_logging_get(c_emu *e)
    c_emu_cpu       *emu_cpu_get(c_emu *e)
    int             emu_errno(c_emu *c)
    char            *emu_strerror(c_emu *e)


cdef extern from "emu/emu_cpu.h":
    ctypedef enum c_emu_reg32 "enum emu_reg32":
        eax = 0
        ecx = 1
        edx = 2
        ebx = 3
        esp = 4
        ebp = 5
        esi = 6
        edi = 7

    ctypedef enum c_emu_reg16 "enum emu_reg16":
        ax = 0 
        cx = 1 
        dx = 2 
        bx = 3 
        sp = 4 
        bp = 5 
        si = 6 
        di = 7 

    ctypedef enum c_emu_reg8 "enum emu_reg8":
        al = 0 
        cl = 1 
        dl = 2 
        bl = 3 
        ah = 4 
        ch = 5 
        dh = 6 
        bh = 7 

    uint32_t emu_cpu_reg32_get(c_emu_cpu *cpu_p, c_emu_reg32 reg)
    void     emu_cpu_reg32_set(c_emu_cpu *cpu_p, c_emu_reg32 reg, uint32_t val)
    uint16_t emu_cpu_reg16_get(c_emu_cpu *cpu_p, c_emu_reg16 reg)
    void     emu_cpu_reg16_set(c_emu_cpu *cpu_p, c_emu_reg16 reg, uint16_t val)
    uint8_t  emu_cpu_reg8_get(c_emu_cpu *cpu_p, c_emu_reg8 reg)
    void     emu_cpu_reg8_set(c_emu_cpu *cpu_p, c_emu_reg8 reg, uint8_t val)
    uint32_t emu_cpu_eflags_get(c_emu_cpu *c)
    void     emu_cpu_eflags_set(c_emu_cpu *c, uint32_t val)
    void     emu_cpu_eip_set(c_emu_cpu *c, uint32_t eip)
    uint32_t emu_cpu_eip_get(c_emu_cpu *c)
    int32_t  emu_cpu_parse(c_emu_cpu *c)
    int32_t  emu_cpu_step(c_emu_cpu *c)
    int32_t  emu_cpu_run(c_emu_cpu *c)
    void     emu_cpu_free(c_emu_cpu *c)
    void     emu_cpu_debug_print(c_emu_cpu *c)
    void     emu_cpu_debugflag_set(c_emu_cpu *c, uint8_t flag)
    void     emu_cpu_debugflag_unset(c_emu_cpu *c, uint8_t flag)


cdef extern from "emu/environment/linux/emu_env_linux.h":
    ctypedef struct c_emu_env_linux "struct emu_env_linux":
        pass

    ctypedef struct c_emu_env_linux_syscall "struct emu_env_linux_syscall":
        pass


cdef extern from "emu/environment/win32/emu_env_w32.h":
    ctypedef struct c_emu_env_w32 "struct emu_env_w32":
        pass


cdef extern from "emu/environment/win32/emu_env_w32_dll_export.h":
    ctypedef struct c_emu_env_w32_dll_export "struct emu_env_w32_dll_export":
        char        *fnname
        uint32_t    virtualaddr
        void        *userdata


cdef extern from "emu/environment/emu_env.h":
    ctypedef struct c_env:
         c_emu_env_w32       *win
         c_emu_env_linux     *lin

    ctypedef struct c_emu_env "struct emu_env":
        c_env           env
        c_emu           *emu
        c_emu_profile   *profile
        void            *userdata

    ctypedef enum c_emu_env_type "enum emu_env_type":
        emu_env_type_win32,
        emu_env_type_linux

    ctypedef union c_hook:
        c_emu_env_w32_dll_export    *win
        c_emu_env_linux_syscall     *lin

    ctypedef struct c_emu_env_hook "struct emu_env_hook":
        c_emu_env_type  type
        c_hook          hook

    c_emu_env *emu_env_new(c_emu *e)
    void      emu_env_free(c_emu_env *env)


cdef extern from "emu/environment/linux/emu_env_linux.h":
    c_emu_env_hook *emu_env_linux_syscall_check(c_emu_env *env)


cdef extern from "emu/environment/win32/emu_env_w32.h":
    int32_t         emu_env_w32_load_dll(c_emu_env_w32 *env, char *path)
    c_emu_env_hook  *emu_env_w32_eip_check(c_emu_env *env)
    int32_t         emu_env_w32_export_hook(c_emu_env   *env,
                                            char        *exportname,
                                            uint32_t    (*fnhook)(c_emu_env *env, c_emu_env_hook *hook, ...),
                                            void        *userdata)



cdef extern from "emu/emu_shellcode.h":
    int32_t emu_shellcode_test(c_emu *e, uint8_t *data, uint16_t size)




