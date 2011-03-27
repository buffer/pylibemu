# pylibemu.pxd
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


from libc.stdint cimport int32_t, uint8_t, uint16_t, uint32_t
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

cdef extern from "emu/emu_memory.h":
    ctypedef struct c_emu_memory "struct emu_memory":
        pass

    int32_t emu_memory_write_byte(c_emu_memory *m, uint32_t addr, uint8_t byte)
    int32_t emu_memory_write_word(c_emu_memory *m, uint32_t addr, uint16_t word)
    int32_t emu_memory_write_dword(c_emu_memory *m, uint32_t addr, uint32_t dword)
    int32_t emu_memory_write_block(c_emu_memory *m, uint32_t addr, void *src, size_t len)


cdef extern from "emu/environment/emu_profile.h":
    ctypedef struct c_emu_profile "struct emu_profile":
        pass

    c_emu_profile   *emu_profile_new()
    void             emu_profile_free(c_emu_profile *profile)
    void             emu_profile_debug(c_emu_profile *profile)


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
    void             emu_free(c_emu *e) 
    c_emu_memory    *emu_memory_get(c_emu *e) 
    c_emu_logging   *emu_logging_get(c_emu *e) 
    c_emu_cpu       *emu_cpu_get(c_emu *e) 
    int              emu_errno(c_emu *c) 
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
    
    void emu_cpu_reg32_set(c_emu_cpu *cpu_p, c_emu_reg32 reg, uint32_t val)
    void emu_cpu_eflags_set(c_emu_cpu *c, uint32_t val)
    void emu_cpu_eip_set(c_emu_cpu *c, uint32_t eip)
    uint32_t emu_cpu_eip_get(c_emu_cpu *c)
    int32_t emu_cpu_parse(c_emu_cpu *c)
    int32_t emu_cpu_step(c_emu_cpu *c)


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
        #int32_t     (*fnhook)(c_emu_env *env, c_emu_env_hook *hook)
        void        *userdata
        #uint32_t    (*userhook)(c_emu_env *env, c_emu_env_hook *hook, ...)

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

    c_emu_env       *emu_env_new(c_emu *e)
    void             emu_env_free(c_emu_env *env)


cdef extern from "emu/environment/linux/emu_env_linux.h":
    c_emu_env_hook *emu_env_linux_syscall_check(c_emu_env *env)


cdef extern from "emu/environment/win32/emu_env_w32.h":
    int32_t         emu_env_w32_load_dll(c_emu_env_w32 *env, char *path)
    c_emu_env_hook *emu_env_w32_eip_check(c_emu_env *env)
    int32_t         emu_env_w32_export_hook(c_emu_env       *env,
                                            char  *exportname,
                                            uint32_t        (*fnhook)(c_emu_env *env, c_emu_env_hook *hook, ...),
                                            void            *userdata)



cdef extern from "emu/emu_shellcode.h":
    int32_t emu_shellcode_test(c_emu *e, uint8_t *data, uint16_t size)




