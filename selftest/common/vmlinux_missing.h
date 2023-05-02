#ifndef __VMLINUX_MISSING_H__
#define __VMLINUX_MISSING_H__
;
; // don't remove: clangd parsing bug https://github.com/clangd/clangd/issues/1167
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

#ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
#endif

#pragma clang attribute pop

#endif
