/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_misra_refs.h
* Summary: Typed second-TU keep helpers for MISRA Rule 8.7 without Rule 11.1
*          function-pointer ↔ integer/void* conversions.
*****************************************************************************/
#ifndef NOXTLS_MISRA_REFS_H
#define NOXTLS_MISRA_REFS_H

/*
 * Call as NOXTLS_MISRA_REF_FN(&function_name) so Rule 17.12 sees an explicit &
 * at the call site (analyzers may not expand macros before checking).
 */
#define NOXTLS_MISRA_REF_FN(fn_addr) \
    do { \
        __typeof__(*(fn_addr)) *volatile noxtls_misra_fn_ref_ = (fn_addr); \
        (void)noxtls_misra_fn_ref_; \
    } while (0 == 1)

/* Reference a file-scope object (including arrays) without pointer casts. */
#define NOXTLS_MISRA_REF_OBJ(obj) \
    do { \
        __typeof__(obj) *volatile noxtls_misra_obj_ref_ = &(obj); \
        (void)noxtls_misra_obj_ref_; \
    } while (0 == 1)

#endif /* NOXTLS_MISRA_REFS_H */
