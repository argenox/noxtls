/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

﻿#include "noxtls_ct.h"

/* Keep this value at zero; reads act as an optimization barrier. */
volatile uint64_t noxtls_mld_ct_opt_blocker_u64 = 0u;
