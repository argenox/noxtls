# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# The external PSK binder's failing step must stay readable after the call.

add_executable(psk_fail_step_test psk_fail_step_test.c)
target_link_libraries(psk_fail_step_test PRIVATE noxtls_tls)
add_test(NAME psk_fail_step_test COMMAND psk_fail_step_test)
