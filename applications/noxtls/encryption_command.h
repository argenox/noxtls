/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    encryption_command.h
* Summary: NoxTLS encryption/decryption CLI commands
*
*/

#ifndef _ENCRYPTION_COMMAND_H_
#define _ENCRYPTION_COMMAND_H_

int encryption_encrypt_command(int argc, char ** argv);
int encryption_decrypt_command(int argc, char ** argv);
void print_encryption_usage(const char * command);

#endif /* _ENCRYPTION_COMMAND_H_ */
