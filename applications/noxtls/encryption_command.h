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

#ifndef ENCRYPTION_COMMAND_H_
#define ENCRYPTION_COMMAND_H_

int encryption_encrypt_command(int argc, uint8_t ** argv);
int encryption_decrypt_command(int argc, uint8_t ** argv);
void print_encryption_usage(const uint8_t * command);

#endif /* ENCRYPTION_COMMAND_H_ */
