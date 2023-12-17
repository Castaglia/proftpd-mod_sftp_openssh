/*
 * ProFTPD - mod_sftp_openssh keys
 * Copyright (c) 2023 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_sftp_openssh.h"

#ifndef MOD_SFTP_OPENSSH_KEYS_H
#define MOD_SFTP_OPENSSH_KEYS_H

int sftp_openssh_keys_parse(pool *p, const char *line, size_t linelen,
  unsigned char **key_data, uint32_t *key_datalen, const char **comment,
  pr_table_t *headers);

#endif /* MOD_SFTP_OPENSSH_KEYS_H */
