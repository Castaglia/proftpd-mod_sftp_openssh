/*
 * ProFTPD: mod_sftp_openssh keys
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, the respective copyright holders give permission
 * to link this program with OpenSSL, and distribute the resulting
 * executable, without including the source code for OpenSSL in the source
 * distribution.
 */

#include "keys.h"

#define SFTP_OPENSSH_BUFSZ	1024

static int is_supported_key_type(const char *key_desc) {
  int supported = FALSE;

  if (strcmp(key_desc, "ssh-rsa") == 0 ||
#if !defined(OPENSSL_NO_DSA)
      strcmp(key_desc, "ssh-dss") == 0) {
#endif /* !OPENSSL_NO_DSA */
#if defined(PR_USE_OPENSSL_ECC)
      strcmp(key_desc, "ecdsa-sha2-nistp256") == 0 ||
      strcmp(key_desc, "ecdsa-sha2-nistp384") == 0 ||
      strcmp(key_desc, "ecdsa-sha2-nistp521") == 0 ||
# if PROFTPD_VERSION_NUMBER >= 0x0001030901
      strcmp(key_desc, "sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
# endif /* Prior to ProFTPD 1.3.9rc1 */
#endif /* PR_USE_OPENSSL_ECC */
#if defined(PR_USE_SODIUM)
      strcmp(key_desc, "ssh-ed25519") == 0 ||
# if PROFTPD_VERSION_NUMBER >= 0x0001030901
      strcmp(key_desc, "sk-ssh-ed25519@openssh.com") == 0 ||
# endif /* Prior to ProFTPD 1.3.9rc1 */
#endif /* PR_USE_SODIUM */
      FALSE) {
    supported = TRUE;
  }

  return supported;
}

/* Return count of handled/parsed options. */
static unsigned int parse_options(pool *p, const char *text,
    pr_table_t *headers) {
  const char *ptr;
  unsigned int count = 0;

  ptr = text;
  while (*ptr &&
         !PR_ISSPACE(*ptr)) {
    const char *opt = NULL;
    size_t opt_len = 0;

    pr_signals_handle();

    /* There are currently only a few OpenSSH options of interest to us. */

#if PROFTPD_VERSION_NUMBER >= 0x0001030901
    /* ProFTPD 1.3.9rc1 is when support for FIDO security keys first appeared.
     */
    opt = "touch-required";
    opt_len = strlen(opt);
    if (strncasecmp(ptr, opt, opt_len) == 0) {
      count++;

      if (pr_table_add_dup(headers, SFTP_KEYSTORE_HEADER_FIDO_TOUCH_REQUIRED,
          "true", 0) < 0) {
        pr_trace_msg(trace_channel, 19,
          "error adding '%s' header from key: %s",
           SFTP_KEYSTORE_HEADER_FIDO_TOUCH_REQUIRED, strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 22, "added header: '%s: true' to notes",
          SFTP_KEYSTORE_HEADER_FIDO_TOUCH_REQUIRED);
      }

      ptr += opt_len;

      if (*ptr == ',') {
        ptr++;
      }
    }

    opt = "verify-required";
    opt_len = strlen(opt);
    if (strncasecmp(ptr, opt, opt_len) == 0) {
      count++;

      if (pr_table_add_dup(headers, SFTP_KEYSTORE_HEADER_FIDO_VERIFY_REQUIRED,
          "true", 0) < 0) {
        pr_trace_msg(trace_channel, 19,
          "error adding '%s' header from key: %s",
           SFTP_KEYSTORE_HEADER_FIDO_VERIFY_REQUIRED, strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 22, "added header: '%s: true' to notes",
          SFTP_KEYSTORE_HEADER_FIDO_VERIFY_REQUIRED);
      }

      ptr += opt_len;

      if (*ptr == ',') {
        ptr++;
      }
    }
#endif /* Prior to ProFTPD 1.3.9rc1 */

    if (*ptr == '\0' ||
        PR_ISSPACE(*ptr)) {
      /* End of options. */
      break;
    }

    if (*ptr != ',') {
      /* Unsupported option. */
      ptr++;
    }

    if (*ptr == '\0') {
      /* End of options. */
      break;
    }
  }

  return count;
}

static int parse_key_data(pool *p, const char *text, size_t text_len,
    unsigned char **key_data, uint32_t *key_datalen) {
  BIO *bio = NULL, *bmem = NULL, *b64 = NULL;
  char chunk[SFTP_OPENSSH_BUFSZ], *data = NULL;
  int chunklen, res;
  long datalen = 0;

  bio = BIO_new(BIO_s_mem());

  if (BIO_write(bio, (void *) *text, text_len) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
      "error buffering base64 data: %s", sftp_crypto_get_errors());
  }

  /* Add a base64 filter BIO, and read the data out, thus base64-decoding
   * the key.  Write the decoded data into another memory BIO.
   */
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  bmem = BIO_new(BIO_s_mem());

  memset(chunk, '\0', sizeof(chunk));
  chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));

  if (chunklen < 0 &&
      !BIO_should_retry(bio)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
      "unable to base64-decode data from OpenSSH key: %s",
      sftp_crypto_get_errors());
    BIO_free_all(bio);
    BIO_free_all(bmem);

    errno = EPERM;
    return -1;
  }

  while (chunklen > 0) {
    pr_signals_handle();

    if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
        "error writing to memory BIO: %s", sftp_crypto_get_errors());
      BIO_free_all(bio);
      BIO_free_all(bmem);

      errno = EPERM;
      return -1;
    }

    memset(chunk, '\0', sizeof(chunk));
    chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
  }

  datalen = BIO_get_mem_data(bmem, &data);
  if (data != NULL &&
      datalen > 0) {
    *key_datalen = datalen;
    *key_data = palloc(p, datalen + 1);
    (*key_data)[datalen] = '\0';
    memcpy(*key_data, data, datalen);
    res = 0;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
      "error base64-decoding key data from OpenSSH key");
    errno = ENOENT;
    res = -1;
  }

  BIO_free_all(bio);
  BIO_free_all(bmem);

  return res;
}

int sftp_openssh_keys_parse(pool *p, const char *line, size_t linelen,
    unsigned char **key_data, uint32_t *key_datalen,
    const char **comment, pr_table_t *headers) {
  const char *key_opts = NULL, *ptr;
  int supported_key_type = FALSE;
  size_t comment_len = 0, len;

  ptr = line;

  len = strcspn(ptr, " \t");
  if (len == strlen(ptr)) {
    pr_trace_msg(trace_channel, 15,
      "ignoring badly formatted OpenSSH key '%.*s'", (int) linelen-1, ptr);

    errno = EINVAL;
    return -1;
  }

  /* field: options, or key type */
  supported_key_type = is_supported_key_type(ptr);
  if (supported_key_type == FALSE) {
    /* Assume we are dealing with key options; we'll parse these later. */
    key_opts = ptr;

    /* XXX Skip options */

    /* field: key type */
    supported_key_type = is_supported_key_type(ptr);
    if (supported_key_type == FALSE) {
      len = strcspn(ptr, " \t");
      pr_trace_msg(trace_channel, 15,
        "skipping unsupported OpenSSH key type '%.*s'", (int) len, ptr);

      errno = EINVAL;
      return -1;
    }
  }

  /* Skip whitespace. */
  for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
  }

  if (*ptr == '\0') {
    pr_trace_msg(trace_channel, 
    errno = EINVAL;
    return -1;
  }

  /* field: base64-encoded key data */
  len = strcspn(ptr, " \t");

  if (parse_key_data(p, ptr, len, key_data, key_datalen) < 0) {
    return -1;
  }

  /* Skip whitespace. */
  for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
  }

  /* field: comment */
  comment_len = strlen(ptr);
  if (comment_len > 1) {
    /* Omit the trailing newline. */
    *comment = pstrndup(p, ptr, comment_len-1);

  } else {
    *comment = pstrdup(p, "");
  }

  return 0;
}
