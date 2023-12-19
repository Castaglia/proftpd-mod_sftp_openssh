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

static const char *trace_channel = "sftp.openssh";

/* Return the index ("span") of the next character, assuming text that
 * contains quoted sections.  Make sure we handle the case where the
 * character of interest is not found in the given text, by returning -1
 * in such cases.
 */
static int strnqspn(const char *text, size_t text_len, char c) {
  int len = 0, quoted = FALSE;

  for (; *text && (quoted || (*text != ' ' && *text != '\t')); text++) {
    if (text[0] == '\\' &&
        text[1] == '"') {
      /* Skip past this escaped quote. */
      text++;
      len += 2;

    } else {
      if (text[0] == c &&
          quoted == FALSE) {
        return len;

      } else if (text[0] == '"') {
        quoted = !quoted;
      }

      len++;
    }
  }

  /* If we reach here, we've reached the end of the text without finding
   * any occurrences of the requested character.
   */
  errno = ENOENT;
  return -1;
}

/* Get the span of an options field of text, which includes any quoted spaces.
 * Returns the span length, or -1 on failure, such as for unterminated quotes.
 */
static int get_optspn(const char *text) {
  int len = 0, quoted = FALSE;

  for (; *text && (quoted || (*text != ' ' && *text != '\t')); text++) {
    if (text[0] == '\\' &&
        text[1] == '"') {
      /* Skip past this escaped quote. */
      text++;
      len += 2;

    } else {
      if (text[0] == '"') {
        quoted = !quoted;
      }

      len++;
    }
  }

  if (*text == '\0' &&
      quoted == TRUE) {
    /* We reached the end of text, and we're still quoted. */
    errno = EINVAL;
    return -1;
  }

  return len;
}

static int is_supported_key_type(const char *key_desc, size_t key_desclen) {
  int supported = FALSE;

  if (strncmp(key_desc, "ssh-rsa", key_desclen) == 0 ||
#if !defined(OPENSSL_NO_DSA)
      strncmp(key_desc, "ssh-dss", key_desclen) == 0 ||
#endif /* !OPENSSL_NO_DSA */
#if defined(PR_USE_OPENSSL_ECC)
      strncmp(key_desc, "ecdsa-sha2-nistp256", key_desclen) == 0 ||
      strncmp(key_desc, "ecdsa-sha2-nistp384", key_desclen) == 0 ||
      strncmp(key_desc, "ecdsa-sha2-nistp521", key_desclen) == 0 ||
# if PROFTPD_VERSION_NUMBER >= 0x0001030901
      strncmp(key_desc, "sk-ecdsa-sha2-nistp256@openssh.com",
        key_desclen) == 0 ||
# endif /* Prior to ProFTPD 1.3.9rc1 */
#endif /* PR_USE_OPENSSL_ECC */
#if defined(PR_USE_SODIUM)
      strncmp(key_desc, "ssh-ed25519", key_desclen) == 0 ||
# if PROFTPD_VERSION_NUMBER >= 0x0001030901
      strncmp(key_desc, "sk-ssh-ed25519@openssh.com", key_desclen) == 0 ||
# endif /* Prior to ProFTPD 1.3.9rc1 */
#endif /* PR_USE_SODIUM */
      FALSE) {
    supported = TRUE;
  }

  return supported;
}

struct key_opt {
  const char *name;
  const char *header_name;
  const char *header_val;
};

static struct key_opt supported_opts[] = {
#if PROFTPD_VERSION_NUMBER >= 0x0001030901
  /* ProFTPD 1.3.9rc1 is when support for FIDO security keys first appeared. */

  { "touch-required", SFTP_KEYSTORE_HEADER_FIDO_TOUCH_REQUIRED, "true" },
  { "no-touch-required", SFTP_KEYSTORE_HEADER_FIDO_TOUCH_REQUIRED, "false" },

  { "verify-required", SFTP_KEYSTORE_HEADER_FIDO_VERIFY_REQUIRED, "true" },
  { "no-verify-required", SFTP_KEYSTORE_HEADER_FIDO_VERIFY_REQUIRED, "false" },
#endif /* Prior to ProFTPD 1.3.9rc1 */

  { NULL, NULL, NULL }
};

static int parse_key_option(pool *p, const char *text, size_t text_len,
    pr_table_t *headers) {
  register unsigned int i;
  int res = -1;

  for (i = 0; supported_opts[i].name != NULL; i++) {
    size_t opt_len;

    opt_len = strlen(supported_opts[i].name);
    if (text_len < opt_len) {
      continue;
    }

    if (strncasecmp(text, supported_opts[i].name, opt_len) == 0) {
      if (pr_table_add_dup(headers, supported_opts[i].header_name,
          supported_opts[i].header_val, 0) < 0) {
        pr_trace_msg(trace_channel, 19,
          "error adding '%s' header from key: %s",
          supported_opts[i].header_name, strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 22, "added header: '%s: %s' to notes",
          supported_opts[i].header_name, supported_opts[i].header_val);
      }

      res = 0;
    }
  }

  return res;
}

/* Return count of handled/parsed options. */
static unsigned int parse_key_options(pool *p, const char *text,
    size_t text_len, pr_table_t *headers) {
  unsigned int count = 0;
  int len;

  len = strnqspn(text, text_len, ',');
  while (len > 0) {
    pr_signals_handle();

    if (parse_key_option(p, text, len, headers) == 0) {
      count++;
    }

    text += len;
    text_len -= len;

    /* Skip the comma, too. */
    text++;
    text_len--;

    len = strnqspn(text, text_len, ',');
  }

  /* Last option. */
  if (parse_key_option(p, text, text_len, headers) == 0) {
    count++;
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

  if (BIO_write(bio, (void *) text, text_len) < 0) {
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
    errno = EINVAL;
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
  size_t comment_len = 0, key_optslen = 0, len;

  ptr = line;

  len = strcspn(ptr, " \t");
  if (len == strlen(ptr)) {
    pr_trace_msg(trace_channel, 15,
      "ignoring badly formatted OpenSSH key '%.*s'", (int) linelen-1, ptr);

    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 22, "checking supported key type '%.*s'",
    (int) len, ptr);

  /* field: options, or key type */
  supported_key_type = is_supported_key_type(ptr, len);
  if (supported_key_type == FALSE) {
    int res;

    /* Assume we are dealing with key options; we'll parse these later.
     * Since the option specifications can themselves have embedded, quoted
     * spaces, we cannot use strcspn(3) directly here to determine the length
     * of this options field.
     */
    res = get_optspn(ptr);
    if (res < 0) {
      errno = EINVAL;
      return -1;
    }

    key_opts = ptr;
    key_optslen = (size_t) res;

    pr_trace_msg(trace_channel, 22, "skipping options '%.*s'",
      (int) key_optslen, key_opts);

    /* Advance past the options. */
    ptr += key_optslen;
    linelen -= key_optslen;

    /* Skip whitespace. */
    for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
      linelen--;
    }

    if (*ptr == '\0') {
      errno = EINVAL;
      return -1;
    }

    len = strcspn(ptr, " \t");

    pr_trace_msg(trace_channel, 22, "checking supported key type '%.*s'",
      (int) len, ptr);

    /* field: key type */
    supported_key_type = is_supported_key_type(ptr, len);
    if (supported_key_type == FALSE) {
      len = strcspn(ptr, " \t");
      pr_trace_msg(trace_channel, 15,
        "skipping unsupported OpenSSH key type '%.*s'", (int) len, ptr);

      errno = EINVAL;
      return -1;
    }
  }

  /* Advance past the key type. */
  ptr += len;
  linelen -= len;

  /* Skip whitespace. */
  for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
    linelen--;
  }

  if (*ptr == '\0') {
    errno = EINVAL;
    return -1;
  }

  /* field: base64-encoded key data */
  len = strcspn(ptr, " \t");

  pr_trace_msg(trace_channel, 22, "parsing key data '%.*s'", (int) len, ptr);
  if (parse_key_data(p, ptr, len, key_data, key_datalen) < 0) {
    return -1;
  }

  /* Advance past the key data. */
  ptr += len;
  linelen -= len;

  /* Skip whitespace. */
  for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
    linelen--;
  }

  /* field: comment */
  comment_len = strlen(ptr);
  if (comment_len > 1) {
    /* Omit the trailing newline. */
    *comment = pstrndup(p, ptr, comment_len-1);

  } else {
    *comment = pstrdup(p, "");
  }

  /* Now we check any options. */
  if (key_opts != NULL &&
      key_optslen > 0) {
    unsigned int count;

    pr_trace_msg(trace_channel, 22, "checking key options '%.*s'",
      (int) key_optslen, key_opts);

    count = parse_key_options(p, key_opts, key_optslen, headers);
    pr_trace_msg(trace_channel, 22, "supported key options parsed: %u", count);
  }

  pr_trace_msg(trace_channel, 22,
    "successfully parsed OpenSSH key (comment '%s')", *comment);
  return 0;
}
