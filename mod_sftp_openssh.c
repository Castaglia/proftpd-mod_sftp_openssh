/*
 * ProFTPD: mod_sftp_openssh
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_sftp_openssh.a $
 */

#include "mod_sftp_openssh.h"
#include "keys.h"

module sftp_openssh_module;

/* File-based keystore implementation, similar to mod_sftp's rfc4716.c
 * implementation, except using OpenSSH's homegrown public key format.
 */

struct filestore_key {
  /* Optional headers */
  pr_table_t *headers;

  /* Key data */
  unsigned char *key_data;
  uint32_t key_datalen;

  const char *comment;
};

struct filestore_data {
  /* We use a FILE * here, in order to use getline(3) for file I/O, as
   * OpenSSH does.
   */
  FILE *fp;
  const char *path;
  unsigned int lineno;
};

static const char *trace_channel = "ssh2";

static struct filestore_key *filestore_alloc_key(pool *p) {
  struct filestore_key *key = NULL;

  key = pcalloc(p, sizeof(struct filestore_key));
  key->headers = pr_table_nalloc(p, 0, 1);

  return key;
}

static struct filestore_key *filestore_get_key(sftp_keystore_t *store,
    pool *p) {
  int res;
  char *line = NULL;
  size_t linelen = 0;
  struct filestore_key *key = NULL;
  struct filestore_data *store_data = store->keystore_data;
  unsigned char *key_data = NULL;
  uint32_t key_datalen = 0;
  const char *comment = NULL;

  while (getline(&line, &linelen, store_data->fp) != -1) {
    char *ptr;

    store_data->lineno++;

    ptr = line;

    /* Skip leading whitespace. */
    for (; *ptr && PR_ISSPACE(*ptr); ptr++) {
      linelen--;
    }

    if (!*ptr ||
        *ptr == '\n' ||
        *ptr == '#') {
      free(line);
      continue;
    }

    res = sftp_openssh_keys_parse(p, ptr, linelen, &key_data, &key_datalen,
      &comment, key->headers);
    if (res < 0) {
      pr_trace_msg(trace_channel, 10,
        "unable to parse data (line %u) as OpenSSH key", store_data->lineno);
      free(line);
      continue;
    }

    free(line);
    break;
  }

  key = filestore_alloc_key(p);
  key->key_datalen = key_datalen;
  key->key_data = key_data;
  key->comment = comment;

  return key;
}

#if PROFTPD_VERSION_NUMBER >= 0x0001030901
static int openssh_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_datalen,
    pr_table_t *headers) {
#else
static int openssh_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_datalen) {
#endif /* Prior to ProFTPD 1.3.9rc1 */
  struct filestore_key *key = NULL;
  struct filestore_data *store_data = store->keystore_data;
  unsigned int count = 0;
#if PROFTPD_VERSION_NUMBER < 0x0001030901
  pr_table_t *headers = NULL;
#endif /* Prior to ProFTPD 1.3.9rc1 */
  int res = -1;

  if (store_data->path == NULL) {
    errno = EPERM;
    return -1;
  }

  key = filestore_get_key(store, p);
  while (key != NULL) {
    int ok;

    pr_signals_handle();
    count++;

    ok = sftp_keys_compare_keys(p, key_data, key_datalen, key->key_data,
      key->key_datalen);
    if (ok != TRUE) {
      if (ok == -1) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
          "error comparing keys from '%s': %s", store_data->path,
          strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 10,
          "failed to match key #%u from file '%s'", count, store_data->path);
      }

    } else {
      res = 0;
      break;
    }

    key = filestore_get_key(store, p);
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 10, "found matching public key for user '%s' "
      "in '%s'", user, store_data->path);
    if (pr_table_copy(headers, key->headers, 0) < 0) {
      pr_trace_msg(trace_channel, 19, "error copying verify notes: %s",
        strerror(errno));
    }
  }

  if (fseek(store_data->fp, 0, SEEK_SET) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_OPENSSH_VERSION,
      "error seeking to start of '%s': %s", store_data->path, strerror(xerrno));

    xerrno = errno;
    return -1;
  }

  store_data->lineno = 0;
  return res;
}

static int openssh_close(sftp_keystore_t *store) {
  struct filestore_data *store_data;

  store_data = store->keystore_data;
  (void) fclose(store_data->fp);
  return 0;
}

static sftp_keystore_t *openssh_open(pool *parent_pool,
    int requested_key_type, const char *store_info, const char *user) {
  int xerrno;
  sftp_keystore_t *store;
  pool *store_pool;
  struct filestore_data *store_data;
  FILE *fp;
  char buf[PR_TUNABLE_PATH_MAX+1], *path;
  struct stat st;

  if (requested_key_type != SFTP_SSH2_USER_KEY_STORE) {
    errno = EPERM;
    return NULL;
  }

  store_pool = make_sub_pool(parent_pool);
  pr_pool_tag(store_pool, "SFTP OpenSSH Keystore Pool");

  store = pcalloc(store_pool, sizeof(sftp_keystore_t));
  store->keystore_pool = store_pool;
  store->store_ktypes = SFTP_SSH2_USER_KEY_STORE;
  store->verify_user_key = openssh_verify_user_key;
  store->store_close = openssh_close;

  /* Open the file.  The given path (store_info) may need to be
   * interpolated.
   */
  session.user = (char *) user;

  memset(buf, '\0', sizeof(buf));
  if (pr_fs_interpolate(store_info, buf, sizeof(buf)-1) == 1) {
    /* Interpolate occurred; make a copy of the interpolated path. */
    path = pstrdup(store_pool, buf);

  } else {
    /* Otherwise, use the path as is. */
    path = pstrdup(store_pool, store_info);
  }

  session.user = NULL;

  PRIVS_ROOT
  fp = fopen(path, "r");
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fp == NULL) {
    destroy_pool(store_pool);
    errno = xerrno;
    return NULL;
  }

  memset(&st, 0, sizeof(st));
  if (fstat(fileno(fp), &st) < 0) {
    xerrno = errno;

    destroy_pool(store_pool);
    (void) fclose(fp);

    errno = xerrno;
    return NULL;
  }

  if (S_ISDIR(st.st_mode)) {
    destroy_pool(store_pool);
    (void) fclose(fp);

    errno = EISDIR;
    return NULL;
  }

  store_data = pcalloc(store_pool, sizeof(struct filestore_data));
  store->keystore_data = store_data;

  store_data->path = path;
  store_data->fp = fp;
  store_data->lineno = 0;

  return store;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sftp_openssh_mod_unload_ev(const void *event_data,
    void *user_data) {
  if (strcmp("mod_sftp_openssh.c", (const char *) event_data) != 0) {
    return;
  }

  sftp_keystore_unregister_store("openssh", SFTP_SSH2_USER_KEY_STORE);
  pr_event_unregister(&sftp_openssh_module, NULL, NULL);
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int sftp_openssh_init(void) {
  sftp_keystore_register_store("openssh", openssh_open,
    SFTP_SSH2_USER_KEY_STORE);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&sftp_openssh_module, "core.module-unload",
    sftp_openssh_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module sftp_openssh_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "sftp_openssh",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  sftp_openssh_init,

  /* Module child initialization function */
  NULL,

  /* Module version */
  MOD_SFTP_OPENSSH_VERSION
};
