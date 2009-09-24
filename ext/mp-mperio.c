/*
** Ruby bindings to the mper messaging routines.
**
** --------------------------------------------------------------------------
** Author: Young Hyun
** Copyright (C) 2008, 2009 The Regents of the University of California.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
** $Id: scping.c,v 1.25 2009/04/24 22:52:55 youngh Exp $
**/

#include "systypes.h"

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#include <process.h>
#define close _close
#define read _read
#define snprintf _snprintf
#define strcasecmp _stricmp
#define SHUT_RDWR SD_BOTH
#define O_NONBLOCK _O_NONBLOCK
#endif

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* for TCP_NODELAY */
#include <unistd.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#include "ruby.h"
#include "compat.h"

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_msg_writer.h"

#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "utils.h"

#include "mp-mperio.h"

typedef struct {
  FILE *log;  /* may be NULL if the user didn't request logging */
  int mper_fd;
  scamper_fd_t *mper_fdn;  /* wraps mper_fd */
  scamper_linepoll_t *lp;
  scamper_writebuf_t *wb;
  control_word_t words[MPER_MSG_MAX_WORDS];
  uint8_t read_buf[8192];
} mperio_data_t;

static VALUE cMperIO;

/*=========================================================================*/

static void send_command(mperio_data_t *data, const char *message)
{
  /* XXX somewhat inefficient to do a separate send for just the newline */
  scamper_writebuf_send(data->wb, message, strlen(message));
  scamper_writebuf_send(data->wb, "\n", 1);
}


/*=========================================================================*/

/* Read callback for data->mper_fdn. */
static void mperio_read_cb(int fd, void *param)
{
  mperio_data_t *data = (mperio_data_t *)param;
  ssize_t n;

  assert(scamper_fd_fd_get(data->mper_fdn) == fd);

  n = read(fd, data->read_buf, sizeof(data->read_buf));
  if (n < 0) {
    if (errno != EAGAIN && errno != EINTR) {
      /* XXX call client's error callback */
      printerror(errno, strerror, __func__, "read failed");
      scamper_fd_read_pause(data->mper_fdn);
    }
  }
  else if (n > 0) {
    scamper_linepoll_handle(data->lp, data->read_buf, (size_t)n);
  }
  else {  /* n == 0 */
    scamper_fd_read_pause(data->mper_fdn);
  }
}


/* Callback for data->lp.  Receives a single line per call. */
static int mperio_read_line_cb(void *param, uint8_t *buf, size_t len)
{
  mperio_data_t *data = (mperio_data_t *)param;

  /* XXX call client callback */

  return 0;  /* the return value isn't used in any way */
}


/* Callback for data->wb: error while writing to data->mper_fdn. */
static void mperio_write_error_cb(void *param, int err, scamper_writebuf_t *wb)
{
  mperio_data_t *data = (mperio_data_t *)param;

  /* XXX call client's error callback */

  printerror(err, strerror, __func__, "write failed");
}


/*
 * client_drained
 *
 * this callback is called when the client's writebuf is empty.
 * the point being to check when the client has had all its output sent
 * and it can be cleaned up
 */
/* Callback for data->wb: all queued data written out to data->mper_fdn. */
static void mperio_write_drained_cb(void *param, scamper_writebuf_t *wb)
{
  mperio_data_t *data = (mperio_data_t *)param;

  /* XXX */
}


/*=========================================================================*/

static void mperio_free(void *data)
{
  mperio_data_t *mperio_data = (mperio_data_t *)data;

  if (mperio_data) {
    if (mperio_data->log) fclose(mperio_data->log);
    if (mperio_data->mper_fd >= 0) close(mperio_data->mper_fd);
    if (mperio_data->mper_fdn) scamper_fd_free(mperio_data->mper_fdn);

    /* XXX flush linepoll? (set 2nd argument to 1 to flush) */
    if(mperio_data->lp != NULL) scamper_linepoll_free(mperio_data->lp, 0);
    if(mperio_data->wb != NULL) scamper_writebuf_free(mperio_data->wb);
  }
}

static VALUE mperio_alloc(VALUE klass)
{
  return Data_Wrap_Struct(klass, 0, mperio_free, 0);
}


static int connect_to_mper(int port, int use_tcp)
{
  struct sockaddr *sa = NULL;
  socklen_t sa_len;
  struct sockaddr_in sin;
  struct in_addr     in;
  int                fd = -1, opt;
#ifndef _WIN32
  struct sockaddr_un sun;
  int path_len;

  if(use_tcp)
#endif
  {
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
      rb_sys_fail("could not create TCP socket");
    }

    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
		   (char *)&opt, sizeof(opt)) != 0) {
      close(fd);
      rb_sys_fail("could not set TCP_NODELAY");
    }

    in.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);

    sa = (struct sockaddr *)&sin;
    sa_len = sizeof(sin);
  }
#ifndef _WIN32
  else
  {
    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
      rb_sys_fail("could not create unix socket");
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_LOCAL;
    path_len = snprintf(sun.sun_path, sizeof(sun.sun_path),
			"/tmp/mper.%d", port);
    if (path_len >= sizeof(sun.sun_path)) {
      close(fd);
      rb_fatal("INTERNAL ERROR: unix domain socket path too long for port %d",
	       port);
    }

    sa = (struct sockaddr *)&sun;
    sa_len = SUN_LEN(&sun);
  }
#endif

#ifndef _WIN32
  if (fcntl_set(fd, O_NONBLOCK) == -1) {
    close(fd);
    rb_sys_fail("could not set O_NONBLOCK on mper connection");
  }
#endif

  if (connect(fd, sa, sa_len) == -1) {
    close(fd);
    rb_sys_fail("could not connect to mper");
  }

  return fd;
}


static VALUE mperio_init(int argc, VALUE *argv, VALUE self)
{
  mperio_data_t *data = NULL;
  VALUE vport, vlog_path, vuse_tcp;
  int port, fd;
  FILE *log = NULL;

  rb_scan_args(argc, argv, "12", &vport, &vlog_path, &vuse_tcp);
  port = NUM2INT(vport);

  if (!NIL_P(vlog_path)) {
    SafeStringValue(vlog_path);
    if ((log = fopen(RSTRING_PTR(vlog_path), "a")) == NULL) {
      rb_sys_fail("could not open MperIO log file");
    }
  }

  fd = connect_to_mper(port, RTEST(vuse_tcp));
  assert(fd != -1);

  data = ALLOC(mperio_data_t);
  memset(data, 0, sizeof(mperio_data_t));
  data->log = log;
  data->mper_fd = fd;
  DATA_PTR(self) = data;

  data->mper_fdn = scamper_fd_private(fd, NULL, NULL, NULL, NULL);
  if (data->mper_fdn) {
    data->lp = scamper_linepoll_alloc(mperio_read_line_cb, data);
    if (data->lp) {
      data->wb = scamper_writebuf_alloc();
      if (data->wb) {
	scamper_writebuf_attach(data->wb, data->mper_fdn, data,
				mperio_write_error_cb,
				mperio_write_drained_cb);
	return self;
      }
      scamper_linepoll_free(data->lp, 0);
    }
    scamper_fd_free(data->mper_fdn);  /* doesn't close data->mper_fd */
  }

  if (data->log) fclose(data->log);
  close(data->mper_fd);
  free(data);
  DATA_PTR(self) = NULL;
  return Qnil;
}


static VALUE mperio_set_delegate(VALUE self, VALUE delegate)
{
  /* XXX */

  return self;
}


static VALUE mperio_start(VALUE self)
{
  /* XXX */

  return self;
}


static VALUE mperio_ping_icmp(VALUE self, VALUE vreqnum, VALUE vdest)
{
  mperio_data_t *data = NULL;
  uint32_t reqnum;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;

  Data_Get_Struct(self, mperio_data_t, data);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "icmp-echo");

  msg = create_control_message(data->words, CMESSAGE_LEN(2), &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);

  return self;
}


static VALUE mperio_ping_icmp_indir(VALUE self, VALUE vreqnum, VALUE vdest,
				    VALUE vhop, VALUE vcksum)
{
  mperio_data_t *data = NULL;
  uint32_t reqnum, hop, cksum;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;

  Data_Get_Struct(self, mperio_data_t, data);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  hop = (uint32_t)NUM2ULONG(vhop);
  cksum = (uint32_t)NUM2ULONG(vcksum);

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "icmp-echo");
  SET_UINT_CWORD(data->words, 3, PROBE_TTL, hop);
  SET_UINT_CWORD(data->words, 4, CKSUM, cksum);

  msg = create_control_message(data->words, CMESSAGE_LEN(4), &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);

  return self;
}


static VALUE mperio_ping_tcp(VALUE self, VALUE vreqnum, VALUE vdest,VALUE vdport)
{
  mperio_data_t *data = NULL;
  uint32_t reqnum, dport;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;

  Data_Get_Struct(self, mperio_data_t, data);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  dport = (uint32_t)NUM2ULONG(vdport);

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "tcp-ack");
  SET_UINT_CWORD(data->words, 3, DPORT, dport);

  msg = create_control_message(data->words, CMESSAGE_LEN(3), &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);

  return self;
}


/***************************************************************************/
/***************************************************************************/

void Init_mp_mperio(void)
{
  ID private_class_method_ID, private_ID;
  ID /*new_ID,*/ dup_ID, clone_ID;

  /* XXX make MperIO a singleton */
  /* XXX fix message creation/parsing routines to not use static buffers */

  cMperIO = rb_define_class("MperIO", rb_cObject);

  rb_define_alloc_func(cMperIO, mperio_alloc);

  rb_define_method(cMperIO, "initialize", mperio_init, -1);
  rb_define_method(cMperIO, "delegate=", mperio_set_delegate, 1);
  rb_define_method(cMperIO, "start", mperio_start, 0);
  rb_define_method(cMperIO, "ping_icmp", mperio_ping_icmp, 2);
  rb_define_method(cMperIO, "ping_icmp_indir", mperio_ping_icmp_indir, 4);
  rb_define_method(cMperIO, "ping_tcp", mperio_ping_tcp, 3);

  private_class_method_ID = rb_intern("private_class_method");
  private_ID = rb_intern("private");
  /* new_ID = rb_intern("new"); */
  dup_ID = rb_intern("dup");
  clone_ID = rb_intern("clone");

  /* rb_funcall(cMperIO, private_class_method_ID, 1, ID2SYM(new_ID)); */
  rb_funcall(cMperIO, private_ID, 1, ID2SYM(dup_ID));
  rb_funcall(cMperIO, private_ID, 1, ID2SYM(clone_ID));
}
