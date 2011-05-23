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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* for TCP_NODELAY */
#endif

#if defined(HAVE_TIME_H)
#include <time.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

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

#include "mperio.h"

/*
** MperIO status:
**
** - idle: not running and have never run
**
** - running: currently running (client called MperIO#start)
**
** - suspended: suspended event processing upon request (client called
**            MperIO#suspend)
**
** - stopped: fully handled stop request (triggered by client calling
**            MperIO#stop); the stopped status is persistent across runs,
**            so a stopped status may mean the previous MperIO run finished
**
** - error: some error occurred (and MperIO will be stopping)
**
*/
typedef enum {
  MPERIO_IDLE=0, MPERIO_RUNNING, MPERIO_SUSPENDED, MPERIO_STOPPED, MPERIO_ERROR
} mperio_status_t;

typedef struct {
  VALUE delegate;  /* cache of @delegate for speed */
  FILE *log;       /* may be NULL if the user didn't request logging */
  mperio_status_t status;
  int suspend_requested;  /* whether client called MperIO#suspend */
  int stop_requested;  /* whether client called MperIO#stop */

  int mper_fd;
  scamper_fd_t *mper_fdn;  /* wraps mper_fd */
  scamper_linepoll_t *lp;
  scamper_writebuf_t *wb;
  control_word_t words[MPER_MSG_MAX_WORDS];
  uint8_t read_buf[8192];

  int external_sources_count;
  int external_source_original_fd[FD_SETSIZE];  /* dup fd => original fd */
  scamper_fd_t *external_sources[FD_SETSIZE];   /* original fd => fdn */

} mperio_data_t;


static VALUE cMperIO, cPingResult;

static ID iv_delegate, iv_reqnum, iv_responded, iv_probe_src, iv_probe_dest;
static ID iv_udata, iv_tx_sec, iv_tx_usec, iv_rx_sec, iv_rx_usec;
static ID iv_probe_ttl, iv_probe_ipid, iv_reply_src, iv_reply_ttl;
static ID iv_reply_qttl, iv_reply_ipid, iv_reply_icmp, iv_reply_tcp;
static ID iv_reply_tsps_ts1, iv_reply_tsps_ip1;
static ID iv_reply_tsps_ts2, iv_reply_tsps_ip2;
static ID iv_reply_tsps_ts3, iv_reply_tsps_ip3;
static ID iv_reply_tsps_ts4, iv_reply_tsps_ip4;

static ID meth_setup_source_state, meth_prepare_sources;
static ID meth_source_read_data, meth_source_write_data;

static ID meth_mperio_on_more, meth_mperio_on_data;
static ID meth_mperio_on_error, meth_mperio_on_send_error;
static ID meth_mperio_service_failure;

static int connect_to_mper(int port, int use_tcp);
static const char* extract_txt_option(mperio_data_t *data,
				      const control_word_t *resp_words,
				      size_t word_count, const char *message);
static void handle_mper_ping_response(mperio_data_t *data,
				      const control_word_t *resp_words,
				      size_t word_count, const char *message);
static void send_command(mperio_data_t *data, const char *message);
static void report_error(mperio_data_t *data, const char *msg_start,
			 uint32_t reqnum, const char *msg_end);
static void report_send_error(mperio_data_t *data, const char *msg_start,
			      uint32_t reqnum, const char *msg_end);
static VALUE create_error_message(const char *msg_start, const char *msg_end);

/*=========================================================================*/

/* Read callback for data->mper_fdn. */
static void
mperio_read_cb(int fd, void *param)
{
  mperio_data_t *data = (mperio_data_t *)param;
  ssize_t n;

  if (data->status != MPERIO_RUNNING) return;

  assert(scamper_fd_fd_get(data->mper_fdn) == fd);

  n = read(fd, data->read_buf, sizeof(data->read_buf));
  if (n < 0) {
    if (errno != EAGAIN && errno != EINTR) {
      int errno_saved = errno;
#ifndef NDEBUG
      printerror(errno, strerror, __func__, "read failed");
#endif
      scamper_fd_read_pause(data->mper_fdn);
      scamper_fd_write_pause(data->mper_fdn);
      data->status = MPERIO_ERROR;

      { char buf[256];
	snprintf(buf, sizeof(buf), "error reading from mper: %s",
		 strerror(errno_saved));
	rb_funcall(data->delegate, meth_mperio_service_failure, 1,
		   rb_str_new2(buf));
      }
    }
  }
  else if (n > 0) {
    scamper_linepoll_handle(data->lp, data->read_buf, (size_t)n);
  }
  else {  /* n == 0 */
    scamper_fd_read_pause(data->mper_fdn);
    scamper_fd_write_pause(data->mper_fdn);

    /* XXX what else needs to be done on EOF? */

    if (!data->stop_requested) {
      data->status = MPERIO_ERROR;
      rb_funcall(data->delegate, meth_mperio_service_failure, 1,
		 rb_str_new2("lost connection to mper"));
    }
  }
}


/* Callback for data->lp.  Receives a single line per call. */
static int
mperio_read_line_cb(void *param, uint8_t *buf, size_t len)
{
  mperio_data_t *data = (mperio_data_t *)param;
  const control_word_t *resp_words = NULL;
  size_t word_count = 0;

  if (data->status != MPERIO_RUNNING) return 0;

  if (data->log) {
    fprintf(data->log, "<< %s\n", (char *)buf);
  }

  if (strcmp((char *)buf, "MORE") == 0) {
    rb_funcall(data->delegate, meth_mperio_on_more, 0);
  }
  else if (strcmp((char *)buf, "bye!") == 0) {
    assert(data->stop_requested);
    data->status = MPERIO_STOPPED;
  }
  else {
    resp_words = parse_control_message((char *)buf, &word_count);
    if (word_count == 0) {
      report_error(data, "couldn't parse mper response", resp_words[0].cw_uint,
		   resp_words[1].cw_str);
    }
    else {
      switch (resp_words[1].cw_code) {
      case KC_CMD_ERROR_CMD:
	{ const char *txt = extract_txt_option(data, resp_words,
					       word_count, (char *)buf);
	  report_error(data, "mper couldn't process our command",
		       resp_words[0].cw_uint, txt);
	}
	break;

      case KC_SEND_ERROR_CMD:
	{ const char *txt = extract_txt_option(data, resp_words,
					       word_count, (char *)buf);
	  report_send_error(data, "send error", resp_words[0].cw_uint, txt);
	}
	break;

      case KC_RESP_TIMEOUT_CMD:
      case KC_PING_RESP_CMD:
	handle_mper_ping_response(data, resp_words, word_count, (char *)buf);
	break;

      default:
	{ char error_msg[128];
	  snprintf(error_msg, sizeof(error_msg),
		   "INTERNAL ERROR: unexpected response code %d from mper",
		   resp_words[1].cw_code);
	  report_error(data, error_msg, resp_words[0].cw_uint, (char *)buf);
	}
	break;
      }
    }
  }

  return 0;  /* the return value isn't used in any way */
}


static const char*
extract_txt_option(mperio_data_t *data, const control_word_t *resp_words,
		   size_t word_count, const char *message)
{
  size_t i;

  for (i = 2; i < word_count; i++) {
    if (resp_words[i].cw_code == KC_TXT_OPT) {
      return resp_words[i].cw_str;
    }
  }

  /* This shouldn't happen, but I'm not sure reporting an internal error
     via report_error() is the right thing to do. */
  return "<<mper error message unavailable>>";
}


static void
handle_mper_ping_response(mperio_data_t *data, const control_word_t *resp_words,
			  size_t word_count, const char *message)
{
  VALUE result;
  size_t i;

  assert(resp_words[1].cw_code == KC_RESP_TIMEOUT_CMD ||
	 resp_words[1].cw_code == KC_PING_RESP_CMD);

  result = rb_class_new_instance(0, NULL, cPingResult);
  rb_ivar_set(result, iv_reqnum, ULONG2NUM(resp_words[0].cw_uint));
  rb_ivar_set(result, iv_responded,
	      (resp_words[1].cw_code == KC_PING_RESP_CMD ? Qtrue : Qfalse));

  for (i = 2; i < word_count; i++) {
    switch (resp_words[i].cw_code) {
    case KC_SRC_OPT:
      rb_ivar_set(result, iv_probe_src, rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_DEST_OPT:
      rb_ivar_set(result, iv_probe_dest, rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_UDATA_OPT:
      rb_ivar_set(result, iv_udata, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_TX_OPT:
      rb_ivar_set(result, iv_tx_sec,
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      rb_ivar_set(result, iv_tx_usec,
		  ULONG2NUM(resp_words[i].cw_timeval.tv_usec));
      break;

    case KC_RX_OPT:
      rb_ivar_set(result, iv_rx_sec,
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      rb_ivar_set(result, iv_rx_usec,
		  ULONG2NUM(resp_words[i].cw_timeval.tv_usec));
      break;

    case KC_PROBE_TTL_OPT:
      rb_ivar_set(result, iv_probe_ttl, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_PROBE_IPID_OPT:
      rb_ivar_set(result, iv_probe_ipid, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_SRC_OPT:
      rb_ivar_set(result, iv_reply_src, rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_REPLY_TTL_OPT:
      rb_ivar_set(result, iv_reply_ttl, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_IPID_OPT:
      rb_ivar_set(result, iv_reply_ipid, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_ICMP_OPT:
      rb_ivar_set(result, iv_reply_icmp, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_QTTL_OPT:
      rb_ivar_set(result, iv_reply_qttl, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_TCP_OPT:
      rb_ivar_set(result, iv_reply_tcp, ULONG2NUM(resp_words[i].cw_uint));
      break;

    case KC_REPLY_TSPS_TS1_OPT:
      rb_ivar_set(result, iv_reply_tsps_ts1, 
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      break;

    case KC_REPLY_TSPS_IP1_OPT:
      rb_ivar_set(result, iv_reply_tsps_ip1, 
		  rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_REPLY_TSPS_TS2_OPT:
      rb_ivar_set(result, iv_reply_tsps_ts2, 
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      break;

    case KC_REPLY_TSPS_IP2_OPT:
      rb_ivar_set(result, iv_reply_tsps_ip2, 
		  rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_REPLY_TSPS_TS3_OPT:
      rb_ivar_set(result, iv_reply_tsps_ts3, 
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      break;

    case KC_REPLY_TSPS_IP3_OPT:
      rb_ivar_set(result, iv_reply_tsps_ip3, 
		  rb_str_new2(resp_words[i].cw_address));
      break;

    case KC_REPLY_TSPS_TS4_OPT:
      rb_ivar_set(result, iv_reply_tsps_ts4, 
		  ULONG2NUM(resp_words[i].cw_timeval.tv_sec));
      break;

    case KC_REPLY_TSPS_IP4_OPT:
      rb_ivar_set(result, iv_reply_tsps_ip4, 
		  rb_str_new2(resp_words[i].cw_address));
      break;

    default:
      { char error_msg[128];
	snprintf(error_msg, sizeof(error_msg),
		 "INTERNAL ERROR: unexpected response option %d from mper",
		 resp_words[i].cw_code);
	report_error(data, error_msg, resp_words[0].cw_uint, message);
      }
      return;
    }
  }

  rb_funcall(data->delegate, meth_mperio_on_data, 1, result);
}


/* Callback for data->wb: error while writing to data->mper_fdn. */
static void
mperio_write_error_cb(void *param, int err, scamper_writebuf_t *wb)
{
  mperio_data_t *data = (mperio_data_t *)param;
  char buf[256];

  data->status = MPERIO_ERROR;

#ifndef NDEBUG
  printerror(err, strerror, __func__, "write failed");
#endif

  snprintf(buf, sizeof(buf), "error writing to mper: %s", strerror(err));
  rb_funcall(data->delegate, meth_mperio_service_failure, 1,
	     rb_str_new2(buf));
}


/*
 * client_drained
 *
 * this callback is called when the client's writebuf is empty.
 * the point being to check when the client has had all its output sent
 * and it can be cleaned up
 */
/* Callback for data->wb: all queued data written out to data->mper_fdn. */
static void
mperio_write_drained_cb(void *param, scamper_writebuf_t *wb)
{
  /* mperio_data_t *data = (mperio_data_t *)param; */

  /* XXX */
}


/*=========================================================================*/

static void
mperio_free(void *data)
{
  mperio_data_t *mperio_data = (mperio_data_t *)data;
  int i;

  if (mperio_data) {
    if(mperio_data->wb != NULL) {
      scamper_writebuf_free(mperio_data->wb);
      mperio_data->wb = NULL;
    }

    /* XXX flush linepoll? (set 2nd argument to 1 to flush) */
    if(mperio_data->lp != NULL) {
      scamper_linepoll_free(mperio_data->lp, 0);
      mperio_data->lp = NULL;
    }

    if (mperio_data->mper_fdn) {
      scamper_fd_free(mperio_data->mper_fdn);
      mperio_data->mper_fdn = NULL;
    }

    if (mperio_data->mper_fd >= 0) {
      close(mperio_data->mper_fd);
      mperio_data->mper_fd = -1;
    }

    if (mperio_data->log) {
      fclose(mperio_data->log);
      mperio_data->log = NULL;
    }

    for (i = 0; i < FD_SETSIZE; i++) {
      if (mperio_data->external_sources[i]) {
	scamper_fd_free(mperio_data->external_sources[i]);
      }
    }
  }
}

static VALUE
mperio_alloc(VALUE klass)
{
  return Data_Wrap_Struct(klass, 0, mperio_free, 0);
}


static VALUE
mperio_init(int argc, VALUE *argv, VALUE self)
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
  data->delegate = Qnil;
  data->log = log;
  data->status = MPERIO_IDLE;
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
	rb_funcall(self, meth_setup_source_state, 0);
	if (data->log) {
	  time_t now = time(NULL);
	  fprintf(data->log, "INIT %ld %s", (long)now, ctime(&now));
	}
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


static int
connect_to_mper(int port, int use_tcp)
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


static VALUE
mperio_set_delegate(VALUE self, VALUE delegate)
{
  mperio_data_t *data = NULL;

  Data_Get_Struct(self, mperio_data_t, data);
  if (NIL_P(delegate) && data->status != MPERIO_IDLE) {
    rb_raise(rb_eRuntimeError,
	     "delegate cannot be set to nil after MperIO has started");
  }

  /* Set the instance variable so that the delegate is retained by the GC. */
  rb_ivar_set(self, iv_delegate, delegate);
  data->delegate = delegate;  /* for performance while invoking callbacks */
  return self;
}


static VALUE
mperio_start(VALUE self)
{
  mperio_data_t *data = NULL;
  struct timeval tv;
  VALUE retval;

  Data_Get_Struct(self, mperio_data_t, data);
  if (NIL_P(data->delegate)) {
    rb_raise(rb_eRuntimeError, "no delegate set");
  }

  switch (data->status) {
  case MPERIO_IDLE:
  case MPERIO_SUSPENDED:
    if (data->log) {
      time_t now = time(NULL);
      const char *event = (data->status == MPERIO_IDLE ? "START" : "RESUME");
      fprintf(data->log, "%s %ld %s", event, (long)now, ctime(&now));
    }

    scamper_fd_read_set(data->mper_fdn, mperio_read_cb, data);
    scamper_fd_read_unpause(data->mper_fdn);

    if (data->status == MPERIO_SUSPENDED) {
      data->status = MPERIO_RUNNING;
      rb_funcall(data->delegate, meth_mperio_on_more, 0);
    }
    else {
      data->status = MPERIO_RUNNING;
    }

    while (data->status == MPERIO_RUNNING) {
      if (data->external_sources_count > 0) {
	rb_funcall(self, meth_prepare_sources, 0);
	if (data->suspend_requested) {  /* support suspend_on_idle feature */
	  data->status = MPERIO_SUSPENDED;
	  data->suspend_requested = 0;
	  break;
	}
      }

      tv.tv_sec = 3;
      tv.tv_usec = 0;
      if (scamper_fds_poll(&tv) < 0) {
	data->status = MPERIO_ERROR;
	rb_funcall(data->delegate, meth_mperio_service_failure, 1,
		   rb_str_new2("select() failed"));
      }

      if (data->status == MPERIO_RUNNING && data->suspend_requested) {
	data->status = MPERIO_SUSPENDED;
	data->suspend_requested = 0;
      }
    }

    if (data->log) {
      time_t now = time(NULL);
      const char *event =
	(data->status == MPERIO_SUSPENDED ? "SUSPEND" : "STOP");
      fprintf(data->log, "%s %ld %s", event, (long)now, ctime(&now));
    }

    if (data->status == MPERIO_SUSPENDED) {
      retval = Qtrue;
    }
    else {
      mperio_free(data);
      retval = (data->status == MPERIO_STOPPED ? Qtrue : Qnil);
      data->status = MPERIO_STOPPED;
      data->stop_requested = 0;
    }
    return retval;

  case MPERIO_RUNNING:
    rb_raise(rb_eRuntimeError, "MperIO is already running");

  case MPERIO_STOPPED:
    rb_raise(rb_eRuntimeError,
	     "MperIO cannot be restarted after being stopped");

  case MPERIO_ERROR:
    rb_raise(rb_eRuntimeError, "MperIO cannot be restarted after an error");

  default:
    rb_fatal("INTERNAL ERROR: invalid MperIO status");
  }
}


static VALUE
mperio_suspend(VALUE self)
{
  mperio_data_t *data = NULL;

  Data_Get_Struct(self, mperio_data_t, data);
  if (data->status == MPERIO_RUNNING && !data->suspend_requested
      && !data->stop_requested) {
    if (data->log) {
      time_t now = time(NULL);
      fprintf(data->log, "SUSPEND_REQUEST %ld %s", (long)now, ctime(&now));
    }
    data->suspend_requested = 1;
  }
  return self;
}


static VALUE
mperio_stop(VALUE self)
{
  mperio_data_t *data = NULL;

  Data_Get_Struct(self, mperio_data_t, data);
  if (data->status == MPERIO_RUNNING && !data->stop_requested) {
    if (data->log) {
      time_t now = time(NULL);
      fprintf(data->log, "STOP_REQUEST %ld %s", (long)now, ctime(&now));
    }
    send_command(data, "done");
    data->suspend_requested = 0;  /* stop overrides any pending suspend */
    data->stop_requested = 1;
  }
  return self;
}


static VALUE
mperio_ping_icmp(int argc, VALUE *argv, VALUE self)
{
  mperio_data_t *data = NULL;
  VALUE vreqnum, vdest, vspacing, vtsps;
  uint32_t reqnum, spacing;
  int rtspsc = 0;
  VALUE *rtsps = NULL;
  char *tspsaddr = NULL;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;
  int i;
  int opt_cnt = 3; /* the first optional option */

  Data_Get_Struct(self, mperio_data_t, data);
  rb_scan_args(argc, argv, "22", &vreqnum, &vdest, &vspacing, &vtsps);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  spacing = (NIL_P(vspacing) ? 0 : (uint32_t)NUM2UINT(vspacing));
  if (spacing > 2147483647) { spacing = 2147483647; }

  if(!NIL_P(vtsps) && rb_type(vtsps) == T_ARRAY)
    {
      rtsps = RARRAY_PTR(RARRAY(vtsps));
      rtspsc = RARRAY_LEN(RARRAY(vtsps));
    }

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "icmp-echo");

  if (spacing > 0) 
    {
      SET_UINT_CWORD(data->words, opt_cnt, SPACING, spacing);
      opt_cnt++;
    }

  for(i=0;i<rtspsc;i++)
    {
      if(rb_type(rtsps[i]) == T_STRING)
	{
	  StringValue(rtsps[i]);
	  tspsaddr = RSTRING_PTR(rtsps[i]);
	  switch (i) 
	    {
	    case 0:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP1, tspsaddr);
	      opt_cnt++;
	      break;

	    case 1:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP2, tspsaddr);
	      opt_cnt++;
	      break;
	      
	    case 2:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP3, tspsaddr);
	      opt_cnt++;
	      break;

	    case 3:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP4, tspsaddr);
	      opt_cnt++;
	      break;
	    }
	}
    }

  msg = create_control_message(data->words, CMESSAGE_LEN(opt_cnt-1),
			       &msg_len);

  assert(msg_len != 0);
  send_command(data, msg);
  return self;
}


static VALUE
mperio_ping_icmp_indir(int argc, VALUE *argv, VALUE self)
{
  mperio_data_t *data = NULL;
  VALUE vreqnum, vdest, vhop, vcksum, vspacing, vtsps;
  uint32_t reqnum, hop, cksum, spacing;
  int rtspsc = 0;
  VALUE *rtsps = NULL;
  char *tspsaddr = NULL;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;
  int i;
  int opt_cnt = 5; /* the first optional option */

  Data_Get_Struct(self, mperio_data_t, data);
  rb_scan_args(argc, argv, "42", 
	       &vreqnum, &vdest, &vhop, &vcksum, &vspacing, &vtsps);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  hop = (uint32_t)NUM2ULONG(vhop);
  cksum = (uint32_t)NUM2ULONG(vcksum);
  spacing = (NIL_P(vspacing) ? 0 : (uint32_t)NUM2UINT(vspacing));
  if (spacing > 2147483647) { spacing = 2147483647; }

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "icmp-echo");
  SET_UINT_CWORD(data->words, 3, TTL, hop);
  SET_UINT_CWORD(data->words, 4, CKSUM, cksum);
  if (spacing > 0)
    {
      SET_UINT_CWORD(data->words, opt_cnt, SPACING, spacing);
      opt_cnt++;
    }

  for(i=0;i<rtspsc;i++)
    {
      if(rb_type(rtsps[i]) == T_STRING)
	{
	  StringValue(rtsps[i]);
	  tspsaddr = RSTRING_PTR(rtsps[i]);
	  switch (i) 
	    {
	    case 0:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP1, tspsaddr);
	      opt_cnt++;
	      break;

	    case 1:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP2, tspsaddr);
	      opt_cnt++;
	      break;
	      
	    case 2:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP3, tspsaddr);
	      opt_cnt++;
	      break;

	    case 3:
	      SET_ADDRESS_CWORD(data->words, opt_cnt, TSPS_IP4, tspsaddr);
	      opt_cnt++;
	      break;
	    }
	}
    }

  msg = create_control_message(data->words, CMESSAGE_LEN(opt_cnt-1),
			       &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);
  return self;
}


static VALUE
mperio_ping_tcp(int argc, VALUE *argv, VALUE self)
{
  mperio_data_t *data = NULL;
  VALUE vreqnum, vdest, vdport, vspacing;
  uint32_t reqnum, dport, spacing;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;

  Data_Get_Struct(self, mperio_data_t, data);
  rb_scan_args(argc, argv, "31", &vreqnum, &vdest, &vdport, &vspacing);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  dport = (uint32_t)NUM2ULONG(vdport);
  spacing = (NIL_P(vspacing) ? 0 : (uint32_t)NUM2UINT(vspacing));
  if (spacing > 2147483647) { spacing = 2147483647; }

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "tcp-ack");
  SET_UINT_CWORD(data->words, 3, DPORT, dport);
  if (spacing > 0) SET_UINT_CWORD(data->words, 4, SPACING, spacing);

  msg = create_control_message(data->words, CMESSAGE_LEN(spacing > 0 ? 4 : 3),
			       &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);
  return self;
}


static VALUE
mperio_ping_udp(int argc, VALUE *argv, VALUE self)
{
  mperio_data_t *data = NULL;
  VALUE vreqnum, vdest, vspacing;
  uint32_t reqnum, spacing;
  const char *dest;
  const char *msg = NULL;
  size_t msg_len = 0;

  Data_Get_Struct(self, mperio_data_t, data);
  rb_scan_args(argc, argv, "21", &vreqnum, &vdest, &vspacing);

  reqnum = (uint32_t)NUM2ULONG(vreqnum);
  StringValue(vdest);
  dest = RSTRING_PTR(vdest);
  spacing = (NIL_P(vspacing) ? 0 : (uint32_t)NUM2UINT(vspacing));
  if (spacing > 2147483647) { spacing = 2147483647; }

  INIT_CMESSAGE(data->words, reqnum, PING);
  SET_ADDRESS_CWORD(data->words, 1, DEST, dest);
  SET_SYMBOL_CWORD(data->words, 2, METH, "udp");
  if (spacing > 0) SET_UINT_CWORD(data->words, 3, SPACING, spacing);

  msg = create_control_message(data->words, CMESSAGE_LEN(spacing > 0 ? 3 : 2),
			       &msg_len);
  assert(msg_len != 0);
  send_command(data, msg);
  return self;
}


static VALUE
mperio_send_raw_command(VALUE self, VALUE command)
{
  mperio_data_t *data = NULL;

  Data_Get_Struct(self, mperio_data_t, data);

  StringValue(command);
  send_command(data, RSTRING_PTR(command));
  return self;
}


static void
send_command(mperio_data_t *data, const char *message)
{
  if (data->log) {
    fprintf(data->log, ">> %s\n", message);
  }

  /* XXX somewhat inefficient to do a separate send for just the newline */
  scamper_writebuf_send(data->wb, message, strlen(message));
  scamper_writebuf_send(data->wb, "\n", 1);
}


static void
report_error(mperio_data_t *data, const char *msg_start, uint32_t reqnum,
	     const char *msg_end)
{
  VALUE msg = create_error_message(msg_start, msg_end);
  rb_funcall(data->delegate, meth_mperio_on_error, 2, ULONG2NUM(reqnum), msg);
}


static void
report_send_error(mperio_data_t *data, const char *msg_start, uint32_t reqnum,
		  const char *msg_end)
{
  VALUE msg = create_error_message(msg_start, msg_end);
  rb_funcall(data->delegate, meth_mperio_on_send_error, 2,
	     ULONG2NUM(reqnum), msg);
}


static VALUE
create_error_message(const char *msg_start, const char *msg_end)
{
  size_t len = strlen(msg_start) + 2 + strlen(msg_end);
  char *buf;
  VALUE retval;

  buf = ALLOC_N(char, len + 1);
  strcpy(buf, msg_start);
  strcat(buf, ": ");
  strcat(buf, msg_end);

  retval = rb_str_new2(buf);
  free(buf);

  return retval;
}


/***************************************************************************/

static void
external_source_read_cb(const int fd, void *param)
{
  VALUE self = (VALUE)param;
  mperio_data_t *data = NULL;
  int original_fd;

  Data_Get_Struct(self, mperio_data_t, data);

  original_fd = data->external_source_original_fd[fd];
  rb_funcall(self, meth_source_read_data, 1, INT2FIX(original_fd));
}


static void
external_source_write_cb(const int fd, void *param)
{
  VALUE self = (VALUE)param;
  mperio_data_t *data = NULL;
  int original_fd;

  Data_Get_Struct(self, mperio_data_t, data);

  original_fd = data->external_source_original_fd[fd];
  rb_funcall(self, meth_source_write_data, 1, INT2FIX(original_fd));
}


static VALUE
mperio_allocate_scamper_fdn(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd, fd_dup;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  fd_dup = dup(fd);
  if (fd_dup < 0) {
    rb_sys_fail(NULL);
  }

  data->external_sources_count += 1;
  data->external_source_original_fd[fd_dup] = fd;
  data->external_sources[fd] = scamper_fd_private(fd_dup,
                                      external_source_read_cb, (void*)self,
                                      external_source_write_cb, (void*)self);

  scamper_fd_read_pause(data->external_sources[fd]);
  scamper_fd_write_pause(data->external_sources[fd]);
  return self;
}


static VALUE
mperio_deallocate_scamper_fdn(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  if (fd <= 0 || fd >= FD_SETSIZE || !data->external_sources[fd]) {
    rb_raise(rb_eArgError, "invalid file descriptor");
  }

  data->external_sources_count -= 1;
  scamper_fd_free(data->external_sources[fd]);
  data->external_sources[fd] = NULL;
  return self;
}


static VALUE
mperio_read_pause(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  if (fd <= 0 || fd >= FD_SETSIZE || !data->external_sources[fd]) {
    rb_raise(rb_eArgError, "invalid file descriptor");
  }

  scamper_fd_read_pause(data->external_sources[fd]);
  return self;
}


static VALUE
mperio_read_unpause(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  if (fd <= 0 || fd >= FD_SETSIZE || !data->external_sources[fd]) {
    rb_raise(rb_eArgError, "invalid file descriptor");
  }

  scamper_fd_read_unpause(data->external_sources[fd]);
  return self;
}


static VALUE
mperio_write_pause(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  if (fd <= 0 || fd >= FD_SETSIZE || !data->external_sources[fd]) {
    rb_raise(rb_eArgError, "invalid file descriptor");
  }

  scamper_fd_write_pause(data->external_sources[fd]);
  return self;
}


static VALUE
mperio_write_unpause(VALUE self, VALUE fd_value)
{
  mperio_data_t *data = NULL;
  int fd;

  Data_Get_Struct(self, mperio_data_t, data);

  fd = FIX2INT(fd_value);
  if (fd <= 0 || fd >= FD_SETSIZE || !data->external_sources[fd]) {
    rb_raise(rb_eArgError, "invalid file descriptor");
  }

  scamper_fd_write_unpause(data->external_sources[fd]);
  return self;
}


/***************************************************************************/
/***************************************************************************/

#define IV_INTERN(name) iv_##name = rb_intern("@" #name)
#define METH_INTERN(name) meth_##name = rb_intern(#name)

void
Init_mperio(void)
{
  ID private_class_method_ID, private_ID;
  ID /*new_ID,*/ dup_ID, clone_ID;

  IV_INTERN(delegate);
  IV_INTERN(reqnum);
  IV_INTERN(responded);
  IV_INTERN(probe_src);
  IV_INTERN(probe_dest);
  IV_INTERN(udata);
  IV_INTERN(tx_sec);
  IV_INTERN(tx_usec);
  IV_INTERN(rx_sec);
  IV_INTERN(rx_usec);
  IV_INTERN(probe_ttl);
  IV_INTERN(probe_ipid);
  IV_INTERN(reply_src);
  IV_INTERN(reply_ttl);
  IV_INTERN(reply_qttl);
  IV_INTERN(reply_tsps_ts1);
  IV_INTERN(reply_tsps_ip1);
  IV_INTERN(reply_tsps_ts2);
  IV_INTERN(reply_tsps_ip2);
  IV_INTERN(reply_tsps_ts3);
  IV_INTERN(reply_tsps_ip3);
  IV_INTERN(reply_tsps_ts4);
  IV_INTERN(reply_tsps_ip4);
  IV_INTERN(reply_ipid);
  IV_INTERN(reply_icmp);
  IV_INTERN(reply_tcp);

  METH_INTERN(setup_source_state);
  METH_INTERN(prepare_sources);
  METH_INTERN(source_read_data);
  METH_INTERN(source_write_data);

  METH_INTERN(mperio_on_more);
  METH_INTERN(mperio_on_data);
  METH_INTERN(mperio_on_error);
  METH_INTERN(mperio_on_send_error);
  METH_INTERN(mperio_service_failure);

  /* XXX make MperIO a singleton */
  /* XXX fix message creation/parsing routines to not use static buffers */

  cMperIO = rb_define_class("MperIO", rb_cObject);

  rb_define_alloc_func(cMperIO, mperio_alloc);

  rb_define_method(cMperIO, "initialize", mperio_init, -1);
  rb_define_method(cMperIO, "delegate=", mperio_set_delegate, 1);
  rb_define_method(cMperIO, "start", mperio_start, 0);
  rb_define_method(cMperIO, "suspend", mperio_suspend, 0);
  rb_define_method(cMperIO, "stop", mperio_stop, 0);
  rb_define_method(cMperIO, "ping_icmp", mperio_ping_icmp, -1);
  rb_define_method(cMperIO, "ping_icmp_indir", mperio_ping_icmp_indir, -1);
  rb_define_method(cMperIO, "ping_tcp", mperio_ping_tcp, -1);
  rb_define_method(cMperIO, "ping_udp", mperio_ping_udp, -1);
  rb_define_method(cMperIO, "send_raw_command", mperio_send_raw_command, 1);

  /* XXX make private */
  rb_define_method(cMperIO, "allocate_scamper_fdn",
		   mperio_allocate_scamper_fdn, 1);
  rb_define_method(cMperIO, "deallocate_scamper_fdn",
		   mperio_deallocate_scamper_fdn, 1);
  rb_define_method(cMperIO, "read_pause", mperio_read_pause, 1);
  rb_define_method(cMperIO, "read_unpause", mperio_read_unpause, 1);
  rb_define_method(cMperIO, "write_pause", mperio_write_pause, 1);
  rb_define_method(cMperIO, "write_unpause", mperio_write_unpause, 1);

  private_class_method_ID = rb_intern("private_class_method");
  private_ID = rb_intern("private");
  /* new_ID = rb_intern("new"); */
  dup_ID = rb_intern("dup");
  clone_ID = rb_intern("clone");

  /* rb_funcall(cMperIO, private_class_method_ID, 1, ID2SYM(new_ID)); */
  rb_funcall(cMperIO, private_ID, 1, ID2SYM(dup_ID));
  rb_funcall(cMperIO, private_ID, 1, ID2SYM(clone_ID));

  /*
  ** The actual declaration of PingResult happens in lib/mperio.rb,
  ** but we need a VALUE of it so that we can create instances.
  */
  cPingResult = rb_define_class_under(cMperIO, "PingResult", rb_cObject);
}
