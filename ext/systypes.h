/*
 * A set of includes to pull in basic system-dependent types, especially
 * the C99 intN_t family of types.
 *
 *        Matthew Luckie, WAND Group, Computer Science, University of Waikato
 *        mjl@wand.net.nz
 *
 * Copyright (C) 2003-2009 The University of Waikato
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef int ssize_t;
typedef int pid_t;
typedef int socklen_t;
typedef int mode_t;
#define __func__ __FUNCTION__
#endif

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#endif

#include <sys/types.h>

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif
