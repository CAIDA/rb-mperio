##===========================================================================
## Copyright (C) 2007,2009 The Regents of the University of California.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
## 
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##===========================================================================

require 'rbconfig'
Config::MAKEFILE_CONFIG['CFLAGS'] += " -DNDEBUG -Wall"

require 'mkmf'

have_stdint = have_header("stdint.h")
have_unistd = have_header("unistd.h")
have_time = have_header("time.h")

common_headers = []
common_headers << "stdint.h" if have_stdint
common_headers << "unistd.h" if have_unistd
common_headers << "time.h" if have_time

create_makefile("mperioext")
