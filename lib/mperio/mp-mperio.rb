#############################################################################
## Some additional methods of mperio classes.
##
## --------------------------------------------------------------------------
## Copyright (C) 2009 The Regents of the University of California.
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
##
## $Id: wl-trace.rb,v 1.12 2008/10/02 23:47:08 youngh Exp $
#############################################################################

# The MperIO delegate should implement the following methods:
#
#   * mperio_on_more
#       mper can accept more commands.
#
#       The MperIO client can invoke a method like ping_icmp to queue
#       additional measurements.
#
#   * mperio_on_data(ping_result)
#       mper returned a measurement result (in the form of a PingResult).
#
#   * mperio_on_error(reqnum, message)
#       There was an unrecoverable error either in MperIO or in mper.
#
#       If reqnum is 0, then there was some general error such as an I/O error.
#       Otherwise, there was an error processing a command/response with the
#       given reqnum.  The reqnum can also be zero if the command MperIO
#       issued to mper was so badly malformed that mper couldn't even parse
#       the reqnum, but this is highly unlikely to happen.
#
#   * mperio_on_send_error(reqnum, message)
#       mper couldn't send a probe for the measurement with the given reqnum.
#
#       There are legitimate reasons why there might be an occasional send
#       error, such as a lack of a route for a given destination (e.g.,
#       route had been withdrawn).  The MperIO client should treat a send
#       error similarly to a non-response.  However, an excessive number of
#       send errors may indicate a true problem in mper or in network
#       connectivity.
#
#   * mperio_service_failure(message)
#       The connection to mper was lost or failed in some way.

class MperIO

  class PingResult

    attr_reader :reqnum
    attr_reader :probe_src, :probe_dest, :udata
    attr_reader :tx_sec, :tx_usec, :rx_sec, :rx_usec
    attr_reader :probe_ttl, :probe_ipid, :reply_src, :reply_ttl, :reply_qttl
    attr_reader :reply_ipid

    def responded?
      @responded
    end

    def icmp_reply?
      @reply_icmp != nil
    end

    def tcp_reply?
      @reply_tcp != nil
    end

    def reply_icmp_type
      @reply_icmp ? @reply_icmp >> 8 : nil
    end

    def reply_icmp_code
      @reply_icmp ? @reply_icmp & 0xff : nil
    end

    def reply_tcp_flags
      @reply_tcp
    end

    # Just a convenience function.  This returns the same strings as warts-dump.
    def decompose_tcp_flags
      return nil unless @reply_tcp
      retval = []
      retval << "fin" if (@reply_tcp & 0x01) != 0
      retval << "syn" if (@reply_tcp & 0x02) != 0
      retval << "rst" if (@reply_tcp & 0x04) != 0
      retval << "psh" if (@reply_tcp & 0x08) != 0
      retval << "ack" if (@reply_tcp & 0x10) != 0
      retval << "urg" if (@reply_tcp & 0x20) != 0
      retval << "ece" if (@reply_tcp & 0x40) != 0
      retval << "cwr" if (@reply_tcp & 0x80) != 0
      retval
    end

  end

end
