#############################################################################
## Pulls in the compiled extension and Ruby-based augmentation of extension
## classes.
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
## $Id: wartslib.rb,v 1.4 2008/10/02 23:05:07 youngh Exp $
#############################################################################

require "mperioext"

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

  attr_accessor :suspend_on_idle

  # Public methods implemented in C extension:
  #
  #   initialize(port, log_path=nil, use_tcp=nil)
  #   delegate=(delegate)
  #   start()
  #   stop()
  #   ping_icmp(reqnum, dest, spacing=0)
  #   ping_icmp_indir(reqnum, dest, hop, cksum, spacing=0)
  #   ping_tcp(reqnum, dest, dport, spacing=0)
  #   ping_udp(reqnum, dest, spacing=0)
  #   ping_raw_command(command)
  #
  # Private methods implemented in C extension:
  #
  #   allocate_scamper_fdn(fd)
  #   deallocate_scamper_fdn(fd)
  #   read_pause(fd)
  #   read_unpause(fd)
  #   write_pause(fd)
  #   write_unpause(fd)

  # A source should implement the following methods:
  #
  #   * io() => return IO object or nil if source has failed/finished,
  #   * want_read() => true if the source wants to perform a read,
  #   * want_write() => true if the source wants to perform a write,
  #   * read_data() => perform nonblocking read, and
  #   * write_data() => perform nonblocking write.
  #
  def add_source(source)
    fd = source.io.fileno
    @sources[source] = fd
    @fd_to_source[fd] = source
    allocate_scamper_fdn fd
  end


  def remove_source(source)
    fd = @sources.delete source
    @fd_to_source.delete fd
    deallocate_scamper_fdn fd
  end


  private #..................................................................

  # Called by initialize in the C extension.
  def setup_source_state
    # $stderr.puts "setup_source_state called"
    @sources = {}  # source => Unix fd
    @fd_to_source = {}  # Unix fd => source
    @suspend_on_idle = false  # suspend event loop if all sources are idle
  end


  # Called by start() in the C extension.
  def prepare_sources
    # $stderr.puts "prepare_sources called"
    defunct_sources = []

    idle = true
    @sources.each_key do |source|
      if source.io
        if source.want_read
          idle = false
          read_unpause source.io.fileno
        else
          read_pause source.io.fileno
        end

        if source.want_write
          idle = false
          write_unpause source.io.fileno
        else
          write_pause source.io.fileno
        end
      else
        defunct_sources << source
      end
    end

    defunct_sources.each do |source|
      remove_source source
    end

    suspend() if idle && @suspend_on_idle
  end


  def source_read_data(fd)
    # $stderr.puts "source_read_data(#{fd}) called"
    @fd_to_source[fd].read_data()
  end


  def source_write_data(fd)
    # $stderr.puts "source_write_data(#{fd}) called"
    @fd_to_source[fd].write_data()
  end


  #..........................................................................
  public

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
