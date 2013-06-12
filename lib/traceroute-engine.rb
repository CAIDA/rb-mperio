#################################################################################
#
# Implements a traceroute algorithm
#
# Used by both mper-trace and rb-trace-test
# 
# Algorithm ported from scamper (http://www.wand.net.nz/scamper)
#
#############################################################################

require 'ostruct'

################################################################################
################################################################################
# Traceroute library classes
# 
# The following three classes - TraceResult, Hop and TraceTask should
# eventually be moved to a stand-alone library which can be used as
# a high-level traceroute method.
#
# Users of the library would instantiate a TraceTask class 
#
################################################################################
################################################################################

#==============================================================================
# TraceResult
# 
# A TraceResult object encapsulates the results of a traceroute to a given
# destination address.
# It is initialized with the target (destination) address of the trace and
# the firsthop TTL value with which to initialize the hop array.
# Once tracing is complete, it contains an array of Hop objects which
# themselves contain the responses to the trace probes.
# 
# The hops array is indexed by TTL value, and as such can contain empty (nil)
# elements. The first valid element in the array should be at the firsthop
# ttl and the last will usually be at the TTL of the destination, or the TTL
# of the last hop probed before giving up due to the gaplimit being reached.
# When the lastditch gapaction is used however, there can be a large gap in the
# hops array, with the last element being the responses to the lastditch
# probes at TTL 255
#==============================================================================
class TraceResult
  
  attr_reader :target
  attr_accessor :hops, :stop_reason  
  def initialize(target, firsthop)
    @target = target
    @hops = [] # hash of hops TTL => hop
    allocate_hop(firsthop)
  end

  def allocate_hop(ttl)
    hop = Hop.new(ttl)
    @hops[ttl-1] = hop
    return hop
  end

  def hop_at_ttl(ttl)
    return @hops[ttl-1]
  end

  def to_s
    str = "traceroute to #{@target}\n"
    @hops.each do |hop|
      next unless hop && hop.results.length != 0
      str += hop.to_s
    end
    str += "stop reason: #{@stop_reason}\n"
  end 

  def scamper_to_s
    str = "traceroute to #{@target}\n"
    @hops.each do |hop|
      next unless hop && hop.results.length != 0
      str += hop.scamper_to_s
    end
    str += "stop reason: #{@stop_reason}\n"
  end

end

#==============================================================================
# Hop
#
# A Hop object is a lightweight wrapper around an array of PingResult objects
# which are the responses to probes at the given TTL.
# It also has a to_s method which allows the trace to be printed in an ASCII
# format which is similar to that used by scamper and bin traceroute. It is
# slightly more verbose in that it explicitly prints the address of each
# response on a separate line.
#==============================================================================
class Hop

  attr_accessor :ttl, :results, :responsive

  def initialize(ttl)
    @ttl = ttl
    @results = []
    @responsive = true
  end

  def to_s
    str = @ttl.to_s
    str += "\n" if @results.length == 0

    @results.each do |result|
      if result.responded?
        str += sprintf("\t%s\t\%.3f ms", result.reply_src, rtt(result))
        if $options.full
          if $options.tsps
            str += sprintf("\t%s", build_tsps_str(result))
          elsif $options.rr
            str += sprintf("\t%s", result.reply_rr)
          end
        end
        str += "\n"
      else
        str += sprintf("\t*\n")
      end
    end
    return str
  end

  def scamper_to_s
    str = @ttl.to_s
    str += "\n" if @results.length == 0
    
    no_responses = true

    sorted = @results.sort {|x, y| x.probe_ipid <=> y.probe_ipid}

    sorted.each do |result|
      if result.responded?
        no_responses = false
        str += sprintf("\t%s\t\%.3f ms\n", result.reply_src, rtt(result))
      end
    end

    if no_responses
      str += sprintf("\t*\n")
    end
    return str
  end

  def build_tsps_str(result)
    str = ""
    str += sprintf("%s=%d", result.reply_tsps_ip1, result.reply_tsps_ts1) if 
      result.reply_tsps_ip1
    str += sprintf("%s=%d", result.reply_tsps_ip2, result.reply_tsps_ts2) if 
      result.reply_tsps_ip2
    str += sprintf("%s=%d", result.reply_tsps_ip3, result.reply_tsps_ts3) if 
      result.reply_tsps_ip3
    str += sprintf("%s=%d", result.reply_tsps_ip4, result.reply_tsps_ts4) if 
      result.reply_tsps_ip4
    return str
  end

  def rtt(result)
    return "-" if !result.responded?
    tx = Time.at(result.tx_sec, result.tx_usec)
    rx = Time.at(result.rx_sec, result.rx_usec)
    (rx-tx) * 1000
  end
  
end

#==============================================================================
# Probe
# 
# A Probe object is used as the primary form of communication between the
# TraceTask and the TraceManager (or other tracing logic). It is constructed
# by the TraceTask object in response to a call to the TraceTask#next_probe
# method.
# The Probe object is constructed with a destination IP address, a TTL and
# an attempt value. Once the TraceTask#next_probe method returns a Probe
# instance, the TraceManager inserts an internal id field (which in this
# implementation is a reqnum counter maintained in the TraceManager object) 
# allowing it to match probes and responses. It also inserts a reference to 
# the TraceTask object which crafted the probe.
#
# Once a reponse is received by the TraceManager, it inserts the PingResult
# object into the appropriate Probe object and passes it back to the TraceTask
# by calling TraceTask#receive_probe
#
#==============================================================================
class Probe

  attr_accessor :id, :task, :dest, :ttl, :attempt, :result
  
  def initialize(dest, ttl, attempt)
    self.dest = dest
    self.ttl = ttl
    self.attempt = attempt #internal id for the task to use
  end

  def to_s
    "Probe #{id}: #{dest} TTL: #{ttl}"
  end
    
end

class TraceTask

  attr_reader :taskid, :is_complete

  def initialize(taskid, target, options)
    @options = options
    @taskid = taskid
    @target = target

    #log("#{@target}: trace starting at #{Time.now}");

    @trace_result = TraceResult.new(@target, @options.firsthop)
    @is_complete = false

    @ttl        = @options.firsthop

    @attempt    = 0
    @n          = 2 # used for confidence, assume two initially
    # @loopc      = 0
    @iloopc     = 0

    @replies = []
    #@probe_queue = []
    @outstanding_probe = false
    
    @interfaces = []

    @state = :trace

    @first = true
  end
  
  def to_s
    "Task: #{@taskid} To: #{@target} TTL: #{@ttl}"
  end

  def next_probe
    # what is our next probe?
    return nil if @is_complete || @outstanding_probe
    @outstanding_probe = true
    @attempt += 1
    return Probe.new(@target, @ttl, @attempt)
  end

  def receive_probe(probe)
    unless probe
      return
    end

    @outstanding_probe = false

    if @state == :trace
      if !probe.result.responded?
        receive_timeout_probe(probe)
      elsif probe.result.icmp_reply?
        receive_icmp_probe(probe)
      elsif probe.result.tcp_reply?
        receive_tcp_probe(probe)
      else
        $stderr.puts "FATAL ERROR: unknown reply type"
      end
    elsif @state == :lastditch
      if !probe.result.responded?
        receive_lastditch_timeout_probe(probe)
      else
        receive_lastditch_probe(probe)
      end
    end
  end

  def is_complete
    #if @is_complete
      #puts @trace_result #don't force users to have the trace dumped to stdout
      #log("#{@target}: trace complete at #{Time.now}")
    #end
    return @is_complete
  end

  def result
    return @trace_result
  end

  ############################################################################
  # All methods below this point are internal to the TraceTask object
  # Users should not need to ever directly call them
  ############################################################################
  private

  def add_interface(interface)
    unless @interfaces.include?(interface)
      @interfaces << interface
      @n = @interfaces.length + 1
    end
  end

  def receive_icmp_probe(probe)
    result = probe.result
    hop = @trace_result.hop_at_ttl(result.probe_ttl)

    unless hop
      $stderr.puts "FATAL ERROR: no hop record for #{result.probe_ttl}"
      exit -1
    end

    hop.results << result
    hop.responsive = true

    return if @is_complete # no point checking any more

    # to make the port from scamper easier, we assume that we're not
    # going to probe any more as the default position of this method
    @is_complete = true

    # if this reply is not for the current ttl (i.e. a late reply),
    # check if we can stop now
    if(result.probe_ttl != @ttl)
      reason = stop_reason(result)
      if(reason != :stop_none)
        @trace_result.stop_reason = reason
      else
        @is_complete = false
      end
      return
    end

    ##
    # the rest of the code in this function deals with the fact this is a
    # reply for the current working hop.
    #
    # check if we are to send all allotted probes to the target
    ##
    if(@options.all_allocated)
      if(@options.confidence)
        $stderr.puts "FATAL ERROR: confidence and all_allocated cannot be "\
          "used simulaneously"
      end
      
      ##
      # if we get an out of order reply, then we go back to waiting for
      # the one we just probed for
      ##
      if(probe.attempt != @attempt)
        @is_complete = false
        return
      end

      ##
      # this response is for the last probe sent.  if there are still
      # probes to send for this hop, then send the next one
      ##
      if(@attempt < @options.attempts)
        @is_complete = false
        return
      end

    elsif(@options.confidence)
      ##
      # record details of the interface, if its details are not
      # currently held
      ##
      add_interface(result.reply_src)

      if(@n <= CONFIDENCE_MAX_N)
        ##
        # if we get an out of order reply, then we go back to waiting for
        # the one we just probed for
        ##
        if(probe.attempt != @attempt)
          @is_complete = false
          return
        end

        ##
        # this response is for the last probe sent.  if there are still
        # probes to send for this hop, then send the next one
        ##
        if(@attempt < k(@n))
          @is_complete = false
          return
        end
      end

      ##
      # if we get to here, the confidence for this hop is done,
      # reset the state we keep about that stuff
      ##
      @n = 2
      @interfaces = []
    end

    ##
    # if we're in a mode where we only care about the first response to
    # a probe, then check it now.  the else block below handles the case
    # where we want a larger number of responses from a hop.
    ##
    if(!@options.confidence && !@options.all_allocated)
      #check to see if we have a stop reason from the ICMP response
      reason = stop_reason(result)
      if(reason != :stop_none)
        @trace_result.stop_reason = reason
        return
      end
    else
      # check all hop records for a reason to halt the trace
      # @trace_result.hops.each do |hop|
        #next unless hop
      checked = []
      hop.results.each do |tr|
        # there is no point checking if we have already checked this interface
        next if checked.include? tr.reply_src
        checked << tr.reply_src
        reason = stop_reason(tr)
        if(reason != :stop_none)
          @trace_result.stop_reason = reason
          return
        end
      end
      # end
    end
    
    # check if we've reached the hoplimit
    if(@trace_result.hops.length == 255 || 
       @trace_result.hops.length == @options.hoplimit)
      @trace_result.stop_reason = :stop_hoplimit
      return
    end

    #move on to the next ttl

    @attempt = 0
    @ttl += 1
    @trace_result.allocate_hop(@ttl)
    
    @is_complete = false
    return
    
  end

  def receive_tcp_probe(probe)
    result = probe.result
    hop = @trace_result.hop_at_ttl(result.probe_ttl)

    unless hop
      $stderr.puts "FATAL ERROR: no hop record for #{result.probe_ttl}"
      exit -1
    end

    hop.results << result
    hop.responsive = true

    return if @is_complete # no point checking any more

    # to make the port from scamper easier, we assume that we're not
    # going to probe any more as the default position of this method
    @is_complete = true

    # if we are sending all allotted probes to the target
    if(@options.all_attempts)
      if(probe.attempts != @attempt)
        @is_complete = false
        return
      end
    elsif(@options.confidence)
      # record details of the interface
      add_interface(result.reply_src)

      if(@n <= CONFIDENCE_MAX_N && @attempt < k(@n))
        @is_completed = false
        return
      end
    end

    @trace_result.stop_reason = :stop_completed
    return
  end

  def receive_lastditch_probe(probe)
    result = probe.result
    hop = @trace_result.hop_at_ttl(result.probe_ttl)

    unless hop
      $stderr.puts "FATAL ERROR: no hop record for #{result.probe_ttl}"
      exit -1
    end

    hop.results << result
    hop.responsive = true

    return if @is_complete # no point checking any more

    # we received a reply from the destination, be done.

    @is_complete = true
    @trace_result.stop_reason = :stop_gaplimit
    return
  end

  def receive_timeout_probe(probe)
    result = probe.result

    hop = @trace_result.hop_at_ttl(result.probe_ttl)

    unless hop
      $stderr.puts "FATAL ERROR: no hop record for #{result.probe_ttl}"
      exit -1
    end

    hop.results << result

    return if @is_complete # no point checking any more

    if(@attempt == @options.attempts)
      @is_complete = true
      hop.responsive = false
      # all probes for this hop have now been sent

      # scamper does a check to see if any of the other responses can be
      # used for a stop reason. this shouldnt apply for us, but let's do
      # it anyway.
      #@trace_result.hops.each do |hop|
      #  next unless hop
      #  checked = []
      #  hop.results.each do |tr|
      #    next if checked.include? tr.reply_src
      #    checked << tr.reply_src
      #    reason = stop_reason(tr)
      #    if(reason != :stop_none)
      #      puts "found a stop reason from the non response: #{reason}"
      #      @trace_result.stop_reason = reason
      #      return
      #    end
      #  end
      #end
      
      # check if we've reached the hoplimit
      if(@trace_result.hops.length == 255 || 
         @trace_result.hops.length == @options.hoplimit)
        @trace_result.stop_reason = :stop_hoplimit
        return
      end

      # see if a non-response for this hop brings us to the gap limit
      if(@trace_result.hops.length >= @options.gaplimit)
        # start at the current ttl -1 and go back gaplimit -1 hops
        # check if all of these hops are unresponsive
        deadpath = true
        (@ttl-1).downto(@ttl-(@options.gaplimit-1)) do |i|
          hop = @trace_result.hop_at_ttl(i)
          if hop && hop.responsive
            deadpath = false
            break
          end
        end

        # add lastditch mode stuff in here
        if deadpath
          if @options.gapaction == :stop
            @trace_result.stop_reason = :stop_gaplimit
          elsif @options.gapaction == :lastditch
            @is_complete = false
            @state = :lastditch
            @attempt = 0
            @ttl = 255
            @trace_result.allocate_hop(@ttl)
          else
            $stderr.puts "FATAL ERROR: invalid gapaction: @options.gapaction"
          end
          return
        end

      end
      @attempt = 0
      @ttl += 1
      @trace_result.allocate_hop(@ttl)
      @is_complete = false
    end
  end

  def receive_lastditch_timeout_probe(probe)
    result = probe.result

    hop = @trace_result.hop_at_ttl(result.probe_ttl)

    unless hop
      $stderr.puts "FATAL ERROR: no hop record for #{result.probe_ttl}"
      exit -1
    end

    hop.results << result
    
    if(@attempt == @options.attempts)
      # this is the last lastditch probe, give up!
      @is_complete = true
      @trace_result.stop_reason = :stop_gaplimit
      return
    end
  end


  ###
  # decide if this result is a good enough reason to stop
  def stop_reason(result)
    
    ##
    # the message received is an ICMP port unreachable -- something that
    # the destination should have sent.  make sure the port unreachable
    # message makes sense based on the traceroute type.
    ##
  
    if(is_icmp_unreach_port(result) && (is_trace_method(:udp) || 
                                        is_trace_method(:tcp)))
      reason = :stop_completed
    elsif(is_icmp_unreach(result))
      reason = :stop_unreach
    elsif(is_icmp_echo_reply(result))
      ##
      # the message received is an ICMP echo reply -- something that only
      # makes sense to include as part of the traceroute if the traceroute
      # is using echo requests.
      ##
      if(is_trace_method(:icmp))
        reason = :stop_completed
      else
        raise "ICMP Echo Reply response received for a UDP or TCP probe "\
          "to #{result.reply_src}"
        reason = :stop_none
      end
    elsif(@options.loops != 0 && is_loop(result)) 
      # checked for and found loop condition
      reason = :stop_loop
    elsif(is_icmp_ttl_exp(result) && @options.not_time_exceeded == false &&
          is_target(result))
      ##
      # if an ICMP TTL expired message is received from an IP address
      # matching the destination being probed, and the traceroute is
      # to stop when this occurs, then stop.
      ##
      reason = :stop_completed
    elsif(is_trace_method(:tcp) && is_method(:tcp, result))
      reason = :stop_completed
    else
      reason = :stop_none
    end

    return reason
  end
  
  def is_trace_method(method)
    return @options.probe_method == method
  end

  def is_method(method, result)
    case method
    when :icmp
        return result.icmp_reply?
    when :tcp
        return result.tcp_reply?
    end
  end
  
  def is_icmp_ttl_exp(result)
    (!is_method(:tcp, result) || result.reply_icmp_type == 11)
  end
  
  def is_icmp_ttl_exp_trans(result)
    (!is_method(:tcp, result) && 
     result.reply_icmp_type == 11 && result.reply_icmp_code == 0)
  end
  
  def is_icmp_unreach(result)
    (!is_method(:tcp, result) && result.reply_icmp_type == 3)
  end

  def is_icmp_unreach_port(result)
    (!is_method(:tcp, result) &&
     result.reply_icmp_type == 3 && result.reply_icmp_code == 3)
  end
  
  def is_icmp_echo_reply(result)
    (!is_method(:tcp, result) && result.reply_icmp_type == 0)
  end
  
  def is_target(result)
    (@target == result.reply_src)
  end
  
  def is_loop(result)

    # need at least a couple of probes first
    if(result.probe_ttl <= @options.firsthop)
      return false
    end

    ##
    # check to see if the address has already been seen this hop; if it is,
    # then we've already checked this address for loops so we don't need to
    # check it again.
    ##
    @trace_result.hop_at_ttl(result.probe_ttl).results.each do |res|
      # if it is not this interface AND not this result, call it not a loop
      if res != result && res.reply_src == result.reply_src
        return false
      end
    end

    one_adjacent = false

    # compare all hop records until the hop prior to this one
    (result.probe_ttl-1).downto(@options.firsthop) do |i|

      checked_interfaces = []

      # all the results for the hop
      @trace_result.hop_at_ttl(i).results.each do |res|

        next unless res.responded?

        # only check an address once per hop
        next if checked_interfaces.include? res.reply_src

        checked_interfaces << res.reply_src
        # if the addresses match, then there is a loop
        if(res.reply_src == result.reply_src)

          # if the loop is between adjacent hops
          if(res.probe_ttl + 1 == result.probe_ttl)
            
            ##
            # check for zero-ttl forwarding.  continue probing if
            # the condition is met.
            ##
            if(res.reply_qttl == 0 && result.reply_qttl == 1)
              return false
            end
            
            # mark these as adjacent so that if the next interface
            # is also repeated we can mark that as a loop, otherwise,
            # mark this as an adjacent loop
            one_adjacent = true

            # move on to the next hop 
            # (i.e. ignore any other results at this hop)
            break

          elsif(res.probe_ttl + 2 == result.probe_ttl && one_adjacent)

            # this loop has one interface in the middle: AXA
            # and we saw AA at the last hop, so we can infer AAA
            return true

          end # we're looking at identical addresses but not at adjacent hops

          # these interfaces are not adjacent
          one_adjacent = false
          
          # check if the loop condition is met
          #@loopc += 1
          #if(@loopc >= @options.loops)
          #  return true
          #end
          
          #this assumes that @options.loops == 1
          # if it is set to 0, this is checked earlier.
          # setting loops to > 1 is silly and is not allowed
          # by the arg parse.
          # if you want the check for the number of 'loops' back,
          # then comment the following line and uncommend the four
          # lines above plus the break below
          return true

          # break
        elsif(one_adjacent)
          # this address is not the same as the test address, but
          # we previously saw AA, so assume we are at AAX and increment
          # the count of adjacent interface loops
          if(@iloopc < @options.loopaction)
            @iloopc += 1
            one_adjacent = false
            break # look for other loops
          else 
            return true
          end
        end # addresses are not the same, nor is one_adjacent set

      end # result loop

    end # hop loop

    # got all the way back to the start of the path with no loop
    return false
    
  end

  @@k = [
         [   0,   0 ], [   0,   0 ], [   6,   8 ], [  11,  15 ], [  16,  21 ],
         [  21,  28 ], [  27,  36 ], [  33,  43 ], [  38,  51 ], [  44,  58 ],
         [  51,  66 ], [  57,  74 ], [  63,  82 ], [  70,  90 ], [  76,  98 ],
         [  83, 106 ], [  90, 115 ], [  96, 123 ], [ 103, 132 ], [ 110, 140 ],
         [ 117, 149 ], [ 124, 157 ], [ 131, 166 ], [ 138, 175 ], [ 145, 183 ],
         [ 152, 192 ], [ 159, 201 ], [ 167, 210 ], [ 174, 219 ], [ 181, 228 ],
         [ 189, 237 ], [ 196, 246 ], [ 203, 255 ], [ 211, 264 ], [ 218, 273 ],
         [ 226, 282 ], [ 233, 291 ], [ 241, 300 ], [ 248, 309 ], [ 256, 319 ],
         [ 264, 328 ], [ 271, 337 ], [ 279, 347 ], [ 287, 356 ], [ 294, 365 ],
         [ 302, 375 ], [ 310, 384 ], [ 318, 393 ], [ 326, 403 ], [ 333, 412 ],
         [ 341, 422 ], [ 349, 431 ], [ 357, 441 ], [ 365, 450 ], [ 373, 460 ],
         [ 381, 470 ], [ 389, 479 ], [ 397, 489 ], [ 405, 499 ], [ 413, 508 ],
         [ 421, 518 ], [ 429, 528 ], [ 437, 537 ], [ 445, 547 ], [ 453, 557 ],
         [ 462, 566 ], [ 470, 576 ], [ 478, 586 ], [ 486, 596 ], [ 494, 606 ],
         [ 502, 616 ], [ 511, 625 ], [ 519, 635 ], [ 527, 645 ], [ 535, 655 ],
         [ 544, 665 ], [ 552, 675 ], [ 560, 685 ], [ 569, 695 ], [ 577, 705 ],
         [ 585, 715 ], [ 594, 725 ], [ 602, 735 ], [ 610, 745 ], [ 619, 755 ],
         [ 627, 765 ], [ 635, 775 ], [ 644, 785 ], [ 652, 795 ], [ 661, 805 ],
         [ 669, 815 ], [ 678, 825 ], [ 686, 835 ], [ 695, 845 ], [ 703, 855 ],
         [ 712, 866 ], [ 720, 876 ], [ 729, 886 ], [ 737, 896 ], [ 746, 906 ],
        ]
  
  CONFIDENCE_MAX_N = @@k.length
  
  def k(n)
    return @@k[n][@options.confidence]
  end
  
  def log(message)
    $stderr.puts message if @options.verbose
  end
  
end #TraceTask
