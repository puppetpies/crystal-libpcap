require "./src/pcap"
require "colorize"
require "option_parser"

# First test lookup interface

def check_packet?(packet)
  if packet.is_a?(Pointer(UInt8))
    if packet == Pointer(UInt8).null
      return true
    else
      return false
    end
  else
    return true
  end
end

def check_datatype?(handleclass)
  if handleclass == LibPcap::PcapT
    return true
  else
    return false
  end
end

def print_stamp
  puts "Author: Brian Hood"
  puts "Homepage: https://github.com/puppetpies/crystal-libpcap\n"
  puts "Description: \n\nCrystal bindings for libpcap"
end

bpfprogram = Pointer(LibPcap::BpfProgram).new
header = Pointer(LibPcap::PcapPkthdr).new
snaplen = 1500
promisc = 1
timeout_ms = 1000
optimize = 0
netmask = 16776960_u32 # of 0xFFFF00
user = nil
dev = "lo"
pcapfilter = "tcp port 80"
packetnum = 0

oparse = OptionParser.parse! do |parser|
  parser.banner = "Usage: Pcap Test Utility [options]"

  parser.on("-i lo", "--interface=lo", "\tNetworking interface") { |d|
    dev = d
  }
  parser.on("-f tcp port 80", "--pcapfilter=tcp port 80", "\tPcap filter") { |f|
    pcapfilter = f
  }
  parser.on("-s 1500", "--snaplen=1500", "\tSnap length max 65535") { |s|
    snaplen = s.to_i
  }
  parser.on("-h", "--help", "Show this help") { |h|
    puts parser
    puts
    print_stamp
    exit 0
  }
end
oparse.parse!

puts "Information:".colorize(:red)
puts " > Interface: #{dev}".colorize(:blue)
puts " > Netmask : #{netmask}".colorize(:blue)
puts " > Filter : #{pcapfilter}".colorize(:blue)
puts " > User : #{user}".colorize(:blue)
puts " > Snaplength : #{snaplen}".colorize(:blue)
puts " > Optimize: #{optimize}".colorize(:blue)

macro byteslice(bytes)
  s = Slice.new({{bytes}}, 255); puts s.hexdump
end

begin
  cap = Pcap.new
  handle = cap.open_live(dev, snaplen, promisc, timeout_ms)
  if check_datatype?(handle.class)
    print "Capturing on Interface: ".colorize(:cyan)
    print "#{dev}\n".colorize(:yellow)
    compiled = cap.applyfilter(handle, bpfprogram, pcapfilter, optimize, netmask)
    cap.loop(handle, packetnum, LibPcap::PcapHandler.new { |data, h, bytes| byteslice(bytes) }, user)
  else
    abort "Invalid handle ?"
    exit
  end
rescue UnknownError
  abort "Please raise and issue on Github!"
end
