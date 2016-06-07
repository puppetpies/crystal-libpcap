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

def print_stamp
  puts "Author: Brian Hood"
  puts "Homepage: https://github.com/puppetpies/crystal-libpcap\n"
  puts "Description: \n\nCrystal bindings for libpcap"
end

bpfprogram = Pointer(LibPcap::BpfProgram).new
header = Pointer(LibPcap::PcapPkthdr).new
snaplen = 65535
promisc = 1
timeout_ms = 1000
optimize = 0
netmask = 16776960_u32 # of 0xFFFF00
user = nil
dev = "lo"
pcapfilter = "tcp port 80"

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

cap = Pcap.new
handle = cap.open_live(dev, snaplen, promisc, timeout_ms)
# puts handle
compiled = cap.applyfilter(handle, bpfprogram, pcapfilter, optimize, netmask)
cap.loop(handle, 0, LibPcap::PcapHandler.new { |data, h, bytes| puts bytes }, user)
#    data = ""
#    10000.times {|k|
#      payload = cap.next(handle, header)
#      data = "#{data}#{payload}"
#      n.print(data) unless Pointer(UInt8).null
#    }
