require "./src/pcap"

# First test lookup interface

bufsize = LibPcap::PCAP_ERRBUF_SIZE
errbuf = Pointer(UInt8).new(bufsize)
bpfprogram = Pointer(LibPcap::BpfProgram).new
header = Pointer(LibPcap::PcapPkthdr).new

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
  
cap = Pcap.new
v = cap.lookupdev("")
handle = cap.open_live("veth9354d01", bufsize, 65000, 0, errbuf)
puts handle
str = "tcp port 80"
optimize = 0
netmask = 16777215_u32 # of 0xFFFFFF
compiled = cap.compile(handle, bpfprogram, str, optimize, netmask)
puts compiled
if compiled == 0
  applyfilter = cap.setfilter(handle, bpfprogram)
  puts applyfilter
end

loop do
packet = cap.next(handle, header)
puts String.new(packet) unless check_packet?(packet)
end
