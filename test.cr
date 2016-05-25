require "./src/pcap"

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

bufsize = LibPcap::PCAP_ERRBUF_SIZE
errbuf = Pointer(UInt8).new(bufsize)
bpfprogram = Pointer(LibPcap::BpfProgram).new
snaplen = 65535_u16
user = nil
pcapfilter = "tcp port 80"

cap = Pcap.new
handle = cap.open_live("wlo1", bufsize, snaplen, 1, errbuf)
puts handle
optimize = 0
netmask = 16776960_u32 # of 0xFFFF00
compiled = cap.compile(handle, bpfprogram, pcapfilter, optimize, netmask)
# puts compiled
unless compiled == -1
  begin
    cap.setfilter(handle, bpfprogram)
    # puts applyfilter
    cap.loop(handle, 0, LibPcap::PcapHandler.new { |data, h, bytes| puts String.new(h) }, user)
  rescue
    raise "Error in capturing packet ?"
  end
end
