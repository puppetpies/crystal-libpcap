require "./src/pcap"

# First test lookup interface

BUFSIZE = LibPcap::PCAP_ERRBUF_SIZE

cap = Pcap.new
v = cap.lookupdev("")
errbuf = Pointer(UInt8).new(BUFSIZE)
dev = cap.open_live("lo", BUFSIZE, 65000, 0, errbuf)
puts dev
