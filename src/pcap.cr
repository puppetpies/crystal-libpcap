require "./pcap/*"

class Pcap
  
  def lookupdev(dev : String)
    LibPcap.pcap_lookupdev(dev)
  end
  
  def lookupnet(dev : String, netp, maskp, errbuf)
    LibPcap.pcap_lookupnet(dev, netp, maskp, errbuf)
  end

  def create(pointer, iface)
    LibPcap.pcap_create(pointer, iface)
  end

  def compile(handle, bpfprogram, str, optimize, netmask)
    LibPcap.pcap_compile(handle, bpfprogram, str, optimize, netmask)
  end
  
  def setfilter(handle, bpfprogram)
    LibPcap.pcap_setfilter(handle, bpfprogram)
  end
  
  def open_live(dev : String, bufsize, snaplen, promisc, timeout)
    LibPcap.pcap_open_live(dev, bufsize, snaplen, promisc, timeout)
  end
  
  def next(handle, header)
    LibPcap.pcap_next(handle, header)
  end
  
  def loop(handle ,&callback : Slice(UInt8)) 
    LibPcap.pcap_loop(handle, LibPcap::PcapHandler.new(callback.pointer, Pointer(Void).null), callback.closure_data) 
  end 

end
