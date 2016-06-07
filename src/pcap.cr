require "./pcap/*"

class SetfilterError < Exception; end

class Pcap
  def initialize; end

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

  def applyfilter(handle, bpfprogram, str, optimize, netmask)
    checkfilter = self.compile(handle, bpfprogram, str, optimize, netmask)
    unless checkfilter == -1
      begin
        return self.setfilter(handle, bpfprogram)
      rescue
        raise SetfilterError.new "Please specify a valid pcap filter"
      end
    end
  end

  def open_live(dev : String, snaplen : Int32 , promisc : Int32, timeout_ms : Int32)
    errbuf = uninitialized UInt8[LibPcap::PCAP_ERRBUF_SIZE]
    pcap_t = LibPcap.pcap_open_live(dev, snaplen, promisc, timeout_ms, errbuf)
    if pcap_t.null?
      raise String.new(errbuf.to_unsafe)
    end
    return pcap_t
  end

  def next(handle, header)
    LibPcap.pcap_next(handle, header)
  end

  def loop(handle, count, callback, user)
    LibPcap.pcap_loop(handle, count, callback, user)
  end
end
