@[Link("pcap")]
lib LibPcap
  alias X__UInt = LibC::UInt
  alias UInt = X__UInt
  alias BpfUInt32 = UInt
  fun pcap_lookupnet(x0 : LibC::Char*, x1 : BpfUInt32*, x2 : BpfUInt32*, x3 : LibC::Char*) : LibC::Int
  type PcapT = Void*
  fun pcap_set_snaplen(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_promisc(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_can_set_rfmon(x0 : PcapT) : LibC::Int
  fun pcap_set_rfmon(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_timeout(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_tstamp_type(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_immediate_mode(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_buffer_size(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_set_tstamp_precision(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_get_tstamp_precision(x0 : PcapT) : LibC::Int
  fun pcap_activate(x0 : PcapT) : LibC::Int
  fun pcap_list_tstamp_types(x0 : PcapT, x1 : LibC::Int**) : LibC::Int
  fun pcap_free_tstamp_types(x0 : LibC::Int*)
  fun pcap_tstamp_type_name_to_val(x0 : LibC::Char*) : LibC::Int
  fun pcap_close(x0 : PcapT)
  alias X__UChar = UInt8
  alias UChar = X__UChar
  struct PcapPkthdr
    ts : Timeval
    caplen : BpfUInt32
    len : BpfUInt32
  end
  alias PcapHandler = UChar*, PcapPkthdr*, UChar* -> Void
  struct Timeval
    tv_sec : X__TimeT
    tv_usec : X__SusecondsT
  end
  alias X__TimeT = LibC::Long
  alias X__SusecondsT = LibC::Long
  fun pcap_loop(x0 : PcapT, x1 : LibC::Int, x2 : PcapHandler, x3 : UChar*) : LibC::Int
  fun pcap_dispatch(x0 : PcapT, x1 : LibC::Int, x2 : PcapHandler, x3 : UChar*) : LibC::Int
  fun pcap_breakloop(x0 : PcapT)
  enum PcapDirectionT
    PcapDInout = 0
    PcapDIn = 1
    PcapDOut = 2
  end
  fun pcap_setdirection(x0 : PcapT, x1 : PcapDirectionT) : LibC::Int
  fun pcap_getnonblock(x0 : PcapT, x1 : LibC::Char*) : LibC::Int
  fun pcap_setnonblock(x0 : PcapT, x1 : LibC::Int, x2 : LibC::Char*) : LibC::Int
  fun pcap_inject(x0 : PcapT, x1 : Void*, x2 : LibC::SizeT) : LibC::Int
  fun pcap_sendpacket(x0 : PcapT, x1 : UChar*, x2 : LibC::Int) : LibC::Int
  fun pcap_perror(x0 : PcapT, x1 : LibC::Char*)
  fun pcap_datalink(x0 : PcapT) : LibC::Int
  fun pcap_datalink_ext(x0 : PcapT) : LibC::Int
  fun pcap_list_datalinks(x0 : PcapT, x1 : LibC::Int**) : LibC::Int
  fun pcap_set_datalink(x0 : PcapT, x1 : LibC::Int) : LibC::Int
  fun pcap_free_datalinks(x0 : LibC::Int*)
  fun pcap_datalink_name_to_val(x0 : LibC::Char*) : LibC::Int
  fun pcap_snapshot(x0 : PcapT) : LibC::Int
  fun pcap_is_swapped(x0 : PcapT) : LibC::Int
  fun pcap_major_version(x0 : PcapT) : LibC::Int
  fun pcap_minor_version(x0 : PcapT) : LibC::Int
  fun pcap_fileno(x0 : PcapT) : LibC::Int
  type PcapDumperT = Void*
  fun pcap_dump_ftell(x0 : PcapDumperT) : LibC::Long
  fun pcap_dump_flush(x0 : PcapDumperT) : LibC::Int
  fun pcap_dump_close(x0 : PcapDumperT)
  struct PcapIf
    next : PcapIf*
    name : LibC::Char*
    description : LibC::Char*
    addresses : PcapAddr*
    flags : BpfUInt32
  end
  type PcapIfT = PcapIf
  struct PcapAddr
    next : PcapAddr*
    addr : Void*
    netmask : Void*
    broadaddr : Void*
    dstaddr : Void*
  end
  fun pcap_findalldevs(x0 : PcapIfT**, x1 : LibC::Char*) : LibC::Int
  fun pcap_freealldevs(x0 : PcapIfT*)
  fun pcap_get_selectable_fd(x0 : PcapT) : LibC::Int
end
