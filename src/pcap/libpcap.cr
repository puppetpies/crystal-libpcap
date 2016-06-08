# /* IP header */

class Ippkt
  property ip_vhl, ip_tos, ip_len, ip_id, ip_off, ip_ttl, ip_p, ip_sum
  property? ip_vhl : UInt8
  property? ip_tos : UInt8
  property? ip_len : UInt8
  property? ip_id : UInt8
  property? ip_off : UInt8
  property? ip_ttl : UInt8
  property? ip_p : UInt8
  property? ip_sum : UInt8

  def initialize
    @ip_vhl = 0_u8 # /* version << 4 | header length >> 2 */
    @ip_tos = 0_u8 #                 /* type of service */
    @ip_len = 0_u8 #                 /* total length */
    @ip_id = 0_u8  #                  /* identification */
    @ip_off = 0_u8 #                 /* fragment offset field */
    @ip_ttl = 0_u8 #                 /* time to live */
    @ip_p = 0_u8   #                   /* protocol */
    @ip_sum = 0_u8 #                /* checksum */
  end
end

class Tcppkt
  property th_sport, th_dport, th_seq, th_ack, th_offx2, th_win, th_sum, th_urp, th_flags
  property? th_sport : UInt16
  property? th_dport : UInt16
  property? th_seq : UInt32
  property? th_ack : UInt32
  property? th_offx2 : UInt8
  property? th_win : UInt16
  property? th_sum : UInt16
  property? th_urp : UInt16
  property? th_flags : UInt8

  def initialize
    @th_sport = 0_u16 #              /* source port */
    @th_dport = 0_u16 #               /* destination port */
    @th_seq = 0_u32   #                 /* sequence number */
    @th_ack = 0_u32   #                 /* acknowledgement number */
    @th_offx2 = 0_u8  #               /* data offset, rsvd */
    @th_win = 0_u16   #                 /* window */
    @th_sum = 0_u16   #                 /* checksum */
    @th_urp = 0_u16   #                 /* urgent pointer */
    @th_flags = 0_u8  #                /* Also known as Control bits RFC 793 */
    # #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  end
end

class Udppkt
  property udp_dport, udp_len, udp_sum, udp_sport
  property? udp_dport : UInt16
  property? udp_len : UInt32
  property? udp_sum : UInt16
  property? udp_sport : UInt16

  def initialize
    @udp_dport = 0_u16
    @udp_len = 0
    @udp_sum = 0_u16
    @udp_sport = 0_u16
  end
end

# Ethernet header
class EthernetHdr
  property ether_dhost, ether_shost, ether_type
  property? ether_dhost : UInt8
  property? ether_shost : UInt8
  property? ether_type : UInt8

  def initialize
    @ether_dhost = 0_u8
    @ether_shost = 0_u8
    @ether_type = 0_u8
  end
end

@[Link("pcap")]
lib LibPcap
  PCAP_ERRBUF_SIZE = 256

  # default snap length (maximum bytes per packet to capture)
  SNAP_LEN = 1518

  # ethernet headers are always exactly 14 bytes [1]
  SIZE_ETHERNET = 14

  # Ethernet addresses are 6 bytes
  ETHER_ADDR_LEN = 6
  # IP Flag constants
  IP_RF      = 0x8000 #           /* reserved fragment flag */
  IP_DF      = 0x4000 #           /* dont fragment flag */
  IP_MF      = 0x2000 #           /* more fragments flag */
  IP_OFFMASK = 0x1fff #      /* mask for fragmenting bits */

  TH_FIN   = 0x01
  TH_SYN   = 0x02
  TH_RST   = 0x04
  TH_PUSH  = 0x08
  TH_ACK   = 0x10
  TH_URG   = 0x20
  TH_ECE   = 0x40
  TH_CWR   = 0x80
  TH_FLAGS = [TH_FIN, TH_SYN, TH_RST, TH_ACK, TH_URG, TH_ECE, TH_CWR]

  fun pcap_lookupdev(x0 : LibC::Char*) : LibC::Char*
  alias X__UInt = LibC::UInt
  alias UInt = X__UInt
  alias BpfUInt32 = UInt
  fun pcap_lookupnet(x0 : LibC::Char*, x1 : BpfUInt32*, x2 : BpfUInt32*, x3 : LibC::Char*) : LibC::Int
  type PcapT = Void*
  fun pcap_create(x0 : LibC::Char*, x1 : LibC::Char*) : PcapT
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
  fun pcap_open_live(x0 : LibC::Char*, x1 : LibC::Int, x2 : LibC::Int, x3 : LibC::Int, x4 : LibC::Char*) : PcapT
  fun pcap_open_dead(x0 : LibC::Int, x1 : LibC::Int) : PcapT
  fun pcap_open_dead_with_tstamp_precision(x0 : LibC::Int, x1 : LibC::Int, x2 : UInt) : PcapT
  fun pcap_open_offline_with_tstamp_precision(x0 : LibC::Char*, x1 : UInt, x2 : LibC::Char*) : PcapT
  fun pcap_open_offline(x0 : LibC::Char*, x1 : LibC::Char*) : PcapT

  struct X_IoFile
    _flags : LibC::Int
    _io_read_ptr : LibC::Char*
    _io_read_end : LibC::Char*
    _io_read_base : LibC::Char*
    _io_write_base : LibC::Char*
    _io_write_ptr : LibC::Char*
    _io_write_end : LibC::Char*
    _io_buf_base : LibC::Char*
    _io_buf_end : LibC::Char*
    _io_save_base : LibC::Char*
    _io_backup_base : LibC::Char*
    _io_save_end : LibC::Char*
    _markers : X_IoMarker*
    _chain : X_IoFile*
    _fileno : LibC::Int
    _flags2 : LibC::Int
    _old_offset : X__OffT
    _cur_column : LibC::UShort
    _vtable_offset : LibC::Char
    _shortbuf : LibC::Char[1]
    _lock : X_IoLockT*
    _offset : X__Off64T
    __pad1 : Void*
    __pad2 : Void*
    __pad3 : Void*
    __pad4 : Void*
    __pad5 : LibC::SizeT
    _mode : LibC::Int
    _unused2 : LibC::Char[20]
  end

  type File = X_IoFile

  struct X_IoMarker
    _next : X_IoMarker*
    _sbuf : X_IoFile*
    _pos : LibC::Int
  end

  alias X__OffT = LibC::Long
  alias X_IoLockT = Void
  alias X__Off64T = LibC::Long
  fun pcap_fopen_offline_with_tstamp_precision(x0 : File*, x1 : UInt, x2 : LibC::Char*) : PcapT
  fun pcap_fopen_offline(x0 : File*, x1 : LibC::Char*) : PcapT
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
  fun pcap_next(x0 : PcapT, x1 : PcapPkthdr*) : UChar*
  fun pcap_next_ex(x0 : PcapT, x1 : PcapPkthdr**, x2 : UChar**) : LibC::Int
  fun pcap_breakloop(x0 : PcapT)

  struct PcapStat
    ps_recv : UInt
    ps_drop : UInt
    ps_ifdrop : UInt
  end

  fun pcap_stats(x0 : PcapT, x1 : PcapStat*) : LibC::Int

  struct BpfProgram
    bf_len : UInt
    bf_insns : BpfInsn*
  end

  struct BpfInsn
    code : UShort
    jt : UChar
    jf : UChar
    k : BpfUInt32
  end

  alias X__UShort = LibC::UShort
  alias UShort = X__UShort
  fun pcap_setfilter(x0 : PcapT, x1 : BpfProgram*) : LibC::Int
  enum PcapDirectionT
    PcapDInout = 0
    PcapDIn    = 1
    PcapDOut   = 2
  end
  fun pcap_setdirection(x0 : PcapT, x1 : PcapDirectionT) : LibC::Int
  fun pcap_getnonblock(x0 : PcapT, x1 : LibC::Char*) : LibC::Int
  fun pcap_setnonblock(x0 : PcapT, x1 : LibC::Int, x2 : LibC::Char*) : LibC::Int
  fun pcap_inject(x0 : PcapT, x1 : Void*, x2 : LibC::SizeT) : LibC::Int
  fun pcap_sendpacket(x0 : PcapT, x1 : UChar*, x2 : LibC::Int) : LibC::Int
  fun pcap_geterr(x0 : PcapT) : LibC::Char*
  fun pcap_perror(x0 : PcapT, x1 : LibC::Char*)
  fun pcap_compile(x0 : PcapT, x1 : BpfProgram*, x2 : LibC::Char*, x3 : LibC::Int, x4 : BpfUInt32) : LibC::Int
  fun pcap_compile_nopcap(x0 : LibC::Int, x1 : LibC::Int, x2 : BpfProgram*, x3 : LibC::Char*, x4 : LibC::Int, x5 : BpfUInt32) : LibC::Int
  fun pcap_freecode(x0 : BpfProgram*)
  fun pcap_offline_filter(x0 : BpfProgram*, x1 : PcapPkthdr*, x2 : UChar*) : LibC::Int
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
  fun pcap_file(x0 : PcapT) : File*
  fun pcap_fileno(x0 : PcapT) : LibC::Int
  type PcapDumperT = Void*
  fun pcap_dump_file(x0 : PcapDumperT) : File*
  fun pcap_dump_ftell(x0 : PcapDumperT) : LibC::Long
  fun pcap_dump_flush(x0 : PcapDumperT) : LibC::Int
  fun pcap_dump_close(x0 : PcapDumperT)
  fun pcap_dump(x0 : UChar*, x1 : PcapPkthdr*, x2 : UChar*)

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
