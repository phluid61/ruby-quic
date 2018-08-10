# encoding: BINARY
# frozen_string_literal: true

module QUIC
  VERSION = 0xff00000D
end

require 'socket'
require 'mug/bittest'

class Buffer
  def initialize b
    @b = b
  end

  def length
    @b.bytesize
  end

  def empty?
    @b.empty?
  end

  ##
  # Peek at the first byte in the buffer.
  def peek
    @b.each_byte {|b| return b }
  end

  ##
  # Unpack data from the buffer, without consuming it.
  def unpack format
    @b.unpack format
  end

  ##
  # Unpack data from the buffer, consuming it in the process.
  def unpack! format
    ary = @b.unpack "#{format}a*"
    @b = ary.pop
    ary
  end

  ##
  # Unpack data from the buffer, without consuming it.
  def unpack_one format
    @b.unpack_one format
  end

  ##
  # Unpack data from the buffer, consuming it in the process.
  def unpack_one! format
    ary = @b.unpack "#{format}a*"
    @b = ary.pop
    ary[0]
  end

  ##
  # Get the first +n+ bytes from the buffer, without consuming it.
  def first n
    @b.byteslice 0, n
  end

  ##
  # Get the first +n+ bytes from the buffer, consuming it in the process.
  def first! n
    slice = @b.byteslice 0, n
    @b = @b.byteslice n, -1
    slice
  end

  ##
  # Get an n-byte integer from the buffer, consuming it in the process.
  def int_n! n
    value = 0
    [
      [8, 'Q>'],
      [4, 'N'],
      [2, 'n'],
      [1, 'C'],
    ].each do |nbytes, fmt|
      shift = nbytes * 8
      while n > nbytes
        value = (value << shift) | unpack_one!(fmt)
        n -= nbytes
      end
    end
    value
  end

  ##
  # Get a variable-length integer from the buffer, consuming it in the process.
  # @see <https://tools.ietf.org/html/draft-ietf-quic-transport-13#section-7.1>
  def varint!
    case (peek & 0xC0)
    when 0x00
      unpack_one!('C') #& 0x3F
    when 0x40
      unpack_one!('n') & 0x3F_FF
    when 0x80
      unpack_one!('N') & 0x3FFF_FFFF
    when 0xC0
      unpack_one!('Q>') & 0x3FFFFFFF_FFFFFFFF
    end
  end
end

class QUIC::Server
  class Client
    PHASE_INITIAL = 0
    PHASE_HANDSHAKE = 1
    PHASE_0RTT = 2
    PHASE_1RTT = 3

    def initialize
      @phase = PHASE_INITIAL
      @packetnum_initial = 0
      @packetnum_handshake = 0
      @packetnum_encrypted = 0
    end

    def packetnum phase=nil
      case (phase || @phase)
      when PHASE_INITIAL
        @packetnum_initial
      when PHASE_HANDSHAKE
        @packetnum_handshake
      when PHASE_0RTT, PHASE_1RTT
        @packetnum_encrypted
      else
        raise "invalid phase #{phase.inspect}"
      end
    end

    def packetnum= value
      # TODO: validate that new value > current value?
      case (phase || @phase)
      when PHASE_INITIAL
        @packetnum_initial = value
      when PHASE_HANDSHAKE
        @packetnum_handshake = value
      when PHASE_0RTT, PHASE_1RTT
        @packetnum_encrypted = value
      else
        raise "invalid phase #{phase.inspect}"
      end
    end
  end

  def initialize
    @sock = UDPSocket.new
    @sock.bind '127.0.0.1', 8443
    @clients = {}
  end

  def go
    loop do
      # max size of UDP datagram = 65527
      mesg, client_addrinfo = @sock.recvfrom(65527)
      client_key = client_addrinfo.inspect_sockaddr
      @clients[client_key] ||= Client.new

      firstbyte = mesg.each_byte {|b| break b }
      if firstbyte.and? 0b10000000
        ##
        ## Long Header
        ##
        buffer = Buffer.new(mesg)

        ## Parse Invariant long header data

        type, version, xcil = buffer.unpack! 'CNC'
        type &= 0b01111111
        dcil = (xcil & 0b11110000) >> 4
        scil = (xcil & 0b00001111)

        dcil += 3 if dcil > 0
        scil += 3 if scil > 0

        if dcil == 0
          dst_id = 0
        else
          dst_id = buffer.int_n!(dcil + 3)
        end

        if scil == 0
          src_id = 0
        else
          src_id = buffer.int_n!(scil + 3)
        end

        ## Check that version matches

        if version == 0x00000000
          # TODO: !?
          raise "unexpected Version Negotiation packet from client #{client_addrinfo.inspect_sockaddr}!"
        if version != QUIC::VERSION
          # TODO: negotiation?
          raise "FIXME: client sent bad QUIC version #{'%08X' % version}"
        end

        ## Read fields common to packets in my version

        length = buffer.varint!

        sample = buffer.first 4
        # TODO: AEAD
        firstbyte = sample.unpack_one 'C'
        if (firstbyte & 0x80) == 0x00
          packet_number = buffer.unpack_one!('C') #& 0x7F
          packet_number_mask = 0xFFFF_FF80
        elsif (firstbyte & 0xC0) == 0x80
          packet_number = buffer.unpack_one!('n') & 0x3FFF
          packet_number_mask = 0xFFFF_C000
        else
          packet_number = buffer.unpack_one!('N') & 0x3FFF_FFFF
          packet_number_mask = 0xC000_0000
        end
        # TODO: what if this packet bumps us to the next phase?
        current_packet_number = client.packetnum
        complete_packet_number = (current_packet_number & packet_number_mask) | packet_number
        raise "FIXME: duplicated packet number #{'%08X' % complete_packet_number}" if complete_packet_number <= current_packet_number # XXX

      else
        # Short Header
      end
    end
  end
end

