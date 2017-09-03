# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

require_relative 'frame'
require_relative 'super-strong-crypto'

class QUIC::Packet

  def initialize connection_id, packet_number
    raise "invalid connection_id #{connection_id.inspect}" unless connection_id.nil? || (connection_id & 0xffff_ffff_ffff_ffff) == connection_id
    raise "invalid packet_number #{packet_number.inspect}" unless (packet_number & 0xffff_ffff) == packet_number
    @connection_id = connection_id
    @packet_number = packet_number
    @connection = nil
  end

  attr_reader :connection_id, :packet_number
  attr_accessor :connection

  def serialize_header
    [self.class::Type, @connection_id, @packet_number, QUIC::VERSION].pack 'CQ>L>L>'
  end

  class <<self
    def parse buffer
      xtype, buffer = buffer.unpack 'Ca*'
      if (xtype & 0x80) == 0x80
        type = xtype ^ 0x80
        raise "invalid Long Header (too short -- need at least 17 bytes)" if buffer.bytesize < 16
        cid, pnum, vers, buffer = buffer.unpack 'Q>L>L>a*'

        if vers != QUIC::VERSION
          # unknown packet type
          return OutversionPacket.new(type, cid, pnum, buffer, vers)
        end
      else
        cid_flag = xtype & 0x40
        key_flag = xtype & 0x20
        type = xtype & 0x1f

        if cid_flag != 0
          raise "invalid Short Header (too short -- expected Connection ID field)" if buffer.bytesize < 8
          cid, buffer = buffer.unpack 'Q>a*'
        else
          cid = nil
        end

        case type
        when 0x01
          raise "invalid Short Header (too short -- need at least 1 byte for Packet Number)" if buffer.bytesize < 1
          pnum, buffer = buffer.unpack 'Ca*'
        when 0x02
          raise "invalid Short Header (too short -- need at least 2 bytes for Packet Number)" if buffer.bytesize < 2
          pnum, buffer = buffer.unpack 'S>a*'
        when 0x03
          raise "invalid Short Header (too short -- need at least 4 bytes for Packet Number)" if buffer.bytesize < 4
          pnum, buffer = buffer.unpack 'L>a*'
        else
          raise "invalid Short Header type #{type}"
        end

        # 0x07 = 1-RTT protected (key phase 0)
        # 0x08 = 1-RTT protected (key phase 1)
        type = (key_flag == 0 ? ProtectedPacketPhase0::Type : ProtectedPacketPhase1::Type)
      end

      case type
      when VersionNegotiationPacket::Type
        VersionNegotiationPacket.new(cid, pnum, buffer)
      when ClientInitialPacket::Type
        ClientInitialPacket.new(cid, pnum, buffer)
      when ServerStatelessRetryPacket::Type
        ServerStatelessRetryPacket.new(cid, pnum, buffer)
      when ServerCleartextPacket::Type
        ServerCleartextPacket.new(cid, pnum, buffer)
      when ClientCleartextPacket::Type
        ClientCleartextPacket.new(cid, pnum, buffer)
      when ProtectedPacket0RTT::Type
        ProtectedPacket0RTT.new(cid, pnum, buffer)
      when ProtectedPacketPhase0::Type
        ProtectedPacketPhase0.new(cid, pnum, buffer)
      when ProtectedPacketPhase1::Type
        ProtectedPacketPhase1.new(cid, pnum, buffer)
      when PublicResetPacket::Type
        PublicResetPacket.new(cid, pnum, buffer)
      else
        raise "bad Packet type #{type}"
      end
    end
  end

  class OutversionPacket < QUIC::Packet
    def initialize type, connection_id, packet_number, buffer, version
      raise "invalid type #{type.inspect}" unless (type & 0x7f) == type
      raise "invalid version #{version.inspect}" unless (version & 0xffff_ffff) == version
      super(connection_id, packet_number)
      @type = type
      @buffer = buffer
      @version = version
    end
    def serialize_header
      [@type, connection_id, packet_number, @version].pack 'CQ>L>L>'
    end
    def serialize
      [@type, connection_id, packet_number, @version, @buffer].pack 'CQ>L>L>a*'
    end
  end

  class VersionNegotiationPacket < QUIC::Packet
    Type = 0x01
    def initialize connection_id, packet_number, buffer
      super(connection_id, packet_number)
      raise "invalid Version Negotiation Buffer (payload length should be multiple of 32-bits)" if buffer.bytesize % 4 != 0
      @versions = buffer.unpack 'L>*'
    end
    attr_reader :versions
    def serialize
      @versions.inject(serialize_header) {|b, v| b + [v].pack('L>') }
    end
  end
  class CleartextPacket < QUIC::Packet
    def initialize connection_id, packet_number, buffer
      super(connection_id, packet_number)
      @buffer = buffer
    end
    def frames
      @frames ||= QUIC::Frame.parse(@buffer)
    end
    def serialize
      @frames.inject(serialize_header) {|b, f| b + f.serialize }
    end
  end
  class ClientInitialPacket < CleartextPacket
    Type = 0x02
  end
  class ServerStatelessRetryPacket < CleartextPacket
    Type = 0x03
  end
  class ServerCleartextPacket < CleartextPacket
    Type = 0x04
  end
  class ClientCleartextPacket < CleartextPacket
    Type = 0x05
  end

  class ProtectedPacket < QUIC::Packet
    def initialize connection_id, packet_number, buffer
      super(connection_id, packet_number)
      @buffer = buffer
    end
    attr_reader :frames
    def frames
      @frames ||= QUIC::Frame.parse(decrypt(@buffer, @connection.key))
    end
    def serialize
      payload = @frames.inject(String.new) {|b, f| b + f.serialize }
      serialize_header + encrypt(payload, connection.key)
    end
  end
  class ProtectedPacket0RTT < ProtectedPacket
    Type = 0x06
  end
  class ProtectedPacketPhase0 < ProtectedPacket
    Type = 0x07
  end
  class ProtectedPacketPhase1 < ProtectedPacket
    Type = 0x08
  end

  class PublicResetPacket < QUIC::Packet
    Type = 0x09
    def initialize connection_id, packet_number, buffer
      super(connection_id, packet_number)
      @buffer = buffer
    end
    def serialize
      serialize_header
    end
  end
end

