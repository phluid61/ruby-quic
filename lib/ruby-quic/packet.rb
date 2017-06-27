# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Packet
  VERSION = 0xff00_0004

  def initialize type, connection_id, packet_number, data, version=VERSION
    raise "invalid type #{type.inspect}" unless (type & 0x7f) == type
    raise "invalid connection_id #{connection_id.inspect}" unless connection_id.nil? || (connection_id & 0xffff_ffff_ffff_ffff) == connection_id
    raise "invalid packet_number #{packet_number.inspect}" unless (packet_number & 0xffff_ffff) == packet_number
    raise "invalid version #{version.inspect}" unless (version & 0xffff_ffff) == version
    @type = type
    @connection_id = connection_id
    @packet_number = packet_number
    @version = version
    @data = data
  end

  # DEBUG
  def inspect
    "\#<#{self.class.name} @type=#{'0x%02x' % @type} @connection_id=#{@connection_id.nil? ? 'nil' : ('0x%016x' % @connection_id)} @packet_number=#{'0x%08x' % @packet_number} @version=#{@version.nil? ? 'nil' : ('0x%08x' % @version)} @data=#{@data.inspect}>"
  end

  class <<self
    def parse buffer
      xtype, buffer = buffer.unpack 'Ca*'
      if (xtype & 0x80) == 0x80
        type = xtype ^ 0x80
        raise "invalid Long Header (too short -- need at least 17 bytes)" if buffer.bytesize < 16
        cid, pnum, vers, buffer = buffer.unpack 'Q>L>L>a*'

        if vers != VERSION
          # unknown packet type
          return new(type, cid, pnum, buffer, vers)
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
        type = (key_flag == 0 ? 0x07 : 0x08)
      end

      case type
      when 0x01
        # version negotiation buffer
        raise "invalid Version Negotiation Buffer (payload length should be multiple of 32-bits)" if buffer.bytesize % 4 != 0
        versions = buffer.unpack 'L>*'
        new(type, cid, pnum, versions)
      when 0x02
        # client initial (cleartext)
        new(type, cid, pnum, buffer)
      when 0x03
        # server stateless retry (cleartext)
        new(type, cid, pnum, buffer)
      when 0x04
        # server cleartext
        new(type, cid, pnum, buffer)
      when 0x05
        # client cleartext
        new(type, cid, pnum, buffer)
      when 0x06
        # 0-RTT protected
        new(type, cid, pnum, buffer)
      when 0x07
        # 1-RTT protected (key phase 0)
        new(type, cid, pnum, buffer)
      when 0x08
        # 1-RTT protected (key phase 1)
        new(type, cid, pnum, buffer)
      when 0x09
        # public reset (??)
        new(type, cid, pnum, buffer)
      else
        raise "bad Packet type #{type}"
      end
    end
  end
end

