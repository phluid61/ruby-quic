# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class STREAM < QUIC::Frame
    Type = (0xc0..0xff)
    def initialize streamid, offset, data, fin
      raise "[8.1] payload must not be empty unless FIN is set" if data.empty? && !fin
      @streamid = streamid
      @offset = offset
      @data = data
      @fin = fin
    end
    attr_accessor :streamid, :offset, :data, :fin

    # DEBUG
    def inspect
      "\#<#{self.class.name} @streamid=#{'0x%08x' % @streamid} @offset=#{@offset} @fin=#{@fin.inspect} @data=#{@data.inspect}>"
    end

    def serialize
      type = 0xc0

      type |= 0x20 if @fin

      if @streamid <= 0xff
        streamid_b = [@streamid].pack('C')
      elsif @streamid <= 0xffff
        type |= 0x08
        streamid_b = [@streamid].pack('S>')
      elsif @streamid <= 0xffffffff
        type |= 0x10
        streamid_b = [@streamid].pack('L>')
      else
        type |= 0x18
        streamid_b = [@streamid].pack('Q>')
      end

      if @offset == 0
        offset_b = ''
      elsif @offset <= 0xffff
        type |= 0x02
        offset_b = [@offset].pack('S>')
      elsif @offset <= 0xffffffff
        type |= 0x04
        offset_b = [@offset].pack('L>')
      else
        type |= 0x06
        offset_b = [@offset].pack('Q>')
      end

      if @fin
        datalen_b = ''
      else
        type |= 0x01
        datalen_b = [@data.bytesize].pack('S>')
      end

      [type,streamid_b,offset_b,datalen_b,@data].pack('Ca*a*a*a*')
    end

    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, buffer = buffer.unpack 'Ca*'
        raise "BUG: Frame type 0x#{type.to_s(16)} not STREAM" unless (type & 0xc0) == 0xc0
        fin = (type & 0x20) == 0x20
        ss  = (type & 0x18) >> 3
        oo  = (type & 0x06) >> 1
        d   = (type & 0x01) == 0x01

        # extract the Stream ID
        streamid_len = (ss + 1)
        raise "packet truncated before STREAM 'Stream ID'" if buffer.bytesize < streamid_len
        parts = buffer.unpack "C#{streamid_len}a*"
        buffer = parts.pop
        streamid = parts.inject {|a,b| (a << 8) + b }

        # extract the Offset
        case oo
        when 0
          offset = 0
        when 1
          raise "packet truncated before STREAM 'offset'" if buffer.bytesize < 2
          offset, buffer = buffer.unpack 'S>a*'
        when 2
          raise "packet truncated before STREAM 'offset'" if buffer.bytesize < 4
          offset, buffer = buffer.unpack 'L>a*'
        when 3
          raise "packet truncated before STREAM 'offset'" if buffer.bytesize < 8
          offset, buffer = buffer.unpack 'Q>a*'
        end

        if d
          data_length, buffer = buffer.unpack 'S>a*'
          data, buffer = buffer.unpack "a#{data_length}a*"
          raise "packet truncated before STREAM data (expected #{data_length} bytes, got (#{data.bytesize})" if data.bytesize < data_length
        else
          data = buffer
          buffer = ''
        end

        [new(streamid, offset, data, fin), buffer]
      end
    end
  end
end
