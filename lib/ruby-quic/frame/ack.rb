# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class ACK < QUIC::Frame
    Type = (0xa0..0xbf)
    def initialize ranges, ack_delay, timestamps
      @ranges = ranges
      @ack_delay = ack_delay
      @timestamps = timestamps
    end

    def largest_ack
      @ranges.first.min
    end

    def serialize
      largest_ack = largest_ack()

      type = 0xa0

      if largest_ack <= 0xff
        lack_b = [largest_ack].pack 'C'
      elsif largest_ack <= 0xffff
        type |= 0x04
        lack_b = [largest_ack].pack 'S>'
      elsif largest_ack <= 0xffffffff
        type |= 0x08
        lack_b = [largest_ack].pack 'L>'
      else
        type |= 0x0c
        lack_b = [largest_ack].pack 'Q>'  #??? not possible ???
      end

      biggest_ack_block = prime = @ranges.first.max - @ranges.first.min
      acks = []
      if @ranges.length > 1
        type |= 0x10

        last = largest_ack
        @ranges.each_with_index do |r,i|
          if i > 0
            gap = (r.min - last)
            block = (r.max - r.min)
            biggest_ack_block = block if block > biggest_ack_block
            acks << [gap, block]
          end
          last = r.max
        end
      end

      if biggest_ack_block <= 0xff
        format = 'C'
      elsif biggest_ack_block <= 0xffff
        type |= 0x01
        format = 'S>'
      elsif biggest_ack_block <= 0xffffffff
        type |= 0x02
        format = 'L>'
      else
        type |= 0x03
        format = 'Q>'
      end

      if !acks.empty?
        buffer = [type, acks.length, @timestamps.length, lack_b, ACK.encode_timestamp_delta(@ack_delay)].pack 'CCCa*S>'
      else
        buffer = [type, @timestamps.length, lack_b, ACK.encode_timestamp_delta(@ack_delay)].pack 'CCa*S>'
      end
      buffer << [prime].pack(format)
      acks.each do |ack|
        buffer << ack.pack("C#{format}")
      end

      @timestamps.each_with_index do |tsblock, i|
        packetnum, ts = tsblock
        if i == 0
          buffer << [packetnum-largest_ack, (ts*1_000_000).to_i].pack('CL>')
        else
          buffer << [packetnum-largest_ack, ACK.encode_timestamp_delta(ts)].pack('CS>')
        end
      end

      buffer
    end

    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, buffer = buffer.unpack 'Ca*'
        raise "BUG: Frame type 0x#{type.to_s(16)} not ACK" unless (type & 0xe0) == 0xa0
        n  = (type & 0x10) == 0x10
        ll = (type & 0x0c) >> 2
        mm = (type & 0x03)

        if n
          num_blocks, buffer = buffer.unpack 'Ca*'
        else
          num_blocks = 0
        end

        # get other metadata
        case ll
        when 0
          format = 'CCS>a*'
        when 1
          format = 'CS>S>a*'
        when 2
          format = 'CL>S>a*'
        when 3
          format = 'CQ>S>a*'  #??? not possible ???
        end
        num_ts, lack, ack_delay, buffer = buffer.unpack format
        ack_delay = decode_timestamp_delta(ack_delay)

        # get ACK blocks
        case mm
        when 0
          format = 'Ca*'
        when 1
          format = 'S>a*'
        when 2
          format = 'L>a*'
        when 3
          format = 'Q>a*'
        end
        block, buffer = buffer.unpack format
        format = "C#{format}"
        acks = [[nil,block]]
        while num_blocks > 0
          gap, block, buffer = buffer.unpack format
          acks << [gap, block]
          num_blocks -= 1
        end

        # get timestamps
        timestamps = []
        if num_ts > 0
          delta_la, ts, buffer = buffer.unpack 'CL>a*'
          timestamps << [delta_la+lack, ts]
          while num_ts > 1
            delta_lan, tspn, buffer = buffer.unpack 'CS>a*'
            timestamps << [delta_lan+lack, decode_timestamp_delta(tspn)]
            num_ts -= 1
          end
        end

        ranges = []
        prev = lack
        acks.each do |gap, block|
          start = prev
          start += gap if gap
          if gap.nil? || block > 0
            ranges << (start..start+block)
          end
          prev = start + block
        end

        [new(ranges, ack_delay, timestamps), buffer]
      end
      # in: int (encodes 16-bit float)
      # out: rational (seconds)
      def decode_timestamp_delta bits
        exp = (bits & 0b11111000_00000000) >> 11
        mnt = (bits & 0b00000111_11111111)

        if exp > 0
          mnt |= 0b00001000_00000000
          mnt <<= exp
        end

        Rational(mnt, 1_000_000)
      end
      # in: numeric (seconds)
      # out: int (encodes 16-bit float)
      def encode_timestamp_delta seconds
        us = (seconds * 1_000_000).to_i
        return us if us <= 0x7ff

        shift = Math.log2(us).floor - 1
        exp = shift - 10
        mnt = us ^ (2 << shift)

        (exp << 11) | mnt
      end
    end
  end
end
