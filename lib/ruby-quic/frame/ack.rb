# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class ACK < QUIC::Frame
    Type = (0xa0..0xbf)
    def initialize largest_ack, ack_delay, acks, timestamps
      @largest_ack = largest_ack
      @ack_delay = ack_delay
      #@acks = acks
      #@timestamps = timestamps
      @timestamps = timestamps.map {|offs,ts| [largest_ack+offs, ts] }

      @ranges = []
      start = largest_ack
      acks.each_with_index do |n, i|
        if i % 2 == 0
          @ranges << (start..start+n)
        end
        start += n
      end
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
          format = 'CQ>S>a*'
        end
        num_ts, lack, ack_delay, buffer = buffer.unpack format
        ack_delay = get_timestamp_delta(ack_delay)

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
        acks = [block]
        while num_blocks > 0
          gap, block, buffer = buffer.unpack format
          acks << gap
          acks << block
          num_blocks -= 1
        end

        # get timestamps
        timestamps = []
        if num_ts > 0
          delta_la, ts, buffer = buffer.unpack 'CL>a*'
          timestamps << [delta_la, ts]
          while num_ts > 1
            delta_lan, tspn, buffer = buffer.unpack 'CS>a*'
            timestamps << [delta_lan, get_timestamp_delta(tspn)]
            num_ts -= 1
          end
        end

        [new(lack, ack_delay, acks, timestamps), buffer]
      end
      # in: int (encodes 16-bit float)
      # out: rational (microseconds)
      def get_timestamp_delta bits
        exp = (bits & 0b11111000_00000000) >> 11
        mnt = (bits & 0b00000111_11111111)

        if exp > 0
          mnt |= 0b00001000_00000000
          mnt <<= exp
        end

        Rational(mnt, 1_000_000)
      end
    end
  end
end
