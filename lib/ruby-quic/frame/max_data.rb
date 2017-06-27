# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class MAX_DATA < QUIC::Frame
    Type = 0x04
    def initialize maxdata
      @maxdata = maxdata
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, maxdata, buffer = buffer.unpack 'CQ>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(maxdata), buffer]
      end
    end
  end
end
