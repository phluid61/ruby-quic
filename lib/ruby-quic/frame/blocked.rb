# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class BLOCKED < QUIC::Frame
    Type = 0x08
    Bytes = "\x08"
    def serialize
      Bytes
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, buffer = buffer.unpack 'Ca*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(), buffer]
      end
    end
  end
end
