# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class STREAM_ID_NEEDED < QUIC::Frame
    Type = 0x0a
    Bytes = "\x0a"
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
