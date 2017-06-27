# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class PING
    Type = 0x07
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
