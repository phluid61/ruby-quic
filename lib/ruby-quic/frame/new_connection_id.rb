# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class NEW_CONNECTION_ID < QUIC::Frame
    Type = 0x0b
    def initialize sequence, connection_id
      @sequence = sequence
      @connection_id = connection_id
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, seq, connection_id, buffer = buffer.unpack 'CS>Q>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(seq, connection_id), buffer]
      end
    end
  end
end
