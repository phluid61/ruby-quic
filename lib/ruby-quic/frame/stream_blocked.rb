# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class STREAM_BLOCKED < QUIC::Frame
    Type = 0x09
    def initialize streamid
      @streamid = streamid
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, streamid, buffer = buffer.unpack 'CL>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(streamid), buffer]
      end
    end
  end
end
