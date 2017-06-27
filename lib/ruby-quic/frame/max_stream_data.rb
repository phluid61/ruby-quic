# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class MAX_STREAM_DATA < QUIC::Frame
    Type = 0x05
    def initialize streamid, maxdata
      @streamid = streamid
      @maxdata = maxdata
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, streamid, maxdata, buffer = buffer.unpack 'CL>Q>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(streamid, maxdata), buffer]
      end
    end
  end
end
