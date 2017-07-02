# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class MAX_STREAM_ID < QUIC::Frame
    Type = 0x06
    def initialize maxstreamid
      @maxstreamid = maxstreamid
    end
    def serialize
      [Type, @maxstreamid].pack 'CL>'
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
