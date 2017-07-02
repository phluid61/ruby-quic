# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class RST_STREAM < QUIC::Frame
    Type = 0x01
    def initialize streamid, error_code, final_offset
      @streamid = streamid
      @error_code = error_code
      @final_offset = final_offset
    end
    def serialize
      [Type, @streamid, @error_code, @final_offset].pack 'CL>L>Q>'
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, streamid, error_code, final_offset, buffer = buffer.unpack 'CL>L>Q>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(streamid, error_code, final_offset), buffer]
      end
    end
  end
end
