# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class CONNECTION_CLOSE < QUIC::Frame
    Type = 0x02
    def initialize error_code, reason_phrase
      @error_code = error_code
      @reason_phrase = reason_phrase
    end
    def serialize
      [Type, @error_code, @reason_phrase.bytesize, @reason_phrase].pack 'CL>S>a*'
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, error_code, reason_len, buffer = buffer.unpack 'CL>S>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        if reason_len > 0
          reason, buffer = buffer.unpack "a#{reason_len}a*"
        end
        [new(error_code, reason), buffer]
      end
    end
  end
end
