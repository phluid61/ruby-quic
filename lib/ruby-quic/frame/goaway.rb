# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::Frame
  class GOAWAY < QUIC::Frame
    Type = 0x03
    def initialize largest_client_streamid, largest_server_streamid
      @largest_client_streamid = largest_client_streamid
      @largest_server_streamid = largest_server_streamid
    end
    class <<self
      # in: buffer
      # out: frame, buffer
      def parse_one buffer
        type, lcsid, lssid, buffer = buffer.unpack 'CL>L>a*'
        raise "BUG: frame type 0x#{type.to_s(16)} not #{name}" unless type == Type
        [new(lcsid, lssid), buffer]
      end
    end
  end
end
