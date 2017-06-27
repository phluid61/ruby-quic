# encoding: BINARY
# frozen_string_literal: true

require_relative 'frame/padding'
require_relative 'frame/rst_stream'
require_relative 'frame/connection_close'
require_relative 'frame/goaway'
require_relative 'frame/max_data'
require_relative 'frame/max_stream_data'
require_relative 'frame/max_stream_id'
require_relative 'frame/ping'
require_relative 'frame/blocked'
require_relative 'frame/stream_blocked'
require_relative 'frame/stream_id_needed'
require_relative 'frame/new_connection_id'
require_relative 'frame/ack'
require_relative 'frame/stream'

module QUIC
end

class QUIC::Frame
  class <<self
    def parse buffer
      frames = []
      until buffer.empty?
        frame, buffer = parse_one buffer
        yield frame if block_given?
        frames << frame
      end
      frames
    end
    def parse_one buffer
      type = buffer.unpack('C').first
      case type
      when PADDING::Type
        PADDING.parse_one buffer
      when RST_STREAM::Type
        RST_STREAM.parse_one buffer
      when CONNECTION_CLOSE::Type
        CONNECTION_CLOSE.parse_one buffer
      when GOAWAY::Type
        GOAWAY.parse_one buffer
      when MAX_DATA::Type
        MAX_DATA.parse_one buffer
      when MAX_STREAM_DATA::Type
        MAX_STREAM_DATA.parse_one buffer
      when MAX_STREAM_ID::Type
        MAX_STREAM_ID.parse_one buffer
      when PING::Type
        PING.parse_one buffer
      when BLOCKED::Type
        BLOCKED.parse_one buffer
      when STREAM_BLOCKED::Type
        STREAM_BLOCKED.parse_one buffer
      when STREAM_ID_NEEDED::Type
        STREAM_ID_NEEDED.parse_one buffer
      when NEW_CONNECTION_ID::Type
        NEW_CONNECTION_ID.parse_one buffer
      when ACK::Type
        ACK.parse_one buffer
      when STREAM::Type
        STREAM.parse_one buffer
      else
        raise "unknown Frame type 0x#{type.to_s(16)}"
      end
    end
  end
end
