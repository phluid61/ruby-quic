# encoding: BINARY
# frozen_string_literal: true

require_relative 'quic'
require 'mug/bittest'

module QUIC::Frame
  class <<self
    def parse buffer #, packet_number_length
      type, buffer = buffer.unpack 'Ca*'

      case type
      when 0x00
        ::QUIC::Frame::PADDING.parse buffer
      when 0x01
        ::QUIC::Frame::RST_STREAM.parse buffer
      when 0x02
        ::QUIC::Frame::CONNECTION_CLOSE.parse buffer
      when 0x03
        ::QUIC::Frame::GOAWAY.parse buffer
      when 0x04
        ::QUIC::Frame::WINDOW_UPDATE.parse buffer
      when 0x05
        ::QUIC::Frame::BLOCKED.parse buffer
      when 0x06
        ::QUIC::Frame::STOP_WAITING.parse buffer #, packet_number_length
      when 0x07
        ::QUIC::Frame::PING.parse buffer
      else
        if type.and? 0b10000000
          ::QUIC::Frame::STREAM.parse type, buffer
        elsif (type & 0b11000000) == 0b01000000
          ::QUIC::Frame::ACK.parse type, buffer
        else
          raise "unrecognised frame type #{'%02X' % type}"
        end
      end
    end
  end
end

class QUIC::Frame::STREAM
  class <<self
    def parse type, buffer
      _F = type.and? 0b01000000
      _D = type.and? 0b00100000
      _O = (type & 0b00011100) >> 2
      _S = (type & 0b00000011)

      stream_id = 0
      _S.times do
        s, buffer = buffer.unpack 'Ca*'
        stream_id = (stream_id << 8) | s
      end

      offset = 0
      if _O != 0
        _O.times do
          o, buffer = buffer.unpack 'Ca*'
          offset = (offset << 8) | o
        end
      end

      if _D
        data_length, buffer = buffer.unpack 'na*'
        data = buffer.byteslice 0, data_length
        buffer = buffer.byteslice data_length, -1
      else
        raise "A STREAM frame MUST have either non-zero data length or the FIN bit set." unless _F
        data = buffer
        buffer = +''.b
      end

      [self.new(stream_id, offset, data), buffer]
    end
  end

  def initialize stream_id, offset, data
    @stream_id = stream_id
    @offset = offset
    @data = data
  end
end

class QUIC::Frame::ACK
  class <<self
    def parse type, buffer
      _N = type.and? 0b00100000
      #U = type.and? 0b00010000
      _L = (type & 0b00001100) >> 1 ; _L = 1 if _L.zero?
      _M = (type & 0b00000011) << 1 ; _M = 1 if _M.zero?

      largest_acked = 0
      _L.times do
        l, buffer = buffer.unpack 'Ca*'
        largest_acked = (largest_acked << 8) | l
      end

      ack_delay, buffer = buffer.unpack 'na*'

      num_blocks = 0
      if _N
        num_blocks, buffer = buffer.unpack 'Ca*'
      end

      blocks = []
      (num_blocks + 1).times do |i|
        if i > 0
          gap_to_next_block, buffer = buffer.unpack 'Ca*'
          blocks << gap_to_next_block
        end

        ack_block_length = 0
        _M.times do
          m, buffer = buffer.unpack 'Ca*'
          ack_block_length = (ack_block_length << 8) | m
        end
        blocks << ack_block_length
      end

      num_timestamps, buffer = buffeer.inpack 'Ca*'
      raise "ACK timestamps currently not supported" if num_timestamps > 0 # XXX

      [self.new(largest_acked, ack_delay, blocks), buffer]
    end
  end

  def initialize largest_acked, ack_delay, blocks
    @largest_acked = largest_acked
    @ack_delay = ack_delay
    @blocks = blocks
  end
end

class QUIC::Frame::STOP_WAITING
  class <<self
    def parse buffer #, packet_number_length
      raise 'not implemented yet' # XXX
    end
  end

  def initialize least_delta
    @least_delta = least_delta
  end
end

class QUIC::Frame::WINDOW_UPDATE
  class <<self
    def parse buffer
      stream_id, byte_offset, buffer = buffer.unpack 'NQ>a*'

      [self.new(stream_id, byte_offset), buffer]
    end
  end

  def initialize stream_id, byte_offset
    @stream_id = stream_id
    @byte_offset = byte_offset
  end
end

class QUIC::Frame::BLOCKED
  class <<self
    def parse buffer
      stream_id, buffer = buffer.unpack 'Na*'

      [self.new(stream_id), buffer]
    end
  end

  def initialize
  end
end

class QUIC::Frame::PADDING
  class <<self
    def parse buffer
      [self.new, +''.b]
    end
  end

  def initialize
  end
end

class QUIC::Frame::PING
  class <<self
    def parse buffer
      [self.new, buffer]
    end
  end

  def initialize
  end
end

class QUIC::Frame::CONNECTION_CLOSE
  class <<self
    def parse buffer
      error_code, reason_phrase_length, buffer = buffer.unpack 'Nna*'

      reason_phrase = buffer.byteslice 0, reason_phrase_length
      buffer = buffer.byteslice reason_phrase_length, -1

      [self.new(error_code, reason_phrase), buffer]
    end
  end

  def initialize error_code, reason_phrase
    @error_code = error_code
    @reason_phrase = reason_phrase
  end
end

class QUIC::Frame::GOAWAY
  class <<self
    def parse buffer
      error_code, last_good_stream_id, reason_phrase_length, buffer = buffer.unpack 'NNna*'

      reason_phrase = buffer.byteslice 0, reason_phrase_length
      buffer = buffer.byteslice reason_phrase_length, -1

      [self.new(error_code, last_good_stream_id, reason_phrase), buffer]
    end
  end

  def initialize error_code, last_good_stream_id, reason_phrase
    @error_code = error_code
    @last_good_stream_id = last_good_stream_id
    @reason_phrase = reason_phrase
  end
end

