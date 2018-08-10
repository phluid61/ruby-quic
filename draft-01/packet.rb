# encoding: BINARY
# frozen_string_literal: true

require_relative 'quic'
require_relative 'frame'
require 'mug/bittest'

class QUIC::Packet
  module Flags
    VERSION               = 0x01

    PUBLIC_RESET          = 0x02

    KEY_PHASE             = 0x04

    CONNECTION_ID         = 0x08

    PACKET_NUMBER_SIZE    = 0x30
    PACKET_NUMBER_SIZE_6  = 0x30
    PACKET_NUMBER_SIZE_4  = 0x20
    PACKET_NUMBER_SIZE_2  = 0x10
    PACKET_NUMBER_SIZE_1  = 0x00

    MULTIPATH             = 0x40

    UNUSED                = 0x80
  end

  class <<self
    def parse buffer, from_server
      flags, buffer = buffer.unpack('Ca*')

      if flags.and? Flags::PUBLIC_RESET
        # Public Reset packet
        return ::QUIC::PublicResetPacket.parse flags, buffer
      elsif flags.and? Flags::VERSION
        if from_server
          # Version Negotiation packet
          return ::QUIC::VersionNegotiationPacket.parse flags, buffer
        else
          # Regular packet with QUIC Version in header
          version, buffer = buffer.unpack('Na*')
        end
      else
        # Regular packet with no QUIC Version in header
        version = nil
      end

      case flags & Flags::PACKET_NUMBER_SIZE
      when FLAGS::PACKET_NUMBER_SIZE_6
        numhi, numlo, buffer = buffer.unpack 'nNa*'
        number = (numhi << 32) | numlo
      when FLAGS::PACKET_NUMBER_SIZE_4
        number, buffer = buffer.unpack 'Na*'
      when FLAGS::PACKET_NUMBER_SIZE_2
        number, buffer = buffer.unpack 'na*'
      when FLAGS::PACKET_NUMBER_SIZE_1
        number, buffer = buffer.unpack 'Ca*'
      #else: bug
      end

      payload = decrypt(buffer) # XXX

      frames = []
      until payload.empty?
        frame, payload = ::QUIC::Frame.parse payload #, packet_number_length
        frames << frame
      end

      self.new flags, version, nonce, number, frames
    end

    def initialize flags, version, nonce, number, frames
      @flags = flags
      @version = version
      @nonce = nonce
      @number = number
      @frames = frames
    end
  end
end

class QUIC::VersionNegotiationPacket
  class <<self
    def parse flags, buffer
      connection_id, buffer = buffer.unpack 'Q>a*'
      raise "truncated Version Negotiation Packet" if buffer.bytesize % 4 != 0
      versions = buffer.unpack 'N*'
      self.new flags, versions
    end
  end

  def initialize flags, versions
    @flags = flags
    @versions = versions
  end
end

class QUIC::PublicResetPacket
  class <<self
    def parse flags, buffer
      connection_id, buffer = buffer.unpack 'Q>a*'

      payload = decrypt(buffer) # XXX

      self.new flags, payload
    end
  end

  def initialize flags, payload
    @flags = flags
    @payload = payload
  end
end

