# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

module QUIC::Hash
  INITIAL = 0xcbf29ce484222325
  PRIME   = 0x100000001b3
  def self.hash bytes
    v = INITIAL
    bytes.each_byte do |b|
      v ^= b
      v *= PRIME
      v &= 0xffffffffffffffff
    end
    [v].pack('Q>')
  end
end

