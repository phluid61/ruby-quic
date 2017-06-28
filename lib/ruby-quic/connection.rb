# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

require_relative 'packet'

class QUIC::Connection
  def initialize
    @state = 0
    @key = "\xa5\xa5\x0f"
  end
  attr_reader :state, :key
end

