# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

require_relative 'packet'

class QUIC::Connection
  def initialize id, addr
    @id = id
    @state = 0

    @addr = addr

    #@tls = ...
    #@tls.set_up_stuff(addr)
    ## TLS Extn: quic_transport_parameters(26)
    #@params = TransportParameters.parse(@tls.get_extension(26))
    @key = "\xa5\xa5\x0f"
  end
  attr_reader :id, :state, :key
  attr_writer :key

  def recv packet
    packet.connection = self
    case @state
    # etc...
    end
  end
end

