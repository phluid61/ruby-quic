# encoding: BINARY
# frozen_string_literal: true

require_relative 'quic'
require_relative 'connection'
require_relative 'packet'

require 'socket'

module QUIC
end

class QUIC::Server

  def initialize
    @connections = []

    @sock = UDPSocket.new
    @sock.bind('127.0.0.1', 443)
  end

  def recv
    # max size of UDP datagram = 65527
    mesg, addr = @sock.recvfrom(65527)

    packet = QUIC::Packet.parse mesg
    case packet
    when QUIC::OutversionPacket
      renegotiate_version(addr)
    when QUIC::ClientInitialPacket
      # ignore client's connection-id
      cid = @connections.length # lol
      conn = QUIC::Connection.new cid, addr
      @connections[cid] = conn

      conn.tls_engine.set_up_stuff(addr)
      conn.recv(packet)
    else
      cid = packet.connection_id
      if packet.connection_id == 0
        # handle server message
      else
        # look up connection
        conn = @connections[cid]
        if conn.nil?
          # 404 Barf
        else
          conn.recv packet
        end
      end
    end
  end

end

