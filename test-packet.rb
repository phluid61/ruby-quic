# encoding: BINARY

def red o
  "\x1B[31m#{o}\x1B[0m"
end
def blue o
  "\x1B[94m#{o}\x1B[0m"
end
def teal o
  "\x1B[36m#{o}\x1B[0m"
end

puts '###', '### Testing QUIC::Packet.parse', '###'

require_relative 'lib/ruby-quic/packet'
require_relative 'lib/ruby-quic/connection'

s1 = QUIC::Frame::STREAM.new(0, 0, 'abcd', false).serialize
s2 = QUIC::Frame::STREAM.new(0, 0, 'wxyz', false).serialize
s3 = QUIC::Frame::STREAM.new(0, 0, 'banana', false).serialize
s4 = QUIC::Frame::STREAM.new(0, 0, 'foobar baz', false).serialize

ack1 = QUIC::Frame::ACK.new([2..2,4..6], 1/1000r, [[4,1/100r], [5,1/5000r], [6,1/100_000r]]).serialize

encrypted = "\x64\xA5\x0F\xAE\xED\x6A\xC9\xC9\x60\x85\xF2\x60\xD7\xC9\x6B\xA5"

udp_payloads = [
  ["\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x04""\xff\x00\x00\x04", "Version Negotiation"],
  ["\x82\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x00\x02\xff\x00\x00\x04"+s1+"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",   "Client Initial"],
  ["\x83\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x00\x02\xff\x00\x00\x04"+s2+ack1+"\x00\x00\x00\x00", "Server Stateless Retry"],
  ["\x84\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\xff\x00\x00\x04""\xc1\x00\x00\x05klmno""\xa0\x00\x03\x03\xe8\x00""\x00\x00\x00\x00", "Server Cleartext"],
  ["\x85\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\xff\x00\x00\x04""\xc1\x00\x00\x05pqrst""\xa0\x00\x04\x03\xe8\x00""\x00\x00\x00\x00", "Client Cleartext"],
  ["\x86\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x06\xff\x00\x00\x04"+encrypted, "0-RTT Protected"],
  ["\x87\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x07\xff\x00\x00\x04"+encrypted, "1-RTT Protected (key phase 0)"],
  ["\x88\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x08\xff\x00\x00\x04"+encrypted, "1-RTT Protected (key phase 1)"],
  ["\x89\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x09\xff\x00\x00\x04", "Public Reset"],

  ["\x01\x81"+encrypted, "1-RTT Protected (key phase 0, no CID)"],
  ["\x02\x80\x01"+encrypted, "1-RTT Protected (key phase 0, no CID)"],
  ["\x03\x80\x00\x00\x01"+encrypted, "1-RTT Protected (key phase 0, no CID)"],
  ["\x21\x81"+encrypted, "1-RTT Protected (key phase 1, no CID)"],
  ["\x22\x80\x01"+encrypted, "1-RTT Protected (key phase 1, no CID)"],
  ["\x23\x80\x00\x00\x01"+encrypted, "1-RTT Protected (key phase 1, no CID)"],
  ["\x41\x00\x00\x00\x00\x00\x00\x00\x10\x81"+encrypted, "1-RTT Protected (key phase 0, CID)"],
  ["\x42\x00\x00\x00\x00\x00\x00\x00\x11\x80\x01"+encrypted, "1-RTT Protected (key phase 0, CID)"],
  ["\x43\x00\x00\x00\x00\x00\x00\x00\x12\x80\x00\x00\x01"+encrypted, "1-RTT Protected (key phase 0, CID)"],
  ["\x61\x00\x00\x00\x00\x00\x00\x00\x13\x81"+encrypted, "1-RTT Protected (key phase 1, CID)"],
  ["\x62\x00\x00\x00\x00\x00\x00\x00\x14\x80\x01"+encrypted, "1-RTT Protected (key phase 1, CID)"],
  ["\x63\x00\x00\x00\x00\x00\x00\x00\x15\x80\x00\x00\x01"+encrypted, "1-RTT Protected (key phase 1, CID)"],
]

udp_payloads.each do |udp_payload|
  if udp_payload.is_a? Array
    puts "#{blue udp_payload.pop}:"
    udp_payload = udp_payload.first
  end
  begin
    packet = QUIC::Packet.parse udp_payload
    p packet
    case packet
    when QUIC::Packet::VersionNegotiationPacket
      packet.versions.each{|v|puts('  %08x' % v)}
    when QUIC::Packet::CleartextPacket
      packet.frames.each{|f|puts "  #{f.inspect}"}
    when QUIC::Packet::ProtectedPacket
      packet.connection = QUIC::Connection.new
      packet.frames.each{|f|puts "  #{f.inspect}"}
    when QUIC::Packet::PublicResetPacket
      # ...
    else
      raise '??? unknown class'
    end
  rescue Exception => ex
    puts red(ex), *ex.backtrace.map{|b|"  #{red b}"}
  end
end

