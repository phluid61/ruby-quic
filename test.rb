# encoding: BINARY

require_relative 'lib/ruby-quic/quic-packet'

udp_payloads = [
  "\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x04\xff\x00\x00\x04",
  "\x82\x11\x22\x33\x44\x55\x66\x77\x88\x00\x00\x00\x02\xff\x00\x00\x04Client Initial",
  "\x83\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\xff\x00\x00\x04Server Stateless Retry",
  "\x84\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\xff\x00\x00\x04Server Cleartext",
  "\x85\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\xff\x00\x00\x04Client Cleartext",
  "\x86\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x06\xff\x00\x00\x040-RTT Protected",
  "\x87\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x07\xff\x00\x00\x041-RTT Protected (key phase 0)",
  "\x87\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x08\xff\x00\x00\x041-RTT Protected (key phase 1)",
  "\x89\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x09\xff\x00\x00\x04Public Reset",
  "\x01\x811-RTT Protected (key phase 0, no CID)",
  "\x02\x80\x011-RTT Protected (key phase 0, no CID)",
  "\x03\x80\x00\x00\x011-RTT Protected (key phase 0, no CID)",
  "\x21\x811-RTT Protected (key phase 1, no CID)",
  "\x22\x80\x011-RTT Protected (key phase 1, no CID)",
  "\x23\x80\x00\x00\x011-RTT Protected (key phase 1, no CID)",
  "\x41\x00\x00\x00\x00\x00\x00\x00\x10\x811-RTT Protected (key phase 0, CID)",
  "\x42\x00\x00\x00\x00\x00\x00\x00\x11\x80\x011-RTT Protected (key phase 0, CID)",
  "\x43\x00\x00\x00\x00\x00\x00\x00\x12\x80\x00\x00\x011-RTT Protected (key phase 0, CID)",
  "\x61\x00\x00\x00\x00\x00\x00\x00\x13\x811-RTT Protected (key phase 1, CID)",
  "\x62\x00\x00\x00\x00\x00\x00\x00\x14\x80\x011-RTT Protected (key phase 1, CID)",
  "\x63\x00\x00\x00\x00\x00\x00\x00\x15\x80\x00\x00\x011-RTT Protected (key phase 1, CID)",
]

udp_payloads.each do |udp_payload|
  begin
    packet = QUICPacket.parse udp_payload
    p packet
  rescue Exception => ex
    puts ex
  end
end

