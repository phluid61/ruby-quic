# encoding: BINARY

puts '###', '### Testing QUIC::Frame.parse', '###'

require_relative 'lib/ruby-quic/frame'

frame_buffers = [
  # STREAM
  [0b11_0_00_01_1, 1, 1, 11, 'Hello world'].pack('CCS>S>a11'),
  # ACK
  [0b101_1_00_00, 1, 2, 100, 0x801,  1,4,5,  1,1_000_000,10,0x7ff ].pack('CCCCS>C3CL>CS>'),
  # MAX_DATA
  [0x04, 100_000_000].pack('CQ>'),
  # MAX_STREAM_DATA
  [0x05, 2, 100_000].pack('CL>Q>'),
  # MAX_STREAM_ID
  [0x06, 9999].pack('CL>'),
  # BLOCKED
  [0x08].pack('C'),
  # STREAM_BLOCKED
  [0x09, 3].pack('CL>'),
  # STREAM_ID_NEEDED
  [0x0a].pack('C'),
  # RST_STREAM
  [0x01, 4, 666, 11111].pack('CL>L>Q>'),
  # PADDING
  [0x00].pack('C'),
  # PING
  [0x07].pack('C'),
  # NEW_CONNECTION_ID
  [0x0b, 8888, 5].pack('CS>Q>'),
  # CONNECTION_CLOSE
  [0x02, 666, 2, ':('].pack('CL>S>a2'),
  # GOAWAY
  [0x03, 98, 99].pack('CL>L>'),
  # STREAM(fin)
  [0b11_1_00_00_0, 6, 'Goodbye world'].pack('CCa13'),
]

whole_buffer = frame_buffers.join

begin
  frames = QUIC::Frame.parse(whole_buffer) {|f| p f }
  puts frames.length
rescue Exception => ex
  puts ex, *ex.backtrace.map{|b|"  #{b}"}
end

