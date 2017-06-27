# encoding: BINARY

require_relative 'lib/ruby-quic/frame'

single_buffers = [
  # STREAM
  #  11_F_SS_OO_D  StreamID       Offset DataLength StreamData
  [0b11_0_00_00_0, 0x00_00_00_01,                   'Hello world'].pack('CCa11'),
  [0b11_1_00_00_0, 0x00_00_00_02,                   'Hello world'].pack('CCa11'),
  [0b11_1_00_00_0, 0x00_00_00_03,                   ].pack('CC'),
  [0b11_0_01_00_0, 0x00_00_00_04,                   'Hello world'].pack('CS>a11'),
  [0b11_1_01_00_0, 0x00_00_00_05,                   'Hello world'].pack('CS>a11'),
  [0b11_1_01_00_0, 0x00_00_00_06,                   ].pack('CS>'),
  [0b11_0_10_00_0, 0x00,0x00_07,                    'Hello world'].pack('CCS>a11'),
  [0b11_1_10_00_0, 0x00,0x00_08,                    'Hello world'].pack('CCS>a11'),
  [0b11_1_10_00_0, 0x00,0x00_09,                    ].pack('CCS>'),
  [0b11_0_11_00_0, 0x00_00_00_0a,                   'Hello world'].pack('CL>a11'),
  [0b11_1_11_00_0, 0x00_00_00_0b,                   'Hello world'].pack('CL>a11'),
  [0b11_1_11_00_0, 0x00_00_00_0c,                   ].pack('CL>'),

  [0b11_0_00_01_0, 0x00_00_00_01, 1,                'Hello world'].pack('CCS>a11'),
  [0b11_1_00_01_0, 0x00_00_00_02, 1,                'Hello world'].pack('CCS>a11'),
  [0b11_1_00_01_0, 0x00_00_00_03, 1,                ].pack('CCS>'),
  [0b11_0_01_01_0, 0x00_00_00_04, 1,                'Hello world'].pack('CS>S>a11'),
  [0b11_1_01_01_0, 0x00_00_00_05, 1,                'Hello world'].pack('CS>S>a11'),
  [0b11_1_01_01_0, 0x00_00_00_06, 1,                ].pack('CS>S>'),
  [0b11_0_10_01_0, 0x00,0x00_07,  1,                'Hello world'].pack('CCS>S>a11'),
  [0b11_1_10_01_0, 0x00,0x00_08,  1,                'Hello world'].pack('CCS>S>a11'),
  [0b11_1_10_01_0, 0x00,0x00_09,  1,                ].pack('CCS>S>'),
  [0b11_0_11_01_0, 0x00_00_00_0a, 1,                'Hello world'].pack('CL>S>a11'),
  [0b11_1_11_01_0, 0x00_00_00_0b, 1,                'Hello world'].pack('CL>S>a11'),
  [0b11_1_11_01_0, 0x00_00_00_0c, 1,                ].pack('CL>S>'),

  [0b11_0_00_10_0, 0x00_00_00_01, 1,                'Hello world'].pack('CCL>a11'),
  [0b11_1_00_10_0, 0x00_00_00_02, 1,                'Hello world'].pack('CCL>a11'),
  [0b11_1_00_10_0, 0x00_00_00_03, 1,                ].pack('CCL>'),
  [0b11_0_01_10_0, 0x00_00_00_04, 1,                'Hello world'].pack('CS>L>a11'),
  [0b11_1_01_10_0, 0x00_00_00_05, 1,                'Hello world'].pack('CS>L>a11'),
  [0b11_1_01_10_0, 0x00_00_00_06, 1,                ].pack('CS>L>'),
  [0b11_0_10_10_0, 0x00,0x00_07,  1,                'Hello world'].pack('CCS>L>a11'),
  [0b11_1_10_10_0, 0x00,0x00_08,  1,                'Hello world'].pack('CCS>L>a11'),
  [0b11_1_10_10_0, 0x00,0x00_09,  1,                ].pack('CCS>L>'),
  [0b11_0_11_10_0, 0x00_00_00_0a, 1,                'Hello world'].pack('CL>L>a11'),
  [0b11_1_11_10_0, 0x00_00_00_0b, 1,                'Hello world'].pack('CL>L>a11'),
  [0b11_1_11_10_0, 0x00_00_00_0c, 1,                ].pack('CL>L>'),

  [0b11_0_00_11_0, 0x00_00_00_01, 1,                'Hello world'].pack('CCQ>a11'),
  [0b11_1_00_11_0, 0x00_00_00_02, 1,                'Hello world'].pack('CCQ>a11'),
  [0b11_1_00_11_0, 0x00_00_00_03, 1,                ].pack('CCQ>'),
  [0b11_0_01_11_0, 0x00_00_00_04, 1,                'Hello world'].pack('CS>Q>a11'),
  [0b11_1_01_11_0, 0x00_00_00_05, 1,                'Hello world'].pack('CS>Q>a11'),
  [0b11_1_01_11_0, 0x00_00_00_06, 1,                ].pack('CS>Q>'),
  [0b11_0_10_11_0, 0x00,0x00_07,  1,                'Hello world'].pack('CCS>Q>a11'),
  [0b11_1_10_11_0, 0x00,0x00_08,  1,                'Hello world'].pack('CCS>Q>a11'),
  [0b11_1_10_11_0, 0x00,0x00_09,  1,                ].pack('CCS>Q>'),
  [0b11_0_11_11_0, 0x00_00_00_0a, 1,                'Hello world'].pack('CL>Q>a11'),
  [0b11_1_11_11_0, 0x00_00_00_0b, 1,                'Hello world'].pack('CL>Q>a11'),
  [0b11_1_11_11_0, 0x00_00_00_0c, 1,                ].pack('CL>Q>'),

  [0b11_0_00_00_1, 0x00_00_00_01,        11,        'Hello worldxxx'].pack('CCS>a14'),
  [0b11_1_00_00_1, 0x00_00_00_02,        11,        'Hello worldxxx'].pack('CCS>a14'),
  [0b11_1_00_00_1, 0x00_00_00_03,         0,        'xxx'].pack('CCS>a3'),
  [0b11_0_01_00_1, 0x00_00_00_04,        11,        'Hello worldxxx'].pack('CS>S>a14'),
  [0b11_1_01_00_1, 0x00_00_00_05,        11,        'Hello worldxxx'].pack('CS>S>a14'),
  [0b11_1_01_00_1, 0x00_00_00_06,         0,        'xxx'].pack('CS>S>a3'),
  [0b11_0_10_00_1, 0x00,0x00_07,         11,        'Hello worldxxx'].pack('CCS>S>a14'),
  [0b11_1_10_00_1, 0x00,0x00_08,         11,        'Hello worldxxx'].pack('CCS>S>a14'),
  [0b11_1_10_00_1, 0x00,0x00_09,          0,        'xxx'].pack('CCS>S>a3'),
  [0b11_0_11_00_1, 0x00_00_00_0a,        11,        'Hello worldxxx'].pack('CL>S>a14'),
  [0b11_1_11_00_1, 0x00_00_00_0b,        11,        'Hello worldxxx'].pack('CL>S>a14'),
  [0b11_1_11_00_1, 0x00_00_00_0c,         0,        'xxx'].pack('CL>S>a3'),

  [0b11_0_00_01_1, 0x00_00_00_01, 1,     11,        'Hello worldxxx'].pack('CCS>S>a14'),
  [0b11_1_00_01_1, 0x00_00_00_02, 1,     11,        'Hello worldxxx'].pack('CCS>S>a14'),
  [0b11_1_00_01_1, 0x00_00_00_03, 1,      0,        'xxx'].pack('CCS>S>a3'),
  [0b11_0_01_01_1, 0x00_00_00_04, 1,     11,        'Hello worldxxx'].pack('CS>S>S>a14'),
  [0b11_1_01_01_1, 0x00_00_00_05, 1,     11,        'Hello worldxxx'].pack('CS>S>S>a14'),
  [0b11_1_01_01_1, 0x00_00_00_06, 1,      0,        'xxx'].pack('CS>S>S>a3'),
  [0b11_0_10_01_1, 0x00,0x00_07,  1,     11,        'Hello worldxxx'].pack('CCS>S>S>a14'),
  [0b11_1_10_01_1, 0x00,0x00_08,  1,     11,        'Hello worldxxx'].pack('CCS>S>S>a14'),
  [0b11_1_10_01_1, 0x00,0x00_09,  1,      0,        'xxx'].pack('CCS>S>S>a3'),
  [0b11_0_11_01_1, 0x00_00_00_0a, 1,     11,        'Hello worldxxx'].pack('CL>S>S>a14'),
  [0b11_1_11_01_1, 0x00_00_00_0b, 1,     11,        'Hello worldxxx'].pack('CL>S>S>a14'),
  [0b11_1_11_01_1, 0x00_00_00_0c, 1,      0,        'xxx'].pack('CL>S>S>a3'),

  [0b11_0_00_10_1, 0x00_00_00_01, 1,     11,        'Hello worldxxx'].pack('CCL>S>a14'),
  [0b11_1_00_10_1, 0x00_00_00_02, 1,     11,        'Hello worldxxx'].pack('CCL>S>a14'),
  [0b11_1_00_10_1, 0x00_00_00_03, 1,      0,        'xxx'].pack('CCL>S>a3'),
  [0b11_0_01_10_1, 0x00_00_00_04, 1,     11,        'Hello worldxxx'].pack('CS>L>S>a14'),
  [0b11_1_01_10_1, 0x00_00_00_05, 1,     11,        'Hello worldxxx'].pack('CS>L>S>a14'),
  [0b11_1_01_10_1, 0x00_00_00_06, 1,      0,        'xxx'].pack('CS>L>S>a3'),
  [0b11_0_10_10_1, 0x00,0x00_07,  1,     11,        'Hello worldxxx'].pack('CCS>L>S>a14'),
  [0b11_1_10_10_1, 0x00,0x00_08,  1,     11,        'Hello worldxxx'].pack('CCS>L>S>a14'),
  [0b11_1_10_10_1, 0x00,0x00_09,  1,      0,        'xxx'].pack('CCS>L>S>a3'),
  [0b11_0_11_10_1, 0x00_00_00_0a, 1,     11,        'Hello worldxxx'].pack('CL>L>S>a14'),
  [0b11_1_11_10_1, 0x00_00_00_0b, 1,     11,        'Hello worldxxx'].pack('CL>L>S>a14'),
  [0b11_1_11_10_1, 0x00_00_00_0c, 1,      0,        'xxx'].pack('CL>L>S>a3'),

  [0b11_0_00_11_1, 0x00_00_00_01, 1,     11,        'Hello worldxxx'].pack('CCQ>S>a14'),
  [0b11_1_00_11_1, 0x00_00_00_02, 1,     11,        'Hello worldxxx'].pack('CCQ>S>a14'),
  [0b11_1_00_11_1, 0x00_00_00_03, 1,      0,        'xxx'].pack('CCQ>S>a3'),
  [0b11_0_01_11_1, 0x00_00_00_04, 1,     11,        'Hello worldxxx'].pack('CS>Q>S>a14'),
  [0b11_1_01_11_1, 0x00_00_00_05, 1,     11,        'Hello worldxxx'].pack('CS>Q>S>a14'),
  [0b11_1_01_11_1, 0x00_00_00_06, 1,      0,        'xxx'].pack('CS>Q>S>a3'),
  [0b11_0_10_11_1, 0x00,0x00_07,  1,     11,        'Hello worldxxx'].pack('CCS>Q>S>a14'),
  [0b11_1_10_11_1, 0x00,0x00_08,  1,     11,        'Hello worldxxx'].pack('CCS>Q>S>a14'),
  [0b11_1_10_11_1, 0x00,0x00_09,  1,      0,        'xxx'].pack('CCS>Q>S>a3'),
  [0b11_0_11_11_1, 0x00_00_00_0a, 1,     11,        'Hello worldxxx'].pack('CL>Q>S>a14'),
  [0b11_1_11_11_1, 0x00_00_00_0b, 1,     11,        'Hello worldxxx'].pack('CL>Q>S>a14'),
  [0b11_1_11_11_1, 0x00_00_00_0c, 1,      0,        'xxx'].pack('CL>Q>S>a3'),
]

single_buffers.each do |buffer|
  begin
    frame, rest = QUIC::Frame.parse_one buffer
    p [frame, rest]
  rescue Exception => ex
    puts ex
  end
end

