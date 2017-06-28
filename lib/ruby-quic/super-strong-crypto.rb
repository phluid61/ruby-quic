# encoding: BINARY
# frozen_string_literal: true

def decrypt cipher, key
  kbytes = key.bytes
  cipher.bytes.each_slice(kbytes.length).map{|cbytes|cbytes.zip(kbytes).map{|c,k|[c^k].pack 'C'}.join}.join
end
alias :encrypt :decrypt

