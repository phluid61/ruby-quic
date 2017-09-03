# encoding: BINARY
# frozen_string_literal: true

module QUIC
end

class QUIC::TransportParameter
  module ID
    MAP = {
      :initial_max_stream_data => 0,
      :initial_max_data => 1,
      :initial_max_stream_id => 2,
      :idle_timeout => 3,
      :omit_connection_id => 4,
      :max_packet_size => 5,
      :stateless_reset_token => 6,
    }.freeze
    class <<self
      def name_of value
        # works because Hash is ordered, and the enum is contiguous from 0
        MAP.keys[value]
      end
      alias :valid? :name_of

      def value_of name
        MAP[name.to_sym]
      end
      alias :[] :value_of
    end
  end

  def initialize id, value=''.freeze
    id = ID.value_of(id) unless id.is_a? Integer
    raise "invalid parameter id #{id}" unless ID.valid? id
    @id = id
    @value = value
  end
  attr_reader :id, :value
  def << bytes
    @value = (@value + bytes).freeze
    self
  end
  def serialize
    raise "value too long" if value.bytesize > 0xFFFF
    [@id, @value.bytesize, @value].pack 'S>S>a*'
  end
end

class QUIC::TransportParameters
  def initialize parameters=[]
    @parameters = {}
    parameters.each {|p| self << p }
  end
  def serialize
    [
      QUIC::TransportParameter::ID[:initial_max_stream_data],
      QUIC::TransportParameter::ID[:initial_max_data],
      QUIC::TransportParameter::ID[:initial_max_stream_id],
      QUIC::TransportParameter::ID[:idle_timeout],
      QUIC::TransportParameter::ID[:stateless_reset_token],
    ].each do |pid|
      raise "missing mandatory parameter #{QUIC::TransportParameter::ID.name_of pid}" unless @parameters[pid]
    end

    [@parameters.length].pack('S>') + @parameters.each_value.map(:serialize).join
  end
  def << param
    pid = param.id
    raise "invalid parameter id #{pid}" unless QUIC::TransportParameter::ID.valid? pid
    raise "duplicate parameter #{QUIC::TransportParameter::ID.name_of pid}" if @parameters[pid]
    @parameters[pid] = param
    self
  end

  class ClientHello < QUIC::TransportParameters
    def initialize negoatiated_version, initial_version, parameters
      @negotiated_version = negotiated_version
      @initial_version = initial_version
      super parameters
    end
    attr_reader :negotiated_version, :initial_version
    def serialize
      [@negotiated_version, @initial_version].pack('L>L>') + super
    end
  end
  class EncryptedExtensions < QUIC::TransportParameters
    def initialize supported_versions, parameters
      raise 'too many versions' if supported_versions.length > 63
      raise 'too few versions' if supported_versions.empty?
      @supported_versions = supported_versions
    end
    attr_reader :supported_versions
    def serialize
      [@supported_versions.length, *@supported_versions].pack('CL>*') + super
    end
  end
  class NewSessionTicket < QUIC::TransportParameters
  end
end
