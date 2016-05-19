require 'spec_helper'
describe 'ipsec_tunnel::config' do
let(:pre_condition) { 'class { "ipsec_tunnel": service_name => "ipsec",}'}
let(:facts) { {:osfamily => 'RedHat'}}
  context "ipsec_tunnel class without any parameters" do
    it { is_expected.to create_file('/etc/ipsec.conf').with({
      :owner   => 'root',
      :mode    => '0400',
      :notify  => 'Service[ipsec]',
      })
    }
  end
  context "ipsec_tunnel::config should initialize NSS database" do
    it { is_expected.to create_ipsec_tunnel__nss__init_db('NSSDB /etc/ipsec.d').with({
      :require  => 'File[/etc/ipsec.conf]',
      :notify   => "Class[Ipsec_tunnel::Nsspki]"
      })
    }
  end
end
