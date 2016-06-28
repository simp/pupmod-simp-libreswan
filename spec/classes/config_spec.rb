require 'spec_helper'
describe 'libreswan::config' do
let(:pre_condition) { 'class { "libreswan": service_name => "ipsec",}'}
let(:facts) {{:osfamily => 'RedHat'}}
  context "libreswan class without any parameters" do
    it { is_expected.to create_file('/etc/ipsec.conf').with({
      :owner   => 'root',
      :mode    => '0400',
      :notify  => 'Service[ipsec]',
      })
    }
    it { is_expected.to create_file('/etc/ipsec.secrets').with({
      :owner   => 'root',
      :mode    => '0400',
      })
    }
  end
  context "libreswan::config should initialize NSS database" do
    it { is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
      :require  => 'File[/etc/ipsec.conf]',
      :notify   => "Class[Libreswan::Nsspki]",
      })
    }
  end
end
