require 'spec_helper'

describe 'libreswan::config' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:pre_condition) { 'class { "libreswan": service_name => "ipsec",}'}

        context 'with default parameters' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan::config') }
        end
  
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
            :notify   => "Class[Libreswan::Nsspki]"
            })
          }
        end
      end
    end
  end
end
