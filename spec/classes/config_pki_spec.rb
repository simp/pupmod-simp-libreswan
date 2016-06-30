require 'spec_helper'

describe 'libreswan::config::pki' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:pre_condition) { 'class { "libreswan": service_name => "ipsec", use_simp_pki => true, certsource => "/etc/pki/ipsec" }'}


        context "libreswan::config should initialize NSS database" do
          it { is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
            :require  => 'File[/etc/ipsec.conf]',
            :notify   => "Class[Libreswan::Config::Pki::Nsspki]"
            })
          }
        end

        context "it should copy certs" do
          it { is_expected.to create_file('/etc/pki/ipsec').with({
              :ensure  => 'directory',
            })
          }
          it { is_expected.to create_pki__copy('/etc/pki/ipsec').with({
            :notify   => 'Class[Libreswan::Config::Pki::Nsspki]',
            :require  => 'File[/etc/pki/ipsec]',
            })
          }
        end
      end
    end
  end
end
