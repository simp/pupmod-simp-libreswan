require 'spec_helper'

describe 'libreswan::config::pki' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        context "with pki true libreswan::config should init NSS db and copy certs" do
        let(:pre_condition) { 'class { "libreswan": service_name => "ipsec", pki => true,
          app_pki_external_source => "/etc/pki/simp-test", app_pki_dir => "/etc/foo" }'}

          it { is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
            :require  => 'File[/etc/ipsec.conf]',
            :notify   => "Class[Libreswan::Config::Pki::Nsspki]"
            })
          }
          it { is_expected.to create_file('/etc/foo').with({
              :ensure  => 'directory',
            })
          }
          it { is_expected.to create_pki__copy('/etc/foo').with({
            :notify   => 'Class[Libreswan::Config::Pki::Nsspki]',
            :require  => 'File[/etc/foo]',
            })
          }
          it { is_expected.to_not create_class('pki') }
        end
        context "with pki false libreswan::config should init NSS db and copy certs" do
        let(:pre_condition) { 'class { "libreswan": service_name => "ipsec", pki => false } ' }
        let(:hieradata) { 'test1_hiera' }

          it { is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
            :require  => 'File[/etc/ipsec.conf]',
            :notify   => "Class[Libreswan::Config::Pki::Nsspki]"
            })
          }
          it { is_expected.to create_file('/etc/pki/foo_ca.pem').with({
              :ensure  => 'file',
            })
          }
          it { is_expected.to create_file('/etc/pki/foo_key.pem').with({
              :ensure  => 'file',
            })
          }
          it { is_expected.to create_file('/etc/pki/foo_cert.pub').with({
              :ensure  => 'file',
            })
          }
          it { is_expected.to_not create_pki__copy('/etc/foo') }
          it { is_expected.to_not create_class('pki') }
        end
        context "with pki true libreswan::config should init NSS db and copy certs" do
        let(:pre_condition) { 'class { "libreswan": service_name => "ipsec",
          pki => "simp", app_pki_external_source => "/etc/pki/simp-test", app_pki_dir => "/etc/foo" }'}

          it { is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
            :require  => 'File[/etc/ipsec.conf]',
            :notify   => "Class[Libreswan::Config::Pki::Nsspki]"
            })
          }
          it { is_expected.to create_file('/etc/foo').with({
              :ensure  => 'directory',
            })
          }
          it { is_expected.to create_pki__copy('/etc/foo').with({
            :notify   => 'Class[Libreswan::Config::Pki::Nsspki]',
            :require  => 'File[/etc/foo]',
            })
          }
          it { is_expected.to create_class('pki') }
        end
      end
    end
  end
end
