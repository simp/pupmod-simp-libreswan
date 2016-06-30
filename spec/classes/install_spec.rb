require 'spec_helper'

describe 'libreswan::install' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:pre_condition) { 'class { "libreswan": ipsecdir => "/etc/ipsec.d" }' }

        context 'with default parameters' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan::install') }
          it { is_expected.to contain_package('libreswan').with_ensure('present') }
          it { is_expected.to create_file('/usr/local/scripts').with({
            :owner => 'root',
            :mode  => '0755',
            :ensure => 'directory'
            })
          }
          it { is_expected.to create_file('/usr/local/scripts/nss').with({
            :owner => 'root',
            :mode  => '0755',
            :ensure => 'directory'
            })
          }
          it { is_expected.to create_file('/etc/ipsec.d').with({
            :ensure  => 'directory',
            :owner   => 'root',
            :mode   =>  '0700'
            })
          }
          it { is_expected.to create_file('/usr/local/scripts/nss/update_nssdb_password.sh').with({
            :source => 'puppet:///modules/libreswan/usr/local/scripts/nss/update_nssdb_password.sh',
            :owner => 'root',
            :mode   => '0500'
            })
          }
        end
      end
    end
  end
end
