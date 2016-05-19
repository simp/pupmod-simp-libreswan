require 'spec_helper'

describe 'ipsec_tunnel::install' do
    let(:pre_condition) { 'class { "ipsec_tunnel": ipsecdir => "/etc/ipsec.d" }' }
    let(:facts) { {:osfamily => 'RedHat'}}
    it { is_expected.to compile.with_all_deps }
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
      :source => 'puppet:///modules/ipsec_tunnel/usr/local/scripts/nss/update_nssdb_password.sh',
      :owner => 'root',
      :mode   => '0500'
      })
    }

end
