require 'spec_helper'

describe 'libreswan::install' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:pre_condition) { 'include libreswan' }

        context 'with default parameters' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan::install') }
          it { is_expected.to contain_package('libreswan').with_ensure('present') }
          it { is_expected.not_to contain_file('/usr/local/scripts') }
          it { is_expected.not_to contain_file('/usr/local/scripts/nss') }
          it { is_expected.not_to contain_file('/usr/local/scripts/nss/update_nssdb_password.sh') }
          it { is_expected.not_to contain_file('/etc/ipsec.d') }
        end
      end
    end
  end
end
