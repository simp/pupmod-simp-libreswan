require 'spec_helper'

describe 'libreswan::config::pki' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context 'with pki = true libreswan::config should init NSS db and copy certs' do
          let(:pre_condition) do
            "class { 'libreswan':
              service_name => 'ipsec',
              pki          => true,
            }"
          end

          it {
            is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
                                                                                       require: 'File[/etc/ipsec.conf]'
                                                                                     })
          }
          it {
            is_expected.to create_file('/etc/pki/simp_apps/libreswan/x509').with({
                                                                                   ensure: 'directory',
                                                                                 })
          }
          it {
            is_expected.to create_pki__copy('libreswan').with({
                                                                source: '/etc/pki/simp/x509'
                                                              })
          }
          it { is_expected.not_to create_class('pki') }
        end

        context 'with pki = false libreswan::config should not init NSS db and copy certs' do
          let(:pre_condition) do
            "
            class { 'libreswan':
               service_name => 'ipsec',
               pki          => false,
            }"
          end
          let(:hieradata) { 'test1_hiera' }

          it {
            is_expected.not_to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
                                                                                           require: 'File[/etc/ipsec.conf]'
                                                                                         })
          }
          it {
            is_expected.not_to create_file('/etc/pki/simp_apps/libreswan/x509').with({
                                                                                       ensure: 'directory',
                                                                                     })
          }
          it { is_expected.not_to create_pki__copy('libreswan') }
          it { is_expected.not_to create_class('pki') }
        end

        context 'with pki = simp libreswan::config should init NSS db and copy certs' do
          let(:pre_condition) do
            "
            class { 'libreswan':
              service_name => 'ipsec',
              pki          => 'simp',
            }"
          end

          it {
            is_expected.to create_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with({
                                                                                       require: 'File[/etc/ipsec.conf]'
                                                                                     })
          }
          it {
            is_expected.to create_file('/etc/pki/simp_apps/libreswan/x509').with({
                                                                                   ensure: 'directory',
                                                                                 })
          }
          it {
            is_expected.to create_pki__copy('libreswan').with({
                                                                source: '/etc/pki/simp/x509'
                                                              })
          }
          it { is_expected.to create_class('pki') }
        end
      end
    end
  end
end
