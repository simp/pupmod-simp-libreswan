require 'spec_helper'

describe 'libreswan::config::pki::nsspki' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        context "with default param" do
          let(:pre_condition) {
            "class { 'libreswan':
              service_name => 'ipsec',
              pki          => true,
            }"
          }

          it { is_expected.to contain_file('/etc/ipsec.secrets').with({
            :ensure  => 'file',
            :owner   => 'root',
            :mode    => '0400',
            :content => ": RSA \"#{facts[:fqdn]}\"",
          })}

          it { is_expected.to contain_libreswan__nss__loadcerts(facts[:fqdn]).with( {
            :dbdir       => '/etc/ipsec.d',
            :nsspwd_file => '/etc/ipsec.d/nsspassword',
            :cert        => "/etc/pki/simp_apps/libreswan/x509/public/#{facts[:fqdn]}.pub",
            :key         => "/etc/pki/simp_apps/libreswan/x509/private/#{facts[:fqdn]}.pem",
            :token       => 'NSS Certificate DB'
          } ) }
        end

        context 'with different certname setup' do
          let(:pre_condition) {
            "class { 'libreswan':
              service_name => 'ipsec',
              pki          => true,
            }"
          }
          let(:hieradata) { 'client1_data' }

          it { is_expected.to contain_file('/etc/ipsec.secrets').with({
            :ensure  => 'file',
            :owner   => 'root',
            :mode    => '0400',
            :content => ": RSA \"client1\"",
          })}

          it { is_expected.to contain_libreswan__nss__loadcerts('client1').with( {
            :dbdir       => '/etc/ipsec.d',
            :nsspwd_file => '/etc/ipsec.d/nsspassword',
            :cert        => "/etc/pki/simp_apps/libreswan/x509/public/client1.pub",
            :key         => "/etc/pki/simp_apps/libreswan/x509/private/client1.pem",
            :token       => 'NSS Certificate DB'
          } ) }
        end
      end
    end
  end
end
