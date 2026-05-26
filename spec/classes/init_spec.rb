require 'spec_helper'

describe 'libreswan' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }

        context 'with default parameters (safe-by-default include)' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan') }
          it { is_expected.to contain_class('libreswan::install') }
          it { is_expected.to contain_class('libreswan::config') }
          it { is_expected.to contain_package('libreswan').with_ensure('present') }

          # A bare include must declare NO service, file (besides nothing), or
          # firewall/PKI/haveged resources.
          it { is_expected.not_to contain_class('libreswan::service') }
          it { is_expected.not_to contain_class('libreswan::config::firewall') }
          it { is_expected.not_to contain_class('libreswan::config::pki') }
          it { is_expected.not_to contain_class('libreswan::config::pki::nsspki') }
          it { is_expected.not_to contain_class('haveged') }
          it { is_expected.not_to contain_service('ipsec') }
          it { is_expected.not_to contain_file('/etc/ipsec.conf') }
          it { is_expected.not_to contain_file('/etc/ipsec.d/policies/block') }
          it { is_expected.not_to contain_file('/etc/ipsec.d/policies/clear') }
          it { is_expected.not_to contain_file('/etc/ipsec.d/policies/clear-or-private') }
          it { is_expected.not_to contain_file('/etc/ipsec.d/policies/private') }
          it { is_expected.not_to contain_file('/etc/ipsec.d/policies/private-or-clear') }

          # No file_line resources should be declared because no settings were
          # passed.
          it {
            catalogue.resources
                     .select { |r| r.type == 'File_line' }
                     .each { |r| raise "unexpected File_line on bare include: #{r.title}" }
          }
        end

        context 'with service_ensure => running' do
          let(:params) { { service_ensure: 'running', service_enable: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan::service') }
          it { is_expected.to contain_service('ipsec').with(ensure: 'running', enable: true) }
        end

        context 'with a single setting overridden' do
          let(:params) { { plutodebug: 'all' } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file_line('libreswan /etc/ipsec.conf plutodebug')
              .with(line: '  plutodebug = all')
          }
          # Other fields must NOT produce file_line resources.
          it { is_expected.not_to contain_file_line('libreswan /etc/ipsec.conf protostack') }
        end

        context 'with purge_settings' do
          let(:params) { { purge_settings: ['plutodebug', 'logfile'] } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file_line('libreswan /etc/ipsec.conf plutodebug')
              .with(ensure: 'absent')
          }
          it {
            is_expected.to contain_file_line('libreswan /etc/ipsec.conf logfile')
              .with(ensure: 'absent')
          }
        end

        context 'with block_cidrs set' do
          let(:params) { { block_cidrs: ['10.0.0.0/8'] } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/ipsec.d/policies/block')
              .with(ensure: 'file', mode: '0644', content: "10.0.0.0/8\n")
          }
        end

        context 'with purge_policies' do
          let(:params) { { purge_policies: ['block', 'clear'] } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/ipsec.d/policies/block').with_ensure('absent') }
          it { is_expected.to contain_file('/etc/ipsec.d/policies/clear').with_ensure('absent') }
        end

        context 'with firewall => true' do
          let(:params) do
            {
              firewall: true,
              trusted_nets: ['192.168.0.0/16'],
              ikeport: 50,
              nat_ikeport: 4500,
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('libreswan::config::firewall') }
          it {
            is_expected.to contain_simp_firewalld__rule('ipsec_allow')
              .with_trusted_nets(['192.168.0.0/16'])
              .with_apply_to('all')
              .with_dports([50, 4500])
              .with_protocol('udp')
          }
        end

        context "with pki => 'simp'" do
          let(:facts) { os_facts.merge(fips_enabled: false) }
          let(:params) { { pki: 'simp', fips: false } }

          it { is_expected.to contain_class('libreswan::config::pki') }
          it { is_expected.to contain_class('libreswan::config::pki::nsspki') }
          it {
            is_expected.to contain_libreswan__nss__init_db('NSSDB /etc/ipsec.d').with(
              dbdir: '/etc/ipsec.d',
              nsspassword: '/etc/ipsec.d/nsspassword',
              token: 'NSS Certificate DB',
              fips: false,
            )
          }
        end

        context 'with haveged => true' do
          let(:params) { { haveged: true } }

          it { is_expected.to contain_class('haveged') }
        end

        describe 'with invalid parameters' do
          context 'invalid virtual_private' do
            let(:params) { { virtual_private: '%v4:1.2.3.0/24' } }

            it { is_expected.not_to compile }
          end

          context 'invalid interfaces' do
            let(:params) { { interfaces: ['eth1='] } }

            it { is_expected.not_to compile }
          end

          context 'with invalid virtual_private cidrs' do
            let(:params) { { virtual_private: ['267.2.3.0/24'] } }

            it { is_expected.not_to compile }
          end
        end
      end
    end
  end
end
