require 'spec_helper'

describe 'libreswan' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('libreswan') }
    it { is_expected.to contain_class('libreswan') }
    it { is_expected.to contain_class('libreswan::params') }
    it { is_expected.to contain_class('libreswan::config') }
    it { is_expected.to contain_class('libreswan::config').that_notifies('libreswan::service') }
    it { is_expected.to contain_class('libreswan::install').that_comes_before('libreswan::config') }
    it { is_expected.to contain_class('libreswan::service').that_subscribes_to('libreswan::config') }
    it { is_expected.to contain_class('haveged') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "libreswan class with firewall enabled" do
          let(:params) {{
            :client_nets     => ['all'],
            :ikeport => '50',
            :nat_ikeport => '4500',
            :simp_firewall => true,
          }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('libreswan::config::firewall') }
          it { is_expected.to contain_class('libreswan::config::firewall').that_notifies('libreswan::service') }
          it { is_expected.to create_iptables__add_udp_listen('ipsec_allow').with_dports(["50","4500"]) }
        end

        context "libreswan class with use_simp_pki enabled" do
          let(:params) {{ :use_simp_pki => true, }}
          it { is_expected.to contain_class('libreswan::config::pki') }
          it { is_expected.to contain_class('libreswan::config::pki').that_notifies('libreswan::config::pki::nsspki') }
          it { is_expected.to contain_class('libreswan::config::pki::nsspki') }
        end
        it { is_expected.to contain_service('ipsec') }

        context 'with use_haveged => false' do
          let(:params) {{:use_haveged => false}}
          it { is_expected.to_not contain_class('haveged') }
        end

        context 'with invalid input' do
          let(:params) {{:use_haveged => 'invalid_input'}}
          it 'with use_haveged as a string' do
            expect {
              is_expected.to compile
            }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/invalid_input" is not a boolean/)
          end
        end
      end
    end
  end

  context 'unsupported operating system' do
    describe 'libreswan class without any parameters on Solaris/Nexenta' do
      let(:facts) {{
        :osfamily        => 'Solaris',
        :operatingsystem => 'Nexenta',
      }}

      it { expect { is_expected.to contain_package('libreswan') }.to raise_error(Puppet::Error, /Nexenta not supported/) }
    end
  end
end
