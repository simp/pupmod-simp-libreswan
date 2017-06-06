require 'spec_helper'

describe 'libreswan' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('libreswan') }
    it { is_expected.to contain_class('libreswan') }
    it { is_expected.to contain_class('libreswan::params') }
    it { is_expected.to contain_class('libreswan::config') }
    it { is_expected.to contain_class('libreswan::config').that_notifies('Class[libreswan::service]') }
    it { is_expected.to_not contain_class('libreswan::config::pki') }
    it { is_expected.to_not contain_class('libreswan::config::pki::nsspki') }
    it { is_expected.to contain_class('libreswan::install').that_comes_before('Class[libreswan::config]') }
    it { is_expected.to contain_class('libreswan::service').that_subscribes_to('Class[libreswan::config]') }
    it { is_expected.to_not contain_class('haveged') }
    it { is_expected.to contain_service('ipsec') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "libreswan class with firewall enabled" do
          let(:params) {{
            :trusted_nets     => ['192.168.0.0/16'],
            :ikeport => 50,
            :nat_ikeport => 4500,
            :firewall => true,
          }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('libreswan::config::firewall') }
          it { is_expected.to contain_class('libreswan::config::firewall').that_notifies('Class[libreswan::service]') }
          it { is_expected.to create_iptables__listen__udp('ipsec_allow').with_dports(["50","4500"]) }
        end

        context "libreswan class with pki = 'simp'" do
          let(:params) {{ :pki => 'simp', }}
          it { is_expected.to contain_class('libreswan::config::pki') }
          it { is_expected.to contain_class('libreswan::config::pki').that_notifies('Class[libreswan::config::pki::nsspki]') }
          it { is_expected.to contain_class('libreswan::config::pki::nsspki') }
        end

        context 'with haveged => true' do
          let(:params) {{:haveged => true}}
          it { is_expected.to contain_class('haveged') }
        end

        #TODO flesh out full list of validation successes and failures
        #     for libreswan types

        describe 'with valid parameters' do
          describe 'interfaces enum' do
            [ ['%none'], ['%defaultroute'], ['ipsec0=eth1', 'ipsec1=ppp0'] ].each do |valid_enum|
              context "protostack #{valid_enum}" do
                let(:params) {{:interfaces => valid_enum}}
                it { is_expected.to compile }
              end
            end
          end
        end

        describe 'with invalid parameters' do
          context 'invalid virtual_private' do
            let(:params) {{:virtual_private => '%v4:1.2.3.0/24'}}
            it { is_expected.to_not compile }
          end

          context 'invalid interfaces' do
            let(:params) {{:interfaces => ['eth1=']}}
            it { is_expected.to_not compile }
          end

          context "with invalid virtual_private " do
            let(:params) {{:virtual_private     => ['267.2.3.0/24']}}
            it { is_expected.to_not compile }
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
