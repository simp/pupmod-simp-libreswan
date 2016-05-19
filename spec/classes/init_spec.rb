require 'spec_helper'

describe 'ipsec' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('ipsec') }
    it { is_expected.to contain_class('ipsec') }
    it { is_expected.to contain_class('ipsec::params') }
    it { is_expected.to contain_class('ipsec::install').that_comes_before('ipsec::config') }
    it { is_expected.to contain_class('ipsec::config').that_comes_before('ipsec::config::pki') }
    it { is_expected.to contain_class('ipsec::config::pki') }
    it { is_expected.to contain_class('ipsec::nsspki').that_subscribes_to('ipsec::config::pki') }
    it { is_expected.to contain_class('ipsec::service').that_subscribes_to('ipsec::config') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "ipsec class without any parameters" do
          let(:params) {{ }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('ipsec').with_client_nets( ['127.0.0.1/32']) }
        end

        context "ipsec class with firewall enabled" do
          let(:params) {{
            :client_nets     => ['all'],
            :ikeport => '50',
            :nat_ikeport => '4500',
            :enable_firewall => true,
          }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('ipsec::config::firewall') }
          it { is_expected.to contain_class('ipsec::config::firewall').that_comes_before('ipsec::service') }
          it { is_expected.to create_iptables__add_udp_listen('ipsec_allow').with_dports(["50","4500"]) }
        end

        context "ipsec class with logging enabled" do
          let(:params) {{
            :enable_logging => true,
          }}
          it { is_expected.to contain_class('ipsec::config::logging') }
          it { is_expected.to contain_class('ipsec::config::logging').that_comes_before('ipsec::service') }
        end
        it { is_expected.to contain_service('ipsec') }
      end
    end
  end

  context 'unsupported operating system' do
    describe 'ipsec class without any parameters on Solaris/Nexenta' do
      let(:facts) {{
        :osfamily        => 'Solaris',
        :operatingsystem => 'Nexenta',
      }}

      it { expect { is_expected.to contain_package('ipsec') }.to raise_error(Puppet::Error, /Nexenta not supported/) }
    end
  end
end
