require 'spec_helper'

describe 'libreswan' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('libreswan') }
    it { is_expected.to contain_class('libreswan') }
    it { is_expected.to contain_class('libreswan::params') }
    it { is_expected.to contain_class('libreswan::install').that_comes_before('libreswan::config') }
    it { is_expected.to contain_class('libreswan::config').that_comes_before('libreswan::config::pki') }
    it { is_expected.to contain_class('libreswan::config::pki') }
    it { is_expected.to contain_class('libreswan::nsspki').that_subscribes_to('libreswan::config::pki') }
    it { is_expected.to contain_class('libreswan::service').that_subscribes_to('libreswan::config') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "libreswan class without any parameters" do
          let(:params) {{ }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('libreswan').with_client_nets( ['127.0.0.1/32']) }
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

        context "libreswan class with logging enabled" do
          let(:params) {{
            :simp_logging => true,
          }}
          it { is_expected.to contain_class('libreswan::config::logging') }
          it { is_expected.to contain_class('libreswan::config::logging').that_notifies('libreswan::service') }
        end
        it { is_expected.to contain_service('ipsec') }
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
