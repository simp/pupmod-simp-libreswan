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

        #TODO flesh out full list of validation successes and failures,

        describe 'accept valid parameter options' do
          describe 'ddos-mode enum' do
            [ 'busy','unlimited', 'auto'].each do |valid_enum|
              context "ddos-mod #{valid_enum}" do
                let(:params) {{:ddos_mode => valid_enum}}
                it { is_expected.to compile}
              end
            end
          end

          describe 'protostack enum' do
            [ 'netkey','klips', 'mast'].each do |valid_enum|
              context "protostack #{valid_enum}" do
                let(:params) {{:protostack => valid_enum}}
                it { is_expected.to compile}
              end
            end
          end

          describe 'interfaces enum' do
            [ ['%none'], ['%defaultroute'], ['ipsec0=eth1', 'ipsec1=ppp0'] ].each do |valid_enum|
              context "protostack #{valid_enum}" do
                let(:params) {{:interfaces => valid_enum}}
                it { is_expected.to compile}
              end
            end
          end
        end

        describe 'with invalid yes/no parameters' do
          [ :strictcrlpolicy,
            :hidetos,
            :plutofork,
            :uniqueids,
            :plutorestartoncrash,
            :fragicmp,
            :perpeerlog,
            :ocsp_enable,
            :ocsp_strict,
            :logappend,
            :logtime
          ].each do |yesno_param|
            context "invalid #{yesno_param}" do
              let(:params) {{yesno_param => false}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/got Boolean/)
              end
            end
          end
        end

        describe 'with invalid integer parameters' do
          [ :nhelpers,
            :overridemtu,
            :keep_alive,
            :crlcheckinterval,
            :ocsp_timeout,
            :ddos_ike_treshold,
            :nflog_all,
          ].each do |int_param|
            context "invalid #{int_param}" do
              let(:params) {{int_param => 'not-a-number'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects an Integer value/)
              end
            end
          end
        end

        describe 'with invalid port parameters' do
          [ :ikeport,
            :nat_ikeport
          ].each do |int_param|
            context "invalid #{int_param}" do
              let(:params) {{int_param => 'not-a-port'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a value of type Integer/)
              end
            end
          end
        end

        describe 'with invalid bool parameters' do
          [ :firewall,
            :fips,
            :haveged
          ].each do |bool_param|
            context "invalid #{bool_param}" do
              let(:params) {{bool_param => 'FALSE'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a Boolean value/)
              end
            end
          end
        end

        describe 'with invalid Stroolean parameters' do
          [ :pki
          ].each do |bool_param|
            context "invalid #{bool_param}" do
              let(:params) {{bool_param => 'FALSE'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a value of type Boolean or Enum/)
              end
            end
          end
        end

        describe 'with invalid absolute path parameters' do
          [ :perpeerlogdir,
            :logfile,
            :ipsecdir,
            :secretsfile,
            :dumpdir,
          ].each do |abs_path_param|
            context "invalid #{abs_path_param}" do
              let(:params) {{abs_path_param => './myfile'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for Variant/)
              end
            end
          end
        end

        describe 'with invalid string parameters' do
          [ :service_name,
            :package_name,
            :myid,
            :myvendorid,
            :statsbin,
            :ocsp_trustname,
            :syslog,
            :klipsdebug,
            :plutodebug
          ].each do |string_param|
            context "invalid #{string_param}" do
              let(:params) {{string_param => ['string-in-an-array']}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a String value, got Tuple/)
              end
            end
          end
        end

        describe 'with invalid parameters' do
          context 'invalid trusted_nets' do
            let(:params) {{:trusted_nets => ['1.2.3.4/33']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a /)
            end
          end

          context 'invalid virtual_private' do
            let(:params) {{:virtual_private => '%v4:1.2.3.0/24'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a /)
            end
          end

          context 'invalid ocsp_uri' do
            let(:params) {{:ocsp_uri => ':myuri'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for/)
            end
          end

          context 'invalid ddos_mode' do
            let(:params) {{:ddos_mode => 'none'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for Enum/)
            end
          end

          context 'invalid protostack' do
            let(:params) {{:protostack => 'none'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for Enum/)
            end
          end

          context 'malformed listen' do
            let(:params) {{:listen => '1..2.3'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for/)
            end
          end

          context 'invalid listen' do
            let(:params) {{:listen => '1.2.3.0/24'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for/)
            end
          end

          context 'invalid interfaces' do
            let(:params) {{:interfaces => ['eth1=']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for/)
            end
          end

          context "with invalid virtual_private " do
            let(:params) {{:virtual_private     => ['267.2.3.0/24']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/expects a match for/)
            end
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
