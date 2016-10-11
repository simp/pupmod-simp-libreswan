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
            :ipsec_client_nets     => ['192.168.0.0/16'],
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
              let(:params) {{yesno_param => 'false'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'false' is not 'yes' or 'no'/)
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
            :ikeport,
            :nflog_all,
            :nat_ikeport
          ].each do |int_param|
            context "invalid #{int_param}" do
              let(:params) {{int_param => 'not-a-number'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'\["not-a-number"\]' is not an integer/)
              end
            end
          end
        end

        describe 'with invalid bool parameters' do
          [ :simp_firewall,
            :use_simp_pki,
            :use_fips,
            :use_haveged
          ].each do |bool_param|
            context "invalid #{bool_param}" do
              let(:params) {{bool_param => 'FALSE'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/FALSE" is not a boolean/)
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
            :certsource,
            :pkiroot
          ].each do |abs_path_param|
            context "invalid #{abs_path_param}" do
              let(:params) {{abs_path_param => './myfile'}}
              it 'fails to compile' do
                expect {
                  is_expected.to compile
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/".\/myfile" is not an absolute path/)
              end
            end
          end
        end

        describe 'with invalid string parameters' do
          [ :service_name,
            :package_name,
            :myid,
            :listen,
            :myvendorid,
            :statsbin,
            :ocsp_uri,
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
                }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/\["string-in-an-array"\] is not a string/)
              end
            end
          end
        end

        describe 'with invalid parameters' do
          context 'invalid ipsec_client_nets' do
#TODO renable this example once simplib's validate_net_list is fixed!
#            let(:params) {{:ipsec_client_nets => ['1.2.3.4/33']}}
            let(:params) {{:ipsec_client_nets => ['1.2..4/32']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..4\/32' is not a valid network/)
            end
          end

          context 'invalid virtual_private' do
            let(:params) {{:virtual_private => '1.2.3.0/24'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/"1.2.3.0\/24" is not an Array/)
            end
          end

          context 'invalid ocsp_uri' do
            let(:params) {{:ocsp_uri => ':myuri'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/':myuri' is not a valid URI/)
            end
          end

          context 'invalid ddos_mode' do
            let(:params) {{:ddos_mode => 'none'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'busy,unlimited,auto' does not contain 'none'/)
            end
          end

          context 'invalid protostack' do
            let(:params) {{:protostack => 'none'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'netkey,klips,mast' does not contain 'none'/)
            end
          end

          context 'malformed listen' do
            let(:params) {{:listen => '1..2.3'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1..2.3' is not a valid network/)
            end
          end

#TODO enable once code validates this
=begin
          context 'invalid listen' do
            let(:params) {{:listen => '1.2.3.0/24'}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1..2.3' is not a valid network/)
            end
          end
=end

          context 'invalid interfaces' do
            let(:params) {{:interfaces => ['eth1=']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/"eth1=" does not match/)
            end
          end

          context "with invalid virtual_private " do
            let(:params) {{:virtual_private     => ['267.2.3.0/24']}}
            it 'fails to compile' do
              expect {
                is_expected.to compile
              }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/267.2.3.0\/24 in virtual_private is not an IPv4\/IPv6 address/)
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
