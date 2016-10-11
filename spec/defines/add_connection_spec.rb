require 'spec_helper'

connection_conf_content = {
  :default =>
    "conn %default\n" +
    "# Left Side Settings\n" +
    "\n" +
    "# Right Side Settings\n" +
    "\n" +
    "# Universal Settings\n" +
    "  ike = aes-sha2;dh24\n" +
    "  phase2alg = aes-sha2;dh24\n" +
    "  fragmentation = force\n" +
    "  xauthby = pam\n" +
    "  xauthfail = hard\n" +
    "  keyingtries = 10\n",

  :outgoing =>
    "conn outgoing\n" +
    "# Left Side Settings\n" +
    "  left = 10.0.0.1\n" +
    "  leftcert = %cert\n" +
    "  leftsendcert = always\n" +
    "\n" +
    "# Right Side Settings\n" +
    "\n" +
    "# Universal Settings\n" +
    "  ike = aes-sha2;dh24\n" +
    "  phase2alg = aes-sha2;dh24\n" +
    "  keyingtries = 10\n",

  # This content is NOT a usable connection file, but exercises default logic
  :minimally_specified_conn =>
    "conn minimally_specified_conn\n" +
    "# Left Side Settings\n" +
    "\n" +
    "# Right Side Settings\n" +
    "\n" +
    "# Universal Settings\n" +
    "  ike = aes-sha2;dh24\n" +
    "  phase2alg = aes-sha2;dh24\n" +
    "  keyingtries = 10\n",

  # This content is NOT a usable connection file, but exercises non-default logic
  :maximally_specified_conn =>
    "conn maximally_specified_conn\n" +
    "# Left Side Settings\n" +
    "  left = 10.11.11.1\n" +
    "  leftid = %myid\n" +
    "  leftupdown = /some/left/updown/script\n" +
    "  leftcert = my-left-cert-nickname\n" +
    "  leftca = myleftca\n" +
    "  leftprotoport = 17/1057\n" +
    "  leftsourceip = 10.0.1.1\n" +
    "  leftrsasigkey = %cert\n" +
    "  leftrsasigkey2 = %dnsondemand\n" +
    "  leftsendcert = sendifasked\n" +
    "  leftsubnet = 10.0.1.0/24\n" +
    "  leftsubnets = {10.0.3.0/24 10.0.5.0/24}\n" +
    "  leftnexthop = 172.16.55.66\n" +
    "  leftaddresspool = 10.0.1.100-10.0.1.200\n" +
    "  leftxauthserver = yes\n" +
    "  leftxauthusername = leftuser\n" +
    "  leftxauthclient = yes\n" +
    "  leftmodecfgserver = yes\n" +
    "  leftmodecfgclient = yes\n" +
    "\n" +
    "# Right Side Settings\n" +
    "  right = 192.168.22.1\n" +
    "  rightid = %fromcert\n" +
    "  rightupdown = /some/right/updown/script\n" +
    "  rightcert = my-right-cert-nickname\n" +
    "  rightca = myrightca\n" +
    "  rightprotoport = tcp/%any\n" +
    "  rightsourceip = 10.0.2.1\n" +
    "  rightrsasigkey = %dnsonload\n" +
    "  rightrsasigkey2 = %none\n" +
    "  rightsendcert = yes\n" +
    "  rightsubnet = 10.0.2.0/24\n" +
    "  rightsubnets = {10.0.4.0/24 10.0.6.0/24}\n" +
    "  rightnexthop = 172.16.88.99\n" +
    "  rightaddresspool = 192.168.1.100-192.168.1.200\n" +
    "  rightxauthserver = yes\n" +
    "  rightxauthusername = rightuser\n" +
    "  rightxauthclient = yes\n" +
    "  rightmodecfgserver = yes\n" +
    "  rightmodecfgclient = yes\n" +
    "\n" +
    "# Universal Settings\n" +
    "  connaddrfamily = ipv4\n" +
    "  authby = secret|rsasig\n" +
    "  type = tunnel\n" +
    "  auto = ondemand\n" +
    "  ike = aes_gcm256-sha2;dh23\n" +
    "  ikev2 = insist\n" +
    "  phase2 = ah\n" +
    "  phase2alg = 3des-md5;modp1024\n" +
    "  sareftrack = conntrack\n" +
    "  narrowing = yes\n" +
    "  ikepad = no\n" +
    "  fragmentation = no\n" +
    "  sha2-truncbug = no\n" +
    "  nat-ikev1-method = drafts\n" +
    "  xauthby = alwaysok\n" +
    "  xauthfail = soft\n" +
    "  modecfgpull = yes\n" +
    "  modecfgdns1 = 8.8.8.8\n" +
    "  modecfgdns2 = 8.8.4.4\n" +
    "  modecfgdomain = test.domain\n" +
    "  modecfgbanner = test banner\n" +
    "  keyingtries = 5\n"
}

shared_examples_for "a libreswan connection config file generator" do
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to contain_file(conn_name).with(
    {
      :notify  => 'Service[ipsec]',
      :path    => "#{params[:dir]}/#{title}.conf",
      :content => connection_conf_content[title]
    })
  }
end

describe 'libreswan::add_connection', :type => :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end
        let(:common_params) { { :dir => '/etc/ipsec.d', } }

        describe 'create %default connection config' do
          let(:conn_name  ){ '%default' }
          let(:title  ){ :default }
          let(:params) { common_params.merge({ :fragmentation => 'force', :xauthby => 'pam', :xauthfail => 'hard' }) }

          it_should_behave_like "a libreswan connection config file generator"
        end

        describe 'create other connection config' do
          let(:conn_name){ 'outgoing' }
          let(:title){ :outgoing }
          let(:params) { common_params.merge({ :left => '10.0.0.1', :leftcert => '%cert', :leftsendcert => 'always' }) }

          it_should_behave_like "a libreswan connection config file generator"
        end

        describe 'create file with only default params' do
          let(:conn_name){ 'minimally_specified_conn' }
          let(:title){ :minimally_specified_conn }
          let(:params) { common_params}

          it_should_behave_like "a libreswan connection config file generator"
        end

        describe 'create file with fully-specified params' do
          let(:conn_name){ 'maximally_specified_conn' }
          let(:title){ :maximally_specified_conn }
          let(:params) { common_params.merge(
            { :keyingtries        => 5,
              :ike                => 'aes_gcm256-sha2;dh23',
              :phase2alg          => '3des-md5;modp1024',
              :left               => '10.11.11.1',
              :right              => '192.168.22.1',
              :connaddrfamily     => 'ipv4',
              :leftaddresspool    => ['10.0.1.100', '10.0.1.200'],
              :leftsubnet         => '10.0.1.0/24',
              :leftsubnets        => ['10.0.3.0/24', '10.0.5.0/24'],
              :leftprotoport      => '17/1057',
              :leftsourceip       => '10.0.1.1',
              :leftupdown         => '/some/left/updown/script',
              :leftcert           => 'my-left-cert-nickname',
              :leftrsasigkey      => '%cert',
              :leftrsasigkey2     => '%dnsondemand',
              :leftsendcert       => 'sendifasked',
              :leftnexthop        => '172.16.55.66',
              :leftid             => '%myid',
              :leftca             => 'myleftca',
              :rightid            => '%fromcert',
              :rightrsasigkey     => '%dnsonload',
              :rightrsasigkey2    => '%none',
              :rightca            => 'myrightca',
              :rightaddresspool   => ['192.168.1.100', '192.168.1.200'],
              :rightsubnet        => '10.0.2.0/24',
              :rightsubnets       => ['10.0.4.0/24', '10.0.6.0/24'],
              :rightprotoport     => 'tcp/%any',
              :rightsourceip      => '10.0.2.1',
              :rightupdown        => '/some/right/updown/script',
              :rightcert          => 'my-right-cert-nickname',
              :rightsendcert      => 'yes',
              :rightnexthop       => '172.16.88.99',
              :auto               => 'ondemand',
              :authby             => 'secret|rsasig',
              :type               => 'tunnel',
              :ikev2              => 'insist',
              :phase2             => 'ah',
	      :ikepad             => 'no',
              :fragmentation      => 'no',
              :sha2_truncbug      => 'no',
              :narrowing          => 'yes',
              :sareftrack         => 'conntrack',
              :leftxauthserver    => 'yes',
              :rightxauthserver   => 'yes',
              :leftxauthusername  => 'leftuser',
              :rightxauthusername => 'rightuser',
              :leftxauthclient    => 'yes',
              :rightxauthclient   => 'yes',
              :leftmodecfgserver  => 'yes',
              :rightmodecfgserver => 'yes',
              :leftmodecfgclient  => 'yes',
              :rightmodecfgclient => 'yes',
              :xauthby            => 'alwaysok',
              :xauthfail          => 'soft',
              :modecfgpull        => 'yes',
              :modecfgdns1        => '8.8.8.8',
              :modecfgdns2        => '8.8.4.4',
              :modecfgdomain      => 'test.domain',
              :modecfgbanner      => 'test banner',
              :nat_ikev1_method   => 'drafts',
            })
          }

          it_should_behave_like "a libreswan connection config file generator"
        end

        # TODO flesh out more success and failure validation cases,
        # especially regex validations and IPv6 cases
        #
        describe 'accept valid parameter options' do
          describe 'magic IP enum' do
            [ :left, :right ].each do |ip_enum|
              [ '%any','%opportunistic', '%group', '%opportunisticgroup'].each do |valid_enum|
                context "#{ip_enum} of #{valid_enum}" do
                  let(:title){ "#{ip_enum}_#{valid_enum}" }
                  let(:params) {{ip_enum => valid_enum}}
                  it { is_expected.to compile}
                end
              end
            end
          end

          describe 'magic subnet enum' do
	    [ :leftsubnet, :rightsubnet ].each do |subnet_enum|
	      [ 'vhost:%priv,%no','vnet:%priv' ].each do |valid_enum|
	        context "#{subnet_enum} of #{valid_enum}" do
	          let(:title){ "#{subnet_enum}_#{valid_enum}" }
	          let(:params) {{subnet_enum => valid_enum}}
	          it { 
                    is_expected.to compile
                  }
                end
	      end
	    end
          end

          describe 'magic nexthop enum' do
	    [ :leftnexthop, :rightnexthop ].each do |nexthop_enum|
	      [ '%direct','%defaultroute' ].each do |valid_enum|
	        context "#{nexthop_enum} of #{valid_enum}" do
	          let(:title){ "#{nexthop_enum}_#{valid_enum}" }
	          let(:params) {{nexthop_enum => valid_enum}}
	          it { is_expected.to compile }
                end
	      end
	    end
          end

          describe 'sendcert enum' do
	    [ :leftsendcert, :rightsendcert ].each do |sendcert_enum|
	      [ 'yes', 'no', 'never', 'always', 'sendifasked' ].each do |valid_enum|
	        context "#{sendcert_enum} of #{valid_enum}" do
	          let(:title){ "#{sendcert_enum}_#{valid_enum}" }
	          let(:params) {{sendcert_enum => valid_enum}}
	          it { is_expected.to compile }
                end
	      end
	    end
          end

          describe 'authby enum' do
	    [ 'rsasig','secret', 'secret|rsasig', 'never', 'null' ].each do |valid_enum|
	      context "authby of #{valid_enum}" do
	        let(:title){ "authby_#{valid_enum}" }
	        let(:params) {{:authby => valid_enum}}
	        it { is_expected.to compile }
              end
            end
          end

          describe 'auto enum' do
	    [ 'add','start','ondemand','ignore' ].each do |valid_enum|
	      context "auto of #{valid_enum}" do
	        let(:title){ "auto_#{valid_enum}" }
	        let(:params) {{:auto => valid_enum}}
	        it { is_expected.to compile }
              end
            end
          end

          describe 'connaddrfamily enum' do
	    [ 'ipv4', 'ipv6' ].each do |valid_enum|
	      context "connaddrfamily of #{valid_enum}" do
	        let(:title){ "connaddrfamily_#{valid_enum}" }
	        let(:params) {{:connaddrfamily => valid_enum}}
	        it { is_expected.to compile }
              end
            end
          end

          describe 'type enum' do
	    [ 'tunnel','transport','passthough','reject','drop' ].each do |valid_enum|
	      context "type of #{valid_enum}" do
	        let(:title){ "type_#{valid_enum}" }
	        let(:params) {{:type => valid_enum}}
	        it { is_expected.to compile }
              end
            end
          end
#TODO ikev2
#TODO phase2
#TODO nat_ikev1_method
#TODO fragmentation
#TODO sareftrack
#TODO xauthby
#TODO xauthfail
#TODO leftrsasigkey, leftrsasigkey2, rightrsasigkey, rightrsasigkey2
        end

        describe 'reject invalid parameters' do
          describe 'yes/no parameter' do
            [ :ikepad,
              :narrowing,
              :sha2_truncbug,
              :leftxauthserver,
              :rightxauthserver,
              :leftxauthclient,
              :rightxauthclient,
              :leftmodecfgserver,
              :rightmodecfgserver,
              :leftmodecfgclient,
              :rightmodecfgclient,
              :modecfgpull
            ].each do |yesno_param|
              context "invalid #{yesno_param}" do
                let(:title){ "invalid_#{yesno_param}" }
                let(:params) {{yesno_param => 'NO'}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'NO' is not 'yes' or 'no'/)
                end
              end
            end
          end

          describe 'string parameter' do
            [ :left,
              :right,
              :leftsourceip,
              :rightsourceip,
              :rightsubnet,
              :leftsubnet,
              :leftnexthop,
              :rightnexthop,
              :leftupdown,
              :rightupdown,
              :leftcert,
              :rightcert,
              :leftid,
              :rightid,
              :leftca,
              :rightca,
              :leftxauthusername,
              :rightxauthusername,
              :modecfgdns1,
              :modecfgdns2,
              :modecfgdomain,
              :modecfgbanner,
              :phase2alg,
              :ike
            ].each do |string_param|
              context "invalid string #{string_param}" do
                let(:title){ "invalid_string_#{string_param}" }
                let(:params) {{string_param => ['string-in-an-array']}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/\["string-in-an-array"\] is not a string/)
                end
              end
            end
          end

          describe 'single IP address' do
            [ :left,
              :right,
              :leftsourceip,
              :rightsourceip,
              :leftnexthop,
              :rightnexthop,
              :modecfgdns1,
              :modecfgdns2
            ].each do |ipaddr_param|
              context "invalid #{ipaddr_param}" do
                let(:title){ "invalid_#{ipaddr_param}" }
                let(:params) {{ipaddr_param => '1.2..4.'}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..4.' is not a valid network/)
                end
              end
               
              context 'CIDR address' do
                it 'rejects CIDR address' do
                  pending 'Currently, CIDR addresses are not rejected'
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..4.' is not a valid network/)
                end
              end
            end
          end

          describe 'pair of IP addresses (not CIDR)' do
            [ :leftaddresspool, :rightaddresspool ].each do |addr_pool_param|
              context "#{addr_pool_param} array not length 2" do
                let(:title){ "invalid_length_#{addr_pool_param}" }
                let(:params) {{addr_pool_param => ['1.2.3.4']}}
                it 'fails to compile' do
                  pending "Currently, length of array is not validated."
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/#{addr_pool_param} must have 2 values/)
                end
              end

              context "#{addr_pool_param} contains CIDR addresses"  do
                let(:title){ "invalid_cidr_#{addr_pool_param}" }
                let(:params) {{addr_pool_param => ['1.2.4.0/24', '5.7.8.0/24'] }}
                it 'fails to compile' do
                  pending "Currently, CIDR addresses are not rejected"
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1..30.0' is not a valid network/)
                end
              end
            end
          end

          describe 'single CIDR address' do
            [ :leftsubnet,
              :rightsubnet,
              :leftsubnets,
              :rightsubnets
            ].each do |cidr_param|
              context "invalid CIDR address #{cidr_param}" do
                let(:title){ "invalid_cidr_#{cidr_param}" }
                let(:params) {{cidr_param => '1.2..30.0/24'}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..30.0\/24' is not a valid network/)
                end
              end

              context "not CIDR address #{cidr_param}" do
                it 'fails to compile' do
                  pending "Currently, non-CIDR addresses are not rejected"
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..30.0\/24' is not a valid network/)
                end
              end
            end
          end

          describe 'array of CIDR addresses' do
            [ :leftsubnets, :rightsubnets ].each do |cidr_param|
              context "invalid CIDR address #{cidr_param}" do
                let(:title){ "invalid_cidr_array_#{cidr_param}" }
                let(:params) {{cidr_param => ['1.2..30.0/24', '1.2.3.4']}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..30.0\/24' is not a valid network/)
                end
              end
              context "not CIDR address #{cidr_param}" do
                it 'fails to compile' do
                  pending "Currently, non-CIDR addresses are not rejected"
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/'1.2..30.0\/24' is not a valid network/)
                end
              end
            end
          end

          describe 'enumerated list' do
            [ :authby,
              :auto,
              :leftsendcert,
              :rightsendcert,
              :type,
              :ikev2,
              :phase2,
              :nat_ikev1_method,
              :fragmentation,
              :sareftrack,
              :xauthby,
              :xauthfail
            ].each do |enum_param|
              context "invalid enumeration #{enum_param}" do
                let(:title){ "invalid_enum_#{enum_param}" }
                let(:params) {{enum_param => 'not-in-enumerated-list'}}
                it 'fails to compile' do
                  expect {
                    is_expected.to compile
                  }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/does not contain 'not-in-enumerated-list'/)
                end
              end
            end
          end

          context 'when connaddrfamily is invalid' do
            let(:title){ :invalid_connaddrfamily }
            let(:params) { common_params.merge({ :connaddrfamily => 'IPV4' }) }
            it { is_expected.to_not compile.with_all_deps }
          end
        end
      end
    end
  end
end
