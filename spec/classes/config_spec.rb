require 'spec_helper'

describe 'libreswan::config' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }

        context 'with default parameters' do
          let(:pre_condition) { 'include libreswan' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to contain_file('/etc/ipsec.conf') }

          it 'declares no file_line resources' do
            file_lines = catalogue.resources.select { |r| r.type == 'File_line' }
            expect(file_lines).to be_empty
          end

          it 'declares no policy files' do
            %w[block clear clear-or-private private private-or-clear].each do |p|
              is_expected.not_to contain_file("/etc/ipsec.d/policies/#{p}")
            end
          end
        end

        context 'with a representative set of settings' do
          let(:pre_condition) do
            <<~EOM
              class { 'libreswan':
                myid                => '@myid',
                protostack          => 'klips',
                interfaces          => ['ipsec0=eth0','ipsec1=ppp0'],
                listen              => '1.2.3.4',
                nflog_all           => 10,
                keep_alive          => 10,
                virtual_private     => ['%v4:1.2.3.0/24', '%v6:fe80::/10'],
                plutodebug          => 'all',
                logfile             => '/var/log/ipsec.log',
                ddos_mode           => 'busy',
                ddos_ike_treshold   => 26000,
                dumpdir             => '/var/run/ipsec',
                statsbin            => '/some/external/reporter -p 266',
                overridemtu         => 1500,
                block_cidrs         => ['10.0.0.0/8'],
                clear_cidrs         => ['192.168.0.0/16'],
              }
            EOM
          end

          {
            'myid'              => '@myid',
            'protostack'        => 'klips',
            'interfaces'        => '"ipsec0=eth0 ipsec1=ppp0"',
            'listen'            => '1.2.3.4',
            'nflog-all'         => 10,
            'keep-alive'        => 10,
            'virtual-private'   => '%v4:1.2.3.0/24,%v6:fe80::/10',
            'plutodebug'        => 'all',
            'logfile'           => '/var/log/ipsec.log',
            'ddos-mode'         => 'busy',
            'ddos-ike-treshold' => 26000,
            'dumpdir'           => '/var/run/ipsec',
            'statsbin'          => '"/some/external/reporter -p 266"',
            'overridemtu'       => 1500,
          }.each do |key, value|
            it "manages #{key} = #{value}" do
              is_expected.to contain_file_line("libreswan /etc/ipsec.conf #{key}")
                .with(
                  ensure: 'present',
                  path:  '/etc/ipsec.conf',
                  line:  "  #{key} = #{value}",
                )
            end
          end

          it 'does NOT manage fields that were not passed' do
            is_expected.not_to contain_file_line('libreswan /etc/ipsec.conf uniqueids')
            is_expected.not_to contain_file_line('libreswan /etc/ipsec.conf ocsp-enable')
          end

          it 'writes the block policy file' do
            is_expected.to contain_file('/etc/ipsec.d/policies/block')
              .with(ensure: 'file', content: "10.0.0.0/8\n")
          end

          it 'writes the clear policy file' do
            is_expected.to contain_file('/etc/ipsec.d/policies/clear')
              .with(ensure: 'file', content: "192.168.0.0/16\n")
          end

          it 'does not write unmanaged policy files' do
            is_expected.not_to contain_file('/etc/ipsec.d/policies/private')
          end
        end
      end
    end
  end
end
