require 'spec_helper'

describe 'libreswan::config' do
  let(:nssdir) { ((facts.dig(:os, :release, :major) || facts.dig(:os, 'release', 'major')).to_i >= 9) ? '/var/lib/ipsec/nss' : '/etc/ipsec.d' }

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
            ['block', 'clear', 'clear-or-private', 'private', 'private-or-clear'].each do |p|
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
            'ddos-ike-treshold' => 26_000,
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

          it 'declares the policies directory when any policy file is managed' do
            is_expected.to contain_file('/etc/ipsec.d/policies').with_ensure('directory')
          end
        end

        context 'with purge_settings overlapping a managed key' do
          let(:pre_condition) do
            <<~EOM
              class { 'libreswan':
                protostack     => 'netkey',
                purge_settings => ['protostack'],
              }
            EOM
          end

          it 'fails compilation with a helpful message' do
            is_expected.to compile.and_raise_error(%r{cannot appear in both managed settings and \$purge_settings: protostack})
          end
        end

        context 'with purge_policies overlapping a managed policy' do
          let(:pre_condition) do
            <<~EOM
              class { 'libreswan':
                block_cidrs    => ['10.0.0.0/8'],
                purge_policies => ['block'],
              }
            EOM
          end

          it 'fails compilation with a helpful message' do
            is_expected.to compile.and_raise_error(%r{cannot appear in both managed policies and \$purge_policies: block})
          end
        end

        context 'with purge_policies and no managed policies' do
          let(:pre_condition) do
            <<~EOM
              class { 'libreswan':
                purge_policies => ['block', 'clear'],
              }
            EOM
          end

          it 'declares the policies directory' do
            is_expected.to contain_file('/etc/ipsec.d/policies').with_ensure('directory')
          end

          it 'declares each policy file as absent' do
            is_expected.to contain_file('/etc/ipsec.d/policies/block').with_ensure('absent')
            is_expected.to contain_file('/etc/ipsec.d/policies/clear').with_ensure('absent')
          end
        end
      end
    end
  end
end
