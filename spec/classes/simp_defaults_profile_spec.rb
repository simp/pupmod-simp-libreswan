require 'spec_helper'

describe 'libreswan' do
  let(:hiera_config) do
    File.expand_path('../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end

  context 'with simp:defaults compliance_engine profile enforced' do
    let(:hieradata) { 'simp_defaults_enforced' }

    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        # Some factsets ship haveged__rngd_enabled=true, which sends the
        # haveged fixture down its stop-and-mask path instead of running the
        # service the profile restores.
        let(:facts) { os_facts.merge(haveged__rngd_enabled: false) }

        it { is_expected.to compile.with_all_deps }

        it 'manages the ipsec service as running and enabled' do
          is_expected.to contain_service('ipsec').with(
            ensure: 'running',
            enable: true,
          )
        end

        {
          'protostack'      => 'netkey',
          'dumpdir'         => '/var/run/pluto',
          'plutodebug'      => 'none',
          'virtual-private' => '%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12',
        }.each do |key, value|
          it "manages the #{key} field in /etc/ipsec.conf" do
            is_expected.to contain_file_line("libreswan /etc/ipsec.conf #{key}").with(
              ensure: 'present',
              path:   '/etc/ipsec.conf',
              line:   "  #{key} = #{value}",
            )
          end
        end

        ['block', 'clear', 'clear-or-private', 'private'].each do |policy|
          it "writes an empty #{policy} policy file" do
            is_expected.to contain_file("/etc/ipsec.d/policies/#{policy}").with(
              ensure:  'file',
              content: "\n",
            )
          end
        end

        it 'writes the private-or-clear policy file with 0.0.0.0/0' do
          is_expected.to contain_file('/etc/ipsec.d/policies/private-or-clear').with(
            ensure:  'file',
            content: "0.0.0.0/0\n",
          )
        end

        it 'contains the firewall, pki, and haveged classes' do
          is_expected.to contain_class('libreswan::config::firewall')
          is_expected.to contain_class('libreswan::config::pki')
          is_expected.to contain_class('libreswan::config::pki::nsspki')
          is_expected.to contain_class('haveged')
        end

        it 'honors site simp_options::trusted_nets in the restored firewall rules' do
          is_expected.to contain_simp_firewalld__rule('ipsec_allow')
            .with_trusted_nets(['192.168.100.0/24'])
        end

        it 'installs the NSS helper script' do
          is_expected.to contain_file('/usr/local/scripts/nss/update_nssdb_password.sh')
        end

        it 'restores the pre-5.0.0 ownership and permission management' do
          is_expected.to contain_file('/etc/ipsec.conf').with(ensure: 'file', owner: 'root', mode: '0400')
          is_expected.to contain_file('/etc/ipsec.d').with(ensure: 'directory', owner: 'root', mode: '0700')
          is_expected.to contain_file('/var/run/pluto').with(ensure: 'directory', owner: 'root', mode: '0700')
        end
      end
    end
  end

  context 'with simp:defaults enforced and an explicit override' do
    let(:hieradata) { 'simp_defaults_with_override' }

    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts.merge(haveged__rngd_enabled: false) }

        it { is_expected.to compile.with_all_deps }

        it 'lets explicit site Hiera override the profile value' do
          is_expected.to contain_service('ipsec').with(enable: false)
        end

        it 'still applies the profile values that were not overridden' do
          is_expected.to contain_service('ipsec').with(ensure: 'running')
        end
      end
    end
  end
end
