require 'spec_helper_acceptance'

# End-to-end check of the shipped `simp:defaults` compliance_engine profile:
# a bare `include libreswan` plus `compliance_engine::enforcement` must
# restore the pre-5.0.0 behavior (service, config fields, policy files,
# permissions, NSS helper scripts).
#
# The compliance_engine hiera backend comes from the `compliance_engine`
# fixture module (the simp-compliance_engine gem repo doubles as a module),
# which `copy_fixture_modules_to` has already staged on the SUTs.
test_name 'simp:defaults compliance_engine profile'

describe 'simp:defaults compliance_engine profile' do
  let(:manifest) { 'include libreswan' }

  let(:hiera_yaml) do
    {
      'version' => 5,
      'defaults' => {
        'data_hash' => 'yaml_data',
        'datadir' => 'data',
      },
      'hierarchy' => [
        { 'name' => 'Common', 'path' => 'common.yaml' },
        { 'name' => 'Compliance Engine', 'lookup_key' => 'compliance_engine::enforcement' },
      ],
    }
  end

  # The two libreswan::* keys demonstrate the documented opt-out pattern:
  # explicit site Hiera wins over the profile. `pki: true` (manually-supplied
  # certs) is used instead of the profile's 'simp' because these SUTs have no
  # Puppet server to serve the `pki` class's keydist; `haveged: false`
  # because the haveged package is not available without EPEL.
  let(:hieradata) do
    <<~EOS
      ---
      compliance_engine::enforcement:
        - 'simp:defaults'
      simp_options::pki::source: '/etc/pki/simp-testing/pki'
      simp_options::trusted_nets: ['0.0.0.0/0']
      libreswan::pki: true
      libreswan::haveged: false
    EOS
  end

  hosts.each do |host|
    context "on #{host}" do
      it 'configures hiera with the compliance_engine backend' do
        set_hieradata_on(host, hieradata)
        set_hiera_config_on(host, hiera_yaml)
      end

      it 'applies with no errors' do
        apply_manifest_on(host, manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest, catch_changes: true)
      end

      it 'runs and enables the ipsec service' do
        on host, 'systemctl is-active ipsec'
        on host, 'systemctl is-enabled ipsec'
      end

      it 'manages the restored ipsec.conf fields in place' do
        [
          'protostack = netkey',
          'dumpdir = /var/run/pluto',
          'plutodebug = none',
          'virtual-private = %v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12',
        ].each do |line|
          on host, "grep -qx '  #{line}' /etc/ipsec.conf"
        end
      end

      it 'produces a config the ipsec tools can parse' do
        on host, 'ipsec addconn --checkconfig'
      end

      it 'restores the pre-5.0.0 file permissions' do
        on host, %(test "$(stat -c %a:%U /etc/ipsec.conf)" = '400:root')
        on host, %(test "$(stat -c %a:%U /etc/ipsec.d)" = '700:root')
      end

      it 'writes the five policy files' do
        ['block', 'clear', 'clear-or-private', 'private'].each do |policy|
          on host, "test -f /etc/ipsec.d/policies/#{policy}"
        end
        on host, "grep -qx '0.0.0.0/0' /etc/ipsec.d/policies/private-or-clear"
      end

      it 'installs the NSS helper script' do
        on host, 'test -x /usr/local/scripts/nss/update_nssdb_password.sh'
      end
    end
  end
end
