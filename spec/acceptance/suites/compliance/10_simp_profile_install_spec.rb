require 'spec_helper_acceptance'

test_name 'libreswan STIG enforcement of simp profile'

describe 'libreswan STIG enforcement of simp profile' do

  let(:manifest) {
    <<-EOS
      include 'libreswan'
    EOS
  }

  hosts.each do |host|
    let(:hiera_yaml) { <<~EOM
      ---
      version: 5
      hierarchy:
        - name: Common
          path: common.yaml
        - name: Compliance
          lookup_key: compliance_markup::enforcement
      defaults:
        data_hash: yaml_data
        datadir: /etc/puppetlabs/code/environments/production/hieradata
      EOM
    }

    context 'when enforcing the STIG' do
      it 'should enable compliance enforcement' do
        common_yaml = on(host, "cat '#{hiera_datadir(host)}/common.yaml'").output

        hieradata = YAML.load(common_yaml)
        hieradata['compliance_markup::enforcement'] = ['disa_stig']

        write_hieradata_to(host, hieradata)

        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
      end

      it 'should work with no errors' do
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end
  end
end
