require 'spec_helper_acceptance'

test_name 'ipsec_tunnel class'

describe 'ipsec_tunnel class' do
  let(:manifest) {
    <<-EOS
      class { 'ipsec_tunnel': }
    EOS
  }

  context 'default parameters' do
    # Using puppet_apply as a helper
    it 'should work with no errors' do
      apply_manifest(manifest, :catch_failures => true)
    end

    it 'should be idempotent' do
      apply_manifest(manifest, :catch_changes => true)
    end


    describe package('libreswan') do
      it { is_expected.to be_installed }
    end

    describe service('ipsec') do
      it { is_expected.to be_enabled }
      it { is_expected.to be_running }
    end
 
    it 'should be listening on port 500' do
       on server, "netstat -nuap | grep '^tcp.* [dd]d.[dd]d.[dd]d.[dd]d:500 .*/pluto'", :acceptable_exit_codes => [0]
    end
    it 'should be listening on port 4500' do
       on server, "netstat -nuap | grep '^ucp.* [dd]d.[dd]d.[dd]d.[dd]d:4500 .*/pluto'", :acceptable_exit_codes => [0]
    end

  end
end
