require 'spec_helper_acceptance'

test_name 'ipsec class'

describe 'ipsec class' do
  let(:server){ only_host_with_role( hosts, 'server' ) }
  let(:haveged) { "package { 'epel-release': ensure => present } -> class { 'haveged': }" }
  let(:manifest) {
    <<-EOS
      class { 'ipsec': }
    EOS
  }

  context 'default parameters' do
    # Using puppet_apply as a helper
    it 'should work with no errors' do
      apply_manifest(haveged, :catch_failures => true)
      sleep(30)
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
       on server, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':500'", :acceptable_exit_codes => [0]
    end
    it 'should be listening on port 4500' do
       on server, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':4500'", :acceptable_exit_codes => [0]
    end

  end
end
