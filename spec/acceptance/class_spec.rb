require 'spec_helper_acceptance'

test_name 'ipsec class'

describe 'ipsec class' do
  let(:server) { only_host_with_role( hosts, 'server' ) }
  let(:clients) { hosts_with_role( hosts, 'ipsec' ) }
  let(:haveged) { "package { 'epel-release': ensure => present } -> class { 'haveged': }" }
  let(:manifest) {
    <<-EOS
      class { 'ipsec': }
    EOS
  }

  context 'default parameters' do

    # Generate ALL of the entropy.
    it 'should install haveged' do
      [server, clients].flatten.each do |node|
        apply_manifest_on( node, haveged, :catch_failures => true)
      end
      sleep(30)
    end

    it 'should apply ipsec, and start the ipsec service' do
      [server, clients].flatten.each do |node|
        # Apply ipsec and check for idempotency
        apply_manifest_on( node, manifest, :catch_failures => true)
        apply_manifest_on( node, manifest, :catch_changes => true)
        on node, "service ipsec status", :acceptable_exit_codes => [0]
      end
    end

    it 'should listen on port 500, 4500' do
      [server, clients].flatten.each do |node|
        on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':500'", :acceptable_exit_codes => [0]
        on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':4500'", :acceptable_exit_codes => [0]
      end
    end

  end
end
