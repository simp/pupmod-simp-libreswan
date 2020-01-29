require 'spec_helper_acceptance'

test_name 'libreswan class'

hosts.each do |host|
  describe "test prep for #{host}" do
    let(:os_major_version) { fact_on(host, 'operatingsystemmajrelease').strip }

    let(:haveged) { <<~EOM
        package { 'epel-release':
          ensure   => installed,
          provider => 'rpm',
          source   => 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-#{os_major_version}.noarch.rpm'
        } -> class { 'haveged': }

        include 'haveged'

      EOM
    }

    context 'test prep' do
      it 'should install haveged, nmap-ncat, and tcpdump' do
        # Generate ALL of the entropy .
        apply_manifest_on(host, haveged, :catch_failures => true)

        if os_major_version == '6'
          host.install_package('nc')
        else
          host.install_package('nmap-ncat')
        end

        host.install_package('tcpdump')
      end
    end
  end
end
