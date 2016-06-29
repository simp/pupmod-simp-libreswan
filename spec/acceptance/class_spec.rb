require 'spec_helper_acceptance'

test_name 'libreswan class'

describe 'libreswan class' do
  let(:left){ only_host_with_role( hosts, 'left' ) }
  let(:right) { only_host_with_role( hosts, 'right' ) }
  let(:haveged) { "package { 'epel-release': ensure => present } -> class { 'haveged': }" }
  let(:manifest) {
    <<-EOS
      class { 'libreswan': }
    EOS
  }
  let(:addcacert){
    <<-EOS
    file { "/etc/pki/simp-testing/pki/cacerts/cacerts.pem" :
      ensure => file,
      owner  => root,
    }
    libreswan::nss::loadcerts { "CA_for_${::domain}" :
      cert        => '/etc/pki/simp-testing/pki/cacerts/cacerts.pem',
      cacert      => true,
      dbdir       => '/etc/ipsec.d',
      nsspwd_file => '/etc/ipsec.d/nsspassword',
      token       => 'NSS Certificate DB',
      subscribe   => File["/etc/pki/simp-testing/pki/cacerts/cacerts.pem"]
    }

    EOS
  }

  let(:addcert){
    <<-EOS
    file { "/etc/pki/simp-testing/pki/public/${::fqdn}.pub" :
      ensure => file,
      owner  => root,
    }
    libreswan::nss::loadcerts{ "$::fqdn" :
      dbdir       => '/etc/ipsec.d',
      nsspwd_file => '/etc/ipsec.d/nsspassword',
      cert        => "/etc/pki/simp-testing/pki/public/${::fqdn}.pub",
      cacert      => false,
      key         => "/etc/pki/simp-testing/pki/private/${::fqdn}.pem",
      token       => 'NSS Certificate DB',
      subscribe   => File["/etc/pki/simp-testing/pki/public/${::fqdn}.pub"]
    }
  EOS
  }
  let(:leftip){ fact_on( left, 'ipaddress_enp0s8' ) }
  let(:leftfqdn){ fact_on( left, 'fqdn' ) }
  let(:rightip){ fact_on( right, 'ipaddress_enp0s8' ) }
  let(:rightfqdn){ fact_on( right, 'fqdn' ) }
  let(:hieradata_rightinterfaces){
    {
      'libreswan::interfaces' => "ipsec0=enp0s8",
      'libreswan::listen' => "#{rightip}"
    }
  }
  let(:hieradata_leftinterfaces){
    {
      'libreswan::interfaces' => "ipsec0=enp0s8",
      'libreswan::listen' => "#{leftip}"
    }
  }
  let(:leftconnection){
  <<-EOS
    libreswan::add_connection{ 'default':
      leftcert => "${::fqdn}",
      left   => "#{leftip}",
      leftrsasigkey     => '%cert',
      leftsendcert      => 'always',
      authby  => 'rsasig'
    }
    libreswan::add_connection{ 'outgoing' :
      right  => "#{rightip}",
      rightrsasigkey     => '%cert',
      auto => 'start'
    }
  EOS
  }
  let(:rightconnection){
  <<-EOS
    libreswan::add_connection{ 'default':
      leftcert => "${::fqdn}",
      left   => "#{rightip}",
      leftrsasigkey     => '%cert',
      leftsendcert      => 'always',
      authby  => 'rsasig'
    }
    libreswan::add_connection{ 'outgoing' :
      right  => "#{leftip}",
      rightrsasigkey     => '%cert',
      auto => 'start'
    }
  EOS
  }

  context 'default parameters' do

    # Generate ALL of the entropy.
    it 'should install haveged' do
      [left, right].flatten.each do |node|
         apply_manifest_on( node, haveged, :catch_failures => true)
      end
      sleep(30)
    end

    it 'should apply ipsec, and start the ipsec service' do
      set_hieradata_on( left, hieradata_leftinterfaces)
      set_hieradata_on( right, hieradata_rightinterfaces)
      [left, right].flatten.each do |node|
      # Apply ipsec and check for idempotency
        apply_manifest_on( node, manifest, :catch_failures => true)
        apply_manifest_on( node, manifest, :catch_changes => true)
        on node, "service ipsec status", :acceptable_exit_codes => [0]
      end
    end

    it 'should listen on port 500, 4500' do
      [left, right].flatten.each do |node|
        on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':500'", :acceptable_exit_codes => [0]
        on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':4500'", :acceptable_exit_codes => [0]
      end
    end

    it 'should load certs in NSS DB' do
      [left, right].flatten.each do |node|
        apply_manifest_on( node, addcacert, :catch_failures => true)
        apply_manifest_on( node, addcert, :catch_failures => true)
        on node, "service ipsec status", :acceptable_exit_codes => [0]
      end
      on left, "/bin/certutil -L -d sql:/etc/ipsec.d | grep -i #{leftfqdn}", :acceptable_exit_codes => [0]
      on right, "/bin/certutil -L -d sql:/etc/ipsec.d | grep -i #{rightfqdn}", :acceptable_exit_codes => [0]
    end

   it 'should start connections' do
     apply_manifest_on( left,leftconnection, :catch_failures => true)
     apply_manifest_on( right, rightconnection, :catch_failures => true)
     apply_manifest_on( left,leftconnection, :catch_changes => true)
     apply_manifest_on( right, rightconnection, :catch_changes => true)
     sleep(30)
     on left, "ipsec status | grep -i \"Total IPsec connections: loaded 1, active 1\"", :acceptable_exit_codes => [0]
     on right, "ipsec status | grep -i \"Total IPsec connections: loaded 1, active 1\"", :acceptable_exit_codes => [0]
   end

  end
end
