require 'spec_helper_acceptance'

#FIXME this code is brittle!
def get_private_network_interface(host)
  interfaces = fact_on(host, 'interfaces').split(',')
   
  # remove interfaces we know are not the private network interface
  interfaces.delete_if do |ifc| 
    ifc == 'lo' or
    ifc.include?('ip_') or # IPsec tunnel
    ifc == 'enp0s3' or     # public interface for puppetlabs/centos-7.2-64-nocm virtual box
    ifc == 'eth0'          # public interface for centos/7 virtual box
  end
  fail("Expecting one interface for the private network: #{interfaces.join(' ')}") unless interfaces.size == 1
  interfaces[0]
end

test_name 'libreswan class'

describe 'libreswan class' do
  let(:left) { only_host_with_role( hosts, 'left' ) }
  let(:right) { only_host_with_role( hosts, 'right' ) }
  let(:haveged) { "package { 'epel-release': ensure => present } -> class { 'haveged': }" }
  let(:manifest) {
    <<-EOS
      class { '::pki':
        cacerts_sources    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
        private_key_source => "file:///etc/pki/simp-testing/pki/private/${::fqdn}.pem",
        public_key_source  => "file:///etc/pki/simp-testing/pki/public/${::fqdn}.pub"
      }
      class { 'libreswan': }
    EOS
  }
  let(:leftinterface) { get_private_network_interface(left) }
  let(:leftip) { fact_on(left, %(ipaddress_#{leftinterface})) }
  let(:leftfqdn) { fact_on( left, 'fqdn' ) }
  let(:rightinterface) { get_private_network_interface(right) }
  let(:rightip) { fact_on(right, %(ipaddress_#{rightinterface})) }
  let(:rightfqdn) { fact_on( right, 'fqdn' ) }
  let(:leftconnection) {
    <<-EOS
      class { '::pki':
        cacerts_sources    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
        private_key_source => "file:///etc/pki/simp-testing/pki/private/${::fqdn}.pem",
        public_key_source  => "file:///etc/pki/simp-testing/pki/public/${::fqdn}.pub"
      }
      libreswan::add_connection{ 'default':
        leftcert      => "${::fqdn}",
        left          => "#{leftip}",
        leftrsasigkey => '%cert',
        leftsendcert  => 'always',
        authby        => 'rsasig',
      }
      libreswan::add_connection{ 'outgoing' :
        right          => "#{rightip}",
        rightrsasigkey => '%cert',
        auto           => 'start'
      }
    EOS
  }
  let(:rightconnection) {
    <<-EOS
      class { '::pki':
        cacerts_sources    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
        private_key_source => "file:///etc/pki/simp-testing/pki/private/${::fqdn}.pem",
        public_key_source  => "file:///etc/pki/simp-testing/pki/public/${::fqdn}.pub"
      }
      libreswan::add_connection{ 'default':
        leftcert      => "${::fqdn}",
        left          => "#{rightip}",
        leftrsasigkey => '%cert',
        leftsendcert  => 'always',
        authby        => 'rsasig'
      }
      libreswan::add_connection{ 'outgoing' :
        right          => "#{leftip}",
        rightrsasigkey => '%cert',
        auto           => 'start'
      }
    EOS
  }
  let(:myhieradataleft) {
    <<-EOS
---
pki_dir : '/etc/pki/simp-testing/pki'
libreswan::pkiroot : '/etc/pki/simp-testing/pki'
libreswan::service_name : 'ipsec'
libreswan::use_simp_pki : true
libreswan::interfaces : ["ipsec0=#{leftip}"]
libreswan::listen : '#{leftip}'
  EOS
  }
  let(:myhieradataright){
  <<-EOM
---
pki_dir : '/etc/pki/simp-testing/pki'
libreswan::service_name : 'ipsec'
libreswan::use_simp_pki : true
libreswan::pkiroot : '/etc/pki/simp-testing/pki'
libreswan::interfaces : ["ipsec0=#{rightip}"]
libreswan::listen : '#{rightip}'
    EOM
  }

  context 'tunnel using certs' do
    # Generate ALL of the entropy.
    it 'should install haveged' do
      [left, right].flatten.each do |node|
         apply_manifest_on( node, haveged, :catch_failures => true)
      end
      sleep(30)
    end

    context "with use_simp_pki" do
      it 'should apply ipsec, start ipsec service and load certs ' do
        set_hieradata_on(left, myhieradataleft)
        set_hieradata_on(right,myhieradataright)

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

      it 'should load certs and create NSS Database' do
        on left, "/bin/certutil -L -d sql:/etc/ipsec.d | grep -i #{leftfqdn}", :acceptable_exit_codes => [0]
        on right, "/bin/certutil -L -d sql:/etc/ipsec.d | grep -i #{rightfqdn}", :acceptable_exit_codes => [0]
      end
    end

    context 'add_connection' do
      it "should apply manifests" do
        apply_manifest_on( left, leftconnection, :catch_failures => true)
        apply_manifest_on( right, rightconnection, :catch_failures => true)
      end
      it "should apply manifests idempotently" do
        apply_manifest_on( left, leftconnection, :catch_changes => true)
        apply_manifest_on( right, rightconnection, :catch_changes => true)
      end

      it "should start connections" do
        sleep(30)
        on left, "ipsec status | grep -i \"Total IPsec connections: loaded 1, active 1\"", :acceptable_exit_codes => [0]
        on right, "ipsec status | grep -i \"Total IPsec connections: loaded 1, active 1\"", :acceptable_exit_codes => [0]
      end
   end

  end
end
