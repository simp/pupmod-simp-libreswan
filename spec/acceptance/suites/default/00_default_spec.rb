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
  fail("Could not determine the interface for the #{host}'s private network") unless interfaces.size == 1
  interfaces[0]
end

#FIXME this code is brittle!
def get_public_network_interface(host)
  interfaces = fact_on(host, 'interfaces').split(',')

  # remove interfaces we know are not the public network interface
  interfaces.delete_if do |ifc|
    ifc == 'lo' or
    ifc.include?('ip_') # IPsec tunnel
  end
  fail("Could not determine the interface for the #{host}'s public network") unless interfaces.size >= 1
  interfaces.sort!
  interfaces.sort[0]
end

#TODO move to Simp::BeakerHelpers
require 'timeout'
def wait_for_command_success(
    host,
    cmd,
    max_wait_seconds = (ENV['SIMPTEST_WAIT_FOR_CMD_MAX'] ? ENV['SIMPTEST_WAIT_FOR_CMD_MAX'].to_f : 60.0),
    interval_sec = (ENV['SIMPTEST_CMD_CHECK_INTERVAL'] ? ENV['SIMPTEST_CMD_CHECK_INTERVAL'].to_f : 1.0)
  )
  result = nil
  Timeout::timeout(max_wait_seconds) do
    while true
      result = on host, cmd, :accept_all_exit_codes => true
      return if result.exit_code == 0
      sleep(interval_sec)
    end
  end
rescue Timeout::Error => e
  error_msg = "Command '#{cmd}' failed to succeed within #{max_wait_seconds} seconds:\n"
  error_msg += "\texit_code = #{result.exit_code}\n"
  error_msg += "\tstdout = \"#{result.stdout}\"\n" unless result.stdout.nil? or result.stdout.strip.empty?
  error_msg += "\tstderr = \"#{result.stderr}\"" unless result.stderr.nil? or result.stderr.strip.empty?
  fail error_msg
end

test_name 'libreswan class'

['7'].each do |os_major_version|
  describe "libreswan class for EL #{os_major_version}" do
    let(:left) { only_host_with_role( hosts, "left#{os_major_version}" ) }
    let(:right) { only_host_with_role( hosts, "right#{os_major_version}" ) }
    let(:haveged) { "package { 'epel-release': ensure => installed, provider => 'rpm', source => \"https://dl.fedoraproject.org/pub/epel/epel-release-latest-#{os_major_version}.noarch.rpm\" } -> class { 'haveged': }" }
    let(:manifest) { "class { 'libreswan': }"}

    let(:leftinterface) { get_private_network_interface(left) }
    let(:leftip) { fact_on(left, %(ipaddress_#{leftinterface})) }
    let(:leftfqdn) { fact_on( left, 'fqdn' ) }
    let(:rightinterface) { get_private_network_interface(right) }
    let(:rightip) { fact_on(right, %(ipaddress_#{rightinterface})) }
    let(:rightfqdn) { fact_on( right, 'fqdn' ) }
    let(:nc_port) { 2389 }
    let(:leftconnection) {
      <<-EOS
        libreswan::connection{ 'default':
          leftcert      => "${::fqdn}",
          left          => "#{leftip}",
          leftrsasigkey => '%cert',
          leftsendcert  => 'always',
          authby        => 'rsasig',
        }
        libreswan::connection{ 'outgoing' :
          right          => "#{rightip}",
          rightrsasigkey => '%cert',
          auto           => 'start'
        }
  EOS
    }
    let(:rightconnection) {
      <<-EOS
        libreswan::connection{ 'default':
          leftcert      => "${::fqdn}",
          left          => "#{rightip}",
          leftrsasigkey => '%cert',
          leftsendcert  => 'always',
          authby        => 'rsasig'
        }
        libreswan::connection{ 'outgoing' :
          right          => "#{leftip}",
          rightrsasigkey => '%cert',
          auto           => 'start'
        }
  EOS
    }
    let(:hieradata_left) {
      <<-EOS
---
libreswan::service_name : 'ipsec'
libreswan::interfaces : ["ipsec0=#{leftip}"]
libreswan::listen : '#{leftip}'
simp_options::pki: true
simp_options::pki::source: '/etc/pki/simp-testing/pki'
EOS
    }
    let(:hieradata_right){
    <<-EOM
---
libreswan::service_name : 'ipsec'
libreswan::interfaces : ["ipsec0=#{rightip}"]
libreswan::listen : '#{rightip}'
simp_options::pki: true
simp_options::pki::source: '/etc/pki/simp-testing/pki'
EOM
    }
    let(:testfile) { testfile = "/tmp/testfile.#{Time.now.to_i}" }
    let(:nc) {'/bin/nc'}

    context 'test prep' do
      it 'should install haveged, nmap-ncat, and tcpdump' do
        [left, right].flatten.each do |node|
           # Generate ALL of the entropy .
           apply_manifest_on(node, haveged, :catch_failures => true)    
           node.install_package('nmap-ncat')
        end
        left.install_package('tcpdump')
      end
    end

    context 'tunnel using certs' do
      context "with pki" do
        it 'should apply manifest idempotently and start ipsec service' do
          set_hieradata_on(left, hieradata_left)
          set_hieradata_on(right,hieradata_right)

          [left, right].flatten.each do |node|
            # Apply ipsec and check for idempotency
            apply_manifest_on(node, manifest, :catch_failures => true)
            apply_manifest_on(node, manifest, :catch_changes => true)
            on node, "ipsec status", :acceptable_exit_codes => [0]
          end
        end

        it 'should listen on port 500, 4500' do
          [left, right].flatten.each do |node|
            on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':500'", :acceptable_exit_codes => [0]
            on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':4500'", :acceptable_exit_codes => [0]
          end
        end

        it 'should load certs and create NSS Database' do
          on left, "certutil -L -d sql:/etc/ipsec.d | grep -i #{leftfqdn}", :acceptable_exit_codes => [0]
          on right, "certutil -L -d sql:/etc/ipsec.d | grep -i #{rightfqdn}", :acceptable_exit_codes => [0]
        end
      end

      context 'with connection but no firewall protection' do
        it 'should apply manifest idempotently and restart ipsec service' do
          apply_manifest_on(left, leftconnection, :catch_failures => true)
          apply_manifest_on(right, rightconnection, :catch_failures => true)
          apply_manifest_on(left, leftconnection, :catch_changes => true)
          apply_manifest_on(right, rightconnection, :catch_changes => true)
          on left, "ipsec status", :acceptable_exit_codes => [0]
          on right, "ipsec status", :acceptable_exit_codes => [0]
        end

        it "should start a usable connection in tunnel mode" do
          wait_for_command_success(left,  "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")
          wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")
          wait_for_command_success(left, "ip xfrm policy | grep 'mode tunnel'")
          wait_for_command_success(right, "ip xfrm policy | grep 'mode tunnel'")

          # send TCP data from right to left over the tunnel and tcpdump
          # while packets are being sent
          on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]

          # couldn't get tcpdump to work as a background process, so run in a thread
          lthread = Thread.new {
            filter = "ip proto 50 and dst #{leftip}"
#            filter = "dst #{leftip} and \( \(ip proto 50\) or \(port #{nc_port} \) \)"
            on left, "tcpdump -i #{leftinterface} -c 3 -w #{testfile}.pcap #{filter}",
              :acceptable_exit_codes => [0]
          }
          sleep(2)
          on right, "echo 'this is a test of a tunnel' | #{nc} -s #{rightip} #{left} #{nc_port} -w 5 ", :acceptable_exit_codes => [0]
          lthread.join

          # verify data reaches left
          on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
            expect(stdout).to match(/this is a test of a tunnel/)
          end

          # verify data carried over ESP
          # Ideally, would want to look at pairs of ESP and decrypted packets.  In an
          # automated test, this gets tricky because ESP keep-alive packets may screw
          # up exact analysis.  So, we are limited to this weak check for now.
          on left, "tcpdump -r #{testfile}.pcap -n", :acceptable_exit_codes => [0] do
            expect(stdout).to match(/ESP\(spi/)
          end
        end
      end

    #  context 'when tunnel goes down' do
    #    it 'should detect disabled tunnel' do
    #      on left, 'puppet resource service ipsec ensure=stopped', :acceptable_exit_codes => [0]
    #      wait_for_command_success(left, "ipsec status |& grep 'Pluto is not running'")

          # can take up to 2 minutes for right to timeout tunnel, so restart instead to detect
          # failure immediately
    #     wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 0\"")
    #      wait_for_command_success(right, "ip xfrm policy | grep 'mode transport'")
    #    end

    #    it "should drop data because of broken tunnel" do
          # try to send TCP data from right to left
    #      on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]
    #      sleep(2)
    #      on right, "echo 'this is a test of a downed tunnel without firewall' | #{nc} -s #{rightip} #{left} #{nc_port} ",
    #        :acceptable_exit_codes => [1]

    #        verify data does NOT reach left
    #      on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
    #        expect(stdout).to_not match(/this is a test of a downed tunnel without firewall/)
    #      end
    #      on left, "pkill -f '#{nc} -l #{nc_port}'", :acceptable_exit_codes => [0]
    #    end
    #  end

    #  context 'when connection with firewall' do
    #    let(:client_net) {
    #      quads = leftip.split('.')  # doesn't matter if use left or right ip
    #      quads[2] = '0'
    #      quads[3] = '0'
    #      quads.join('.') + '/16'
    #    }
    #    let(:hieradata_with_firewall_left)  {
    #      hieradata_left +
    #      "simp_options::firewall: yes\n" +
    #      "simp_options::trusted_nets : ['#{client_net}']\n"
    #    }
    #    let(:hieradata_with_firewall_right) {
    #      hieradata_right +
    #      "simp_options::firewall: yes\n" +
    #      "simp_options::trusted_nets : ['#{client_net}']\n"
    #    }
    #    let(:leftconnection_with_firewall) { leftconnection +
    #      "      class { 'iptables': }\n" +
    #      "      iptables::rule {'allow_public_network_interface':\n" +
    #      "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(left)} -j ACCEPT',\n" +
    #      "        apply_to => 'all',\n" +
    #      "        order => 11\n" +
    #      "      }\n" +
    #      "      iptables::rule {'allow_decrypted_nc_traffic':\n" +
    #      "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" +
    #      "        apply_to => 'all',\n" +
    #      "        order => 11\n" +
    #      "      }\n" +
    #      "      iptables::listen::tcp_stateful { 'allow_sshd':\n" +
    #      "        order => 8,\n" +
    #      "        trusted_nets => ['ALL'],\n" +
    #      "        dports => 22,\n" +
    #      "      }\n"
    #    }
    #    let(:rightconnection_with_firewall) { rightconnection +
    #      "      class { 'iptables': }\n" +
    #      "      iptables::rule {'allow_public_network_interface':\n" +
    #      "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(right)} -j ACCEPT',\n" +
    #      "        apply_to => 'all',\n" +
    #      "        order => 11\n" +
    #      "      }\n" +
    #      "      iptables::rule {'allow_decrypted_nc_traffic':\n" +
    #      "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" +
    #      "        apply_to => 'all',\n" +
    #      "        order => 11\n" +
    #      "      }\n" +
    #      "      iptables::listen::tcp_stateful { 'allow_sshd':\n" +
    #      "        order => 8,\n" +
    #      "        trusted_nets => ['ALL'],\n" +
    #      "        dports => 22,\n" +
    #      "      }\n"
    #    }

    #    it 'should apply manifest idempotently, restart ipsec service, start iptables with ipsec firewall' do
    #      set_hieradata_on(left, hieradata_with_firewall_left)
    #      set_hieradata_on(right,hieradata_with_firewall_right)
    
          # Apply ipsec and check for idempotency
    #      apply_manifest_on(left, leftconnection_with_firewall, :catch_failures => true)
    #      apply_manifest_on(right, rightconnection_with_firewall, :catch_failures => true)
    #      apply_manifest_on(left, leftconnection_with_firewall, :catch_changes => true)
    #      apply_manifest_on(right, rightconnection_with_firewall, :catch_changes => true)

    #      [left, right].flatten.each do |node|
    #        on node, "ipsec status", :acceptable_exit_codes => [0]
    #        on node, 'iptables --list -v', :acceptable_exit_codes => [0] do
    #          expect(stdout).to match(/ACCEPT\s+udp\s+--\s+any\s+any\s+#{client_net}\s+anywhere\s+state NEW multiport dports ipsec-nat-t,isakmp/m)
    #          expect(stdout).to match(/ACCEPT\s+esp/m)
    #          expect(stdout).to match(/ACCEPT\s+ah/m)
    #        end
    #      end
    #    end

    #    it "should allow data carried by connection's tunnel" do
    #      wait_for_command_success(left,  "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")
    #      wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")

          # send TCP data from right to left
    #      on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]
    #      sleep(2)
    #      on right, "echo 'this is a test of a tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ", :acceptable_exit_codes => [0]

          # verify data does reach left
    #      on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
    #        expect(stdout).to match(/this is a test of a tunnel with firewall enabled/)
    #      end

          # verify iptables packet counts for esp and nc (over tcp) traffic have incremented
    #      on left, 'iptables --list -v' do
    #        expect(stdout).to match(/^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+esp/m)
    #        expect(stdout).to match(/^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+tcp/m)
    #      end
    #    end
    #  end

    #  context 'when tunnel goes down with firewall protection' do
    #    it 'should detect disabled tunnel' do
    #      on left, 'puppet resource service ipsec ensure=stopped', :acceptable_exit_codes => [0]
    #      wait_for_command_success(left, "ipsec status |& grep 'Pluto is not running'")

          # can take up to 2 minutes for right to timeout tunnel,
          # so restart instead to detect
          # failure immediately
    #      wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 0\"")
    #      wait_for_command_success(right, "ip xfrm policy | grep 'mode transport'")
    #    end

    #    it "should drop data because of broken tunnel" do
          # try to send TCP data from right to left
    #      on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]
    #      sleep(2)
    #      on right, "echo 'this is a test of a downed tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ",
    #        :acceptable_exit_codes => [1]

          # verify data does NOT reach left
    #      on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
    #        expect(stdout).to_not match(/this is a test of a downed tunnel with firewall enabled/)
    #      end
    #      on left, "pkill -f '#{nc} -l #{nc_port}'", :acceptable_exit_codes => [0]
    #    end
    #  end
    end
    #TODO ipv6 tests
  end
end
