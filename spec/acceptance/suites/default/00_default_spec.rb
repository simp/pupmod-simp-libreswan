require 'spec_helper_acceptance'

# FIXME: this code is brittle!
def get_private_network_interface(host)
  interfaces = fact_on(host, 'interfaces').split(',')

  # remove interfaces we know are not the private network interface
  interfaces.delete_if do |ifc|
    ifc == 'lo' or
      ifc.include?('ip_') or # IPsec tunnel
      ifc == 'enp0s3' or     # public interface for puppetlabs/centos-7.2-64-nocm virtual box
      ifc == 'eth0'          # public interface for centos/7 virtual box
  end
  raise("Could not determine the interface for the #{host}'s private network") unless interfaces.size == 1
  interfaces[0]
end

# FIXME: this code is brittle!
def get_public_network_interface(host)
  interfaces = fact_on(host, 'interfaces').split(',')

  # remove interfaces we know are not the public network interface
  interfaces.delete_if do |ifc|
    ifc == 'lo' or
      ifc.include?('ip_') # IPsec tunnel
  end
  raise("Could not determine the interface for the #{host}'s public network") unless interfaces.size >= 1
  interfaces.sort[0]
end

# TODO: move to Simp::BeakerHelpers
require 'timeout'
def wait_for_command_success(
  host,
  cmd,
  max_wait_seconds = (ENV['SIMPTEST_WAIT_FOR_CMD_MAX'] ? ENV['SIMPTEST_WAIT_FOR_CMD_MAX'].to_f : 60.0),
  interval_sec = (ENV['SIMPTEST_CMD_CHECK_INTERVAL'] ? ENV['SIMPTEST_CMD_CHECK_INTERVAL'].to_f : 1.0)
)
  result = nil
  Timeout.timeout(max_wait_seconds) do
    loop do
      result = on host, cmd, accept_all_exit_codes: true
      return if result.exit_code == 0
      sleep(interval_sec)
    end
  end
rescue Timeout::Error
  error_msg = "Command '#{cmd}' failed to succeed within #{max_wait_seconds} seconds:\n"
  error_msg += "\texit_code = #{result.exit_code}\n"
  error_msg += "\tstdout = \"#{result.stdout}\"\n" unless result.stdout.nil? || result.stdout.strip.empty?
  error_msg += "\tstderr = \"#{result.stderr}\"" unless result.stderr.nil? || result.stderr.strip.empty?
  raise error_msg
end

test_name 'libreswan class'

describe 'enable epel' do
  it 'enables EPEL' do
    enable_epel_on(hosts)
  end
end

['7', '8'].each do |os_major_version|
  describe "libreswan class for EL #{os_major_version}" do
    let(:left) { only_host_with_role(hosts, "left#{os_major_version}") }
    let(:right) { only_host_with_role(hosts, "right#{os_major_version}") }
    let(:haveged) { 'include haveged' }

    let(:disable_firewalld) { "service { 'firewalld': ensure => 'stopped', enable => false }" }
    let(:disable_iptables) { "service { 'iptables': ensure => 'stopped', enable => false }" }
    let(:manifest) { "class { 'libreswan': }" }

    let(:leftinterface) { get_private_network_interface(left) }
    let(:leftip) { fact_on(left, %(ipaddress_#{leftinterface})) }
    let(:leftfqdn) { fact_on(left, 'fqdn') }
    let(:rightinterface) { get_private_network_interface(right) }
    let(:rightip) { fact_on(right, %(ipaddress_#{rightinterface})) }
    let(:rightfqdn) { fact_on(right, 'fqdn') }
    let(:nc_port) { 2389 }
    let(:leftconnection) do
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
    end
    let(:rightconnection) do
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
    end
    let(:hieradata_left) do
      <<~EOS
        ---
        libreswan::service_name : 'ipsec'
        libreswan::interfaces : ["ipsec0=#{leftip}"]
        libreswan::listen : '#{leftip}'
        simp_options::pki: true
        simp_options::pki::source: '/etc/pki/simp-testing/pki'
      EOS
    end
    let(:hieradata_right) do
      <<~EOM
        ---
        libreswan::service_name : 'ipsec'
        libreswan::interfaces : ["ipsec0=#{rightip}"]
        libreswan::listen : '#{rightip}'
        simp_options::pki: true
        simp_options::pki::source: '/etc/pki/simp-testing/pki'
      EOM
    end
    let(:testfile) { "/tmp/testfile.#{Time.now.to_i}" }
    let(:nc) { '/bin/nc' }

    context 'test prep' do
      it 'installs haveged, nmap-ncat, screen, and tcpdump' do
        [left, right].flatten.each do |node|
          # Generate ALL of the entropy .
          apply_manifest_on(node, haveged, catch_failures: true)
          node.install_package('nmap-ncat')
        end
        left.install_package('screen')
        left.install_package('tcpdump')
      end

      it 'disables firewalls' do
        [left, right].flatten.each do |node|
          if os_major_version == '8'
            apply_manifest_on(node, disable_firewalld, catch_failures: true)
          else
            apply_manifest_on(node, disable_iptables, catch_failures: true)
          end
        end
      end
    end

    context 'tunnel using certs' do
      context 'with pki' do
        it 'applies manifest idempotently and start ipsec service' do
          set_hieradata_on(left, hieradata_left)
          set_hieradata_on(right, hieradata_right)

          [left, right].flatten.each do |node|
            # Apply ipsec and check for idempotency
            apply_manifest_on(node, manifest, catch_failures: true)
            apply_manifest_on(node, manifest, catch_changes: true)
            on node, 'ipsec status', acceptable_exit_codes: [0]
          end
        end

        it 'listens on port 500, 4500' do
          [left, right].flatten.each do |node|
            on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':500'", acceptable_exit_codes: [0]
            on node, "netstat -nuapl | grep -e '.*\/pluto' | grep -e ':4500'", acceptable_exit_codes: [0]
          end
        end

        it 'loads certs and create NSS Database' do
          on left, "certutil -L -d sql:/etc/ipsec.d | grep -i #{leftfqdn}", acceptable_exit_codes: [0]
          on right, "certutil -L -d sql:/etc/ipsec.d | grep -i #{rightfqdn}", acceptable_exit_codes: [0]
        end
      end

      context 'with connection but no firewall protection' do
        it 'applies manifest idempotently and restart ipsec service' do
          apply_manifest_on(left, leftconnection, catch_failures: true)
          apply_manifest_on(right, rightconnection, catch_failures: true)
          apply_manifest_on(left, leftconnection, catch_changes: true)
          apply_manifest_on(right, rightconnection, catch_changes: true)
          on left, 'ipsec status', acceptable_exit_codes: [0]
          on right, 'ipsec status', acceptable_exit_codes: [0]
        end

        it 'starts a usable connection in tunnel mode' do
          wait_for_command_success(left,  'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 1"')
          wait_for_command_success(right, 'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 1"')
          wait_for_command_success(left, "ip xfrm policy | grep 'mode tunnel'")
          wait_for_command_success(right, "ip xfrm policy | grep 'mode tunnel'")

          # send TCP data from right to left over the tunnel and tcpdump
          # while packets are being sent
          on left, "/usr/bin/screen -dm bash -c '#{nc} -l #{nc_port} > #{testfile}'", acceptable_exit_codes: [0]

          # couldn't get tcpdump to work as a background process, so run in a thread
          lthread = Thread.new do
            filter = "ip proto 50 and dst #{leftip}"
            #            filter = "dst #{leftip} and \( \(ip proto 50\) or \(port #{nc_port} \) \)"
            on left, "tcpdump -i #{leftinterface} -c 3 -w #{testfile}.pcap #{filter}",
              acceptable_exit_codes: [0]
          end
          sleep(2)
          on right, "echo 'this is a test of a tunnel' | #{nc} -s #{rightip} #{left} #{nc_port} -w 5 ", acceptable_exit_codes: [0]
          lthread.join

          # verify data reaches left
          on left, "cat #{testfile}", acceptable_exit_codes: [0] do
            expect(stdout).to match(%r{this is a test of a tunnel})
          end

          # verify data carried over ESP
          # Ideally, would want to look at pairs of ESP and decrypted packets.  In an
          # automated test, this gets tricky because ESP keep-alive packets may screw
          # up exact analysis.  So, we are limited to this weak check for now.
          on left, "tcpdump -r #{testfile}.pcap -n", acceptable_exit_codes: [0] do
            expect(stdout).to match(%r{ESP\(spi})
          end
        end
      end

      context 'when tunnel goes down' do
        it 'detects disabled tunnel' do
          on left, 'puppet resource service ipsec ensure=stopped', acceptable_exit_codes: [0]
          wait_for_command_success(left, "ipsec status |& grep 'Pluto is not running'")

          # can take up to 2 minutes for right to timeout tunnel, so restart instead to detect
          # failure immediately
          wait_for_command_success(right, 'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 0"')
          wait_for_command_success(right, "ip xfrm policy | grep 'mode transport'")
        end

        it 'drops data because of broken tunnel' do
          # try to send TCP data from right to left
          on left, "/usr/bin/screen -dm bash -c '#{nc} -l #{nc_port} > #{testfile}'", acceptable_exit_codes: [0]
          sleep(2)
          on right, "echo 'this is a test of a downed tunnel without firewall' | #{nc} -s #{rightip} #{left} #{nc_port} ",
            acceptable_exit_codes: [1]

          # verify data does NOT reach left
          on left, "cat #{testfile}", acceptable_exit_codes: [0] do
            expect(stdout).not_to match(%r{this is a test of a downed tunnel without firewall})
          end
          on left, "pkill -f '#{nc} -l #{nc_port}'", acceptable_exit_codes: [0]
        end
      end

      context 'when connection with firewall' do
        let(:client_net) do
          quads = leftip.split('.') # doesn't matter if use left or right ip
          quads[2] = '0'
          quads[3] = '0'
          quads.join('.') + '/16'
        end
        let(:hieradata_with_firewall_left) do
          hieradata_left +
            "simp_options::firewall: true\n" \
            "simp_options::trusted_nets : ['#{client_net}']\n"
        end
        let(:hieradata_with_firewall_right) do
          hieradata_right +
            "simp_options::firewall: true\n" \
            "simp_options::trusted_nets : ['#{client_net}']\n"
        end
        let(:leftconnection_with_iptables) do
          leftconnection +
            "      class { 'iptables': }\n" \
            "      iptables::rule {'allow_public_network_interface':\n" \
            "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(left)} -j ACCEPT',\n" \
            "        apply_to => 'all',\n" \
            "        order => 11\n" \
            "      }\n" \
            "      iptables::rule {'allow_decrypted_nc_traffic':\n" \
            "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" \
            "        apply_to => 'all',\n" \
            "        order => 11\n" \
            "      }\n" \
            "      iptables::listen::tcp_stateful { 'allow_sshd':\n" \
            "        order => 8,\n" \
            "        trusted_nets => ['ALL'],\n" \
            "        dports => 22,\n" \
            "      }\n"
        end
        let(:leftconnection_with_firewalld) do
          leftconnection +
            "      class { 'simp_firewalld': }\n" \
            "      simp_firewalld::rule { 'allow_all_sshd':\n" \
            "        trusted_nets => ['ALL'],\n" \
            "        protocol     => 'tcp',\n" \
            "        dports       => 22,\n" \
            "      }\n" \
            "      simp_firewalld::rule { 'allow_decrypted_nc_traffic':\n" \
            "        protocol     => 'tcp',\n" \
            "        dports       => #{nc_port},\n" \
            "      }\n"
        end
        let(:rightconnection_with_iptables) do
          rightconnection +
            "      class { 'iptables': }\n" \
            "      iptables::rule {'allow_public_network_interface':\n" \
            "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(right)} -j ACCEPT',\n" \
            "        apply_to => 'all',\n" \
            "        order => 11\n" \
            "      }\n" \
            "      iptables::rule {'allow_decrypted_nc_traffic':\n" \
            "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" \
            "        apply_to => 'all',\n" \
            "        order => 11\n" \
            "      }\n" \
            "      iptables::listen::tcp_stateful { 'allow_sshd':\n" \
            "        order => 8,\n" \
            "        trusted_nets => ['ALL'],\n" \
            "        dports => 22,\n" \
            "      }\n"
        end
        let(:rightconnection_with_firewalld) do
          rightconnection +
            "      class { 'simp_firewalld': }\n" \
            "      simp_firewalld::rule { 'allow_all_sshd':\n" \
            "        trusted_nets => ['ALL'],\n" \
            "        protocol     => 'tcp',\n" \
            "        dports       => 22,\n" \
            "      }\n" \
            "      simp_firewalld::rule { 'allow_decrypted_nc_traffic':\n" \
            "        protocol     => 'tcp',\n" \
            "        dports       => #{nc_port},\n" \
            "      }\n"
        end

        it 'applies manifest idempotently, restart ipsec service, start iptables with ipsec firewall' do
          set_hieradata_on(left, hieradata_with_firewall_left)
          set_hieradata_on(right, hieradata_with_firewall_right)

          # Apply ipsec and check for idempotency
          if os_major_version == '8'
            apply_manifest_on(left, leftconnection_with_firewalld, catch_failures: true)
            apply_manifest_on(right, rightconnection_with_firewalld, catch_failures: true)
            apply_manifest_on(left, leftconnection_with_firewalld, catch_changes: true)
            apply_manifest_on(right, rightconnection_with_firewalld, catch_changes: true)
          else
            apply_manifest_on(left, leftconnection_with_iptables, catch_failures: true)
            apply_manifest_on(right, rightconnection_with_iptables, catch_failures: true)
            apply_manifest_on(left, leftconnection_with_iptables, catch_changes: true)
            apply_manifest_on(right, rightconnection_with_iptables, catch_changes: true)
          end

          [left, right].flatten.each do |node|
            on node, 'ipsec status', acceptable_exit_codes: [0]
            if os_major_version == '8'
              on node, 'firewall-cmd --list-all', acceptable_exit_codes: [0] do
                expect(stdout).to match(%r{service\s+name="simp_ipsec_allow"\s+accept}m)
                expect(stdout).to match(%r{protocol\s+value="esp"\s+accept}m)
                expect(stdout).to match(%r{protocol\s+value="ah"\s+accept}m)
              end
            else
              on node, 'iptables --list -v', acceptable_exit_codes: [0] do
                expect(stdout).to match(%r{ACCEPT\s+udp\s+--\s+any\s+any\s+#{client_net}\s+anywhere\s+state NEW multiport dports ipsec-nat-t,isakmp}m)
                expect(stdout).to match(%r{ACCEPT\s+esp}m)
                expect(stdout).to match(%r{ACCEPT\s+ah}m)
              end
            end
          end
        end

        it "allows data carried by connection's tunnel" do
          wait_for_command_success(left,  'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 1"')
          wait_for_command_success(right, 'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 1"')

          # send TCP data from right to left
          on left, "/usr/bin/screen -dm bash -c '#{nc} -l #{nc_port} > #{testfile}'", acceptable_exit_codes: [0]
          sleep(2)
          on right, "echo 'this is a test of a tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ", acceptable_exit_codes: [0]

          # verify data does reach left
          on left, "cat #{testfile}", acceptable_exit_codes: [0] do
            expect(stdout).to match(%r{this is a test of a tunnel with firewall enabled})
          end

          # verify iptables packet counts for esp and nc (over tcp) traffic have incremented
          on left, 'iptables --list -v' do
            expect(stdout).to match(%r{^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+esp}m)
            expect(stdout).to match(%r{^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+tcp}m)
          end
        end
      end

      context 'when tunnel goes down with firewall protection' do
        it 'detects disabled tunnel' do
          on left, 'puppet resource service ipsec ensure=stopped', acceptable_exit_codes: [0]
          wait_for_command_success(left, "ipsec status |& grep 'Pluto is not running'")

          # can take up to 2 minutes for right to timeout tunnel,
          # so restart instead to detect
          # failure immediately
          wait_for_command_success(right, 'ipsec status | egrep "Total IPsec connections: loaded [1-9]+[0-9]*, active 0"')
          wait_for_command_success(right, "ip xfrm policy | grep 'mode transport'")
        end

        it 'drops data because of broken tunnel' do
          # try to send TCP data from right to left
          on left, "/usr/bin/screen -dm bash -c '#{nc} -l #{nc_port} > #{testfile}'", acceptable_exit_codes: [0]
          sleep(2)
          on right, "echo 'this is a test of a downed tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ",
            acceptable_exit_codes: [1]

          # verify data does NOT reach left
          on left, "cat #{testfile}", acceptable_exit_codes: [0] do
            expect(stdout).not_to match(%r{this is a test of a downed tunnel with firewall enabled})
          end
          on left, "pkill -f '#{nc} -l #{nc_port}'", acceptable_exit_codes: [0]
        end
      end
    end
    # TODO: ipv6 tests
  end
end
