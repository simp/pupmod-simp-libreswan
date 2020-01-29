require 'spec_helper_acceptance'

require_relative('include/common_methods')

test_name 'libreswan class'

['6', '7'].each do |os_version|
  describe "libreswan class for EL #{os_version}" do
    require_relative('include/common_let_statements')
    include_context('shared let', :include_shared => true) do
      let(:os_major_version) { os_version }
    end

    context 'tunnel using certs' do
      context 'when connection with firewall' do
        let(:client_net) {
          quads = leftip.split('.')  # doesn't matter if use left or right ip
          quads[2] = '0'
          quads[3] = '0'
          quads.join('.') + '/16'
        }
        let(:hieradata_with_firewall_left)  {
          hieradata_left +
          "simp_options::firewall: yes\n" +
          "simp_options::trusted_nets : ['#{client_net}']\n"
        }
        let(:hieradata_with_firewall_right) {
          hieradata_right +
          "simp_options::firewall: yes\n" +
          "simp_options::trusted_nets : ['#{client_net}']\n"
        }
        let(:leftconnection_with_firewall) { leftconnection +
          "      class { 'iptables': }\n" +
          "      iptables::rule {'allow_public_network_interface':\n" +
          "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(left)} -j ACCEPT',\n" +
          "        apply_to => 'all',\n" +
          "        order => 11\n" +
          "      }\n" +
          "      iptables::rule {'allow_decrypted_nc_traffic':\n" +
          "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" +
          "        apply_to => 'all',\n" +
          "        order => 11\n" +
          "      }\n" +
          "      iptables::listen::tcp_stateful { 'allow_sshd':\n" +
          "        order => 8,\n" +
          "        trusted_nets => ['ALL'],\n" +
          "        dports => 22,\n" +
          "      }\n"
        }
        let(:rightconnection_with_firewall) { rightconnection +
          "      class { 'iptables': }\n" +
          "      iptables::rule {'allow_public_network_interface':\n" +
          "        content => '-A LOCAL-INPUT -i #{get_public_network_interface(right)} -j ACCEPT',\n" +
          "        apply_to => 'all',\n" +
          "        order => 11\n" +
          "      }\n" +
          "      iptables::rule {'allow_decrypted_nc_traffic':\n" +
          "        content => '-A LOCAL-INPUT -p tcp --dport #{nc_port} -j ACCEPT',\n" +
          "        apply_to => 'all',\n" +
          "        order => 11\n" +
          "      }\n" +
          "      iptables::listen::tcp_stateful { 'allow_sshd':\n" +
          "        order => 8,\n" +
          "        trusted_nets => ['ALL'],\n" +
          "        dports => 22,\n" +
          "      }\n"
        }

        it 'should apply manifest idempotently, restart ipsec service, start iptables with ipsec firewall' do
          set_hieradata_on(left, hieradata_with_firewall_left)
          set_hieradata_on(right,hieradata_with_firewall_right)

          # Apply ipsec and check for idempotency
          apply_manifest_on(left, leftconnection_with_firewall, :catch_failures => true)
          apply_manifest_on(right, rightconnection_with_firewall, :catch_failures => true)
          apply_manifest_on(left, leftconnection_with_firewall, :catch_changes => true)
          apply_manifest_on(right, rightconnection_with_firewall, :catch_changes => true)

          [left, right].flatten.each do |node|
            on node, "ipsec status", :acceptable_exit_codes => [0]
            on node, 'iptables --list -v', :acceptable_exit_codes => [0] do
              expect(stdout).to match(/ACCEPT\s+udp\s+--\s+any\s+any\s+#{client_net}\s+anywhere\s+state NEW multiport dports ipsec-nat-t,isakmp/m)
              expect(stdout).to match(/ACCEPT\s+esp/m)
              expect(stdout).to match(/ACCEPT\s+ah/m)
            end
          end
        end

        it "should allow data carried by connection's tunnel" do
          wait_for_command_success(left,  "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")
          wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 1\"")

          # send TCP data from right to left
          on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]
          sleep(2)
          on right, "echo 'this is a test of a tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ", :acceptable_exit_codes => [0]

          # verify data does reach left
          on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
            expect(stdout).to match(/this is a test of a tunnel with firewall enabled/)
          end

          # verify iptables packet counts for esp and nc (over tcp) traffic have incremented
          on left, 'iptables --list -v' do
            expect(stdout).to match(/^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+esp/m)
            expect(stdout).to match(/^(\s+[1-9]+[0-9]*\s+){2}ACCEPT\s+tcp/m)
          end
        end
      end
    end
  end
end
