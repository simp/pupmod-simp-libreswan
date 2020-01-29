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
    end
  end
end
