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
      context 'when tunnel goes down with firewall protection' do
        it 'should detect disabled tunnel' do
          on left, 'puppet resource service ipsec ensure=stopped', :acceptable_exit_codes => [0]
          wait_for_command_success(left, "ipsec status |& grep 'Pluto is not running'")

          # can take up to 2 minutes for right to timeout tunnel,
          # so restart instead to detect
          # failure immediately
          wait_for_command_success(right, "ipsec status | egrep \"Total IPsec connections: loaded [1-9]+[0-9]*, active 0\"")
          wait_for_command_success(right, "ip xfrm policy | grep 'mode transport'")
        end

        it "should drop data because of broken tunnel" do
          # try to send TCP data from right to left
          on left, "#{nc} -l #{nc_port} > #{testfile} &", :acceptable_exit_codes => [0]
          sleep(2)
          on right, "echo 'this is a test of a downed tunnel with firewall enabled' | #{nc} -s #{rightip} #{left} #{nc_port} ",
            :acceptable_exit_codes => [1]

          # verify data does NOT reach left
          on left, "cat #{testfile}", :acceptable_exit_codes => [0] do
            expect(stdout).to_not match(/this is a test of a downed tunnel with firewall enabled/)
          end
          on left, "pkill -f '#{nc} -l #{nc_port}'", :acceptable_exit_codes => [0]
        end
      end
    end
  end
end
