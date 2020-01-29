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
