require 'spec_helper'
top_comment = <<EOM
# /etc/ipsec.conf - Libreswan IPsec configuration file
#
# This file is controlled by puppet.  Changes should be done through hiera.
#
# This file holds only the config setup section of ipsec.conf.
# Connection information should be placed in seperate files in the directory
# defined by libreswan::ipsecdir (default /etc/ipsec.d)
# There is information on the possible values in the manual page, "man ipsec.conf"
# or at https://libreswan.org
#
EOM

logfile_comment = <<EOM
  # Normally, pluto logs via syslog. If you want to log to a file,
  # specify below or to disable logging, eg for embedded systems, use
  # the file name /dev/null
  # Note: SElinux policies might prevent pluto writing to a log file at
  #       an unusual location.
EOM

plutodebug_comment = <<EOM
  # Do not enable debug options to debug configuration issues!
  # plutodebug "all", "none" or a combination from below:
  # "raw crypt parsing emitting control controlmore kernel pfkey
  #  natt x509 dpd dns oppo oppoinfo private".
  # Note: "private" is not included with "all", as it can show confidential
  #       information. It must be specifically specified
  # examples:
  # plutodebug="control parsing"
  # plutodebug="all crypt"
  # Again: only enable plutodebug when asked by a developer
EOM

dump_dir_comment = <<EOM
  # Enable core dumps (might require system changes, like ulimit -C)
  # This is required for abrtd to work properly
  # Note: SElinux policies might prevent pluto writing the core at
  #       unusual locations
EOM

protostack_comment = <<EOM
  # which IPsec stack to use, "netkey" (the default), "klips" or "mast".
  # For MacOSX use "bsd"
EOM

virtual_private_comment = <<EOM
  #
  # NAT-TRAVERSAL support
  # exclude networks used on server side by adding %v4:!a.b.c.0/24
  # It seems that T-Mobile in the US and Rogers/Fido in Canada are
  # using 25/8 as "private" address space on their wireless networks.
  # This range has never been announced via BGP (at least upto 2015)
  #	virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:25.0.0.0/8,%v4:100.64.0.0/10,%v6:fd00::/8,%v6:fe80::/10
EOM

include_comment = <<EOM
#
# You must add your IPsec connections as separate files in the ipsecdir
#  (defined above (default /etc/ipsec.d/ )
EOM

ipsec_conf_content = {
  default:     top_comment +
               "config setup\n" \
               "  ipsecdir = /etc/ipsec.d\n" +
               plutodebug_comment +
               "  plutodebug = none\n" +
               logfile_comment +
               "  #logfile=/var/log/pluto.log\n" +
               dump_dir_comment +
               "  dumpdir = /var/run/pluto\n" \
               "  secretsfile = /etc/ipsec.secrets\n" +
               protostack_comment +
               "  protostack = netkey\n" +
               virtual_private_comment +
               "  virtual-private = %v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12\n" +
               include_comment +
               "include /etc/ipsec.d/*.conf\n",

  # This content is NOT a valid ipsec configuration, but simply a
  # configuration that exercises parameter processing code.
  fully_specified:     top_comment +
                       "config setup\n" \
                       "  ipsecdir = /etc/myipsec.d\n" \
                       "  myid = @myid\n" \
                       "  interfaces = \"ipsec0=eth0 ipsec1=ppp0\"\n" \
                       "  listen = 1.2.3.4\n" \
                       "  nflog-all = 10\n" \
                       "  keep-alive = 10\n" \
                       "  myvendorid = my-vendor-id\n" \
                       "  nhelpers = -1\n" \
                       "  plutofork = no\n" \
                       "  crlcheckinterval = 60\n" \
                       "  strictcrlpolicy = yes\n" \
                       "  ocsp-enable = yes\n" \
                       "  ocsp-strict = yes\n" \
                       "  ocsp-timeout = 4\n" \
                       "  ocsp-uri = https://myuri\n" \
                       "  ocsp-trustname = my-trustname\n" \
                       "  syslog = daemon.warning\n" +
                       plutodebug_comment +
                       "  plutodebug = all\n" \
                       "  uniqueids = no\n" \
                       "  plutorestartoncrash = no\n" +
                       logfile_comment +
                       "  logfile = /var/log/ipsec.log\n" \
                       "  logappend = no\n" \
                       "  logtime = no\n" \
                       "  ddos-mode = busy\n" \
                       "  ddos-ike-treshold = 26000\n" +
                       dump_dir_comment +
                       "  dumpdir = /var/run/ipsec\n" \
                       "  statsbin = \"/some/external/reporter -p 266\"\n" \
                       "  secretsfile = /etc/myipsec.secrets\n" \
                       "  fragicmp = yes\n" \
                       "  hidetos = no\n" \
                       "  overridemtu = 1500\n" +
                       protostack_comment +
                       "  protostack = klips\n" +
                       virtual_private_comment +
                       "  virtual-private = %v4:1.2.3.0/24,%v6:fe80::/10,%v4:!5.6.0.0/16,%v6:!fd80::/10\n" +
                       include_comment +
                       "include /etc/myipsec.d/*.conf\n"
}

shared_examples_for 'a libreswan ipsec config file generator' do
  it { is_expected.to compile.with_all_deps }
  it {
    is_expected.to contain_file('/etc/ipsec.conf')
      .with_owner('root')
      .with_mode('0400')
      .with_content(ipsec_conf_content[title])
      .that_notifies('Class[libreswan::service]')
  }

  it {
    is_expected.to contain_file(dumpdir).with(
    {
      ensure: :directory,
      owner: 'root',
      mode: '0700',
      before: 'File[/etc/ipsec.conf]'
    },
  )
  }
end

describe 'libreswan::config' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context 'with default parameters' do
          let(:pre_condition) { 'class { "libreswan": service_name => "ipsec",}' }
          let(:title) { :default }
          let(:dumpdir) { '/var/run/pluto' }

          it_behaves_like 'a libreswan ipsec config file generator'
        end

        context 'with fully-specified parameters' do
          let(:title) { :fully_specified }
          let(:dumpdir) { '/var/run/ipsec' }
          let(:pre_condition) do
            <<-EOM
class { "libreswan":
  service_name        => "ipsec",
  myid                => '@myid',
  protostack          => 'klips',
  interfaces          => ['ipsec0=eth0','ipsec1=ppp0'],
  listen              => '1.2.3.4',
  ikeport             => 600,
  nflog_all           => 10,
  nat_ikeport         => 4600,
  keep_alive          => 10,
  virtual_private     => ['%v4:1.2.3.0/24', '%v6:fe80::/10', '%v4:!5.6.0.0/16', '%v6:!fd80::/10'],
  myvendorid          => 'my-vendor-id',
  nhelpers            => -1,
  #seedbits
  #secctx-attr-type
  plutofork           => 'no',
  crlcheckinterval    => 60,
  strictcrlpolicy     => 'yes',
  ocsp_enable         => 'yes',
  ocsp_strict         => 'yes',
  ocsp_timeout        => 4,
  ocsp_uri            => 'https://myuri',
  ocsp_trustname      => 'my-trustname',
  syslog              => 'daemon.warning',
  klipsdebug          => 'all',
  plutodebug          => 'all',
  uniqueids           => 'no',
  plutorestartoncrash => 'no',
  logfile             => '/var/log/ipsec.log',
  logappend           => 'no',
  logtime             => 'no',
  ddos_mode           => 'busy',
  ddos_ike_treshold   => 26000,
  #max-halfopen-ike
  #shuntlifetime
  #xfrmlifetime
  dumpdir             => '/var/run/ipsec',
  statsbin            => '/some/external/reporter -p 266',
  ipsecdir            => '/etc/myipsec.d',
  secretsfile         => '/etc/myipsec.secrets',
  perpeerlog          => 'yes',
  perpeerlogdir       => '/var/log/ipsec/peer',
  fragicmp            => 'yes',
  hidetos             => 'no',
  overridemtu         => 1500,
}
EOM
          end

          it_behaves_like 'a libreswan ipsec config file generator'
          it {
            is_expected.to contain_file('/var/log/ipsec.log').with(
            {
              owner: 'root',
              mode: '0600',
              before: 'File[/etc/ipsec.conf]'
            },
          )
          }
        end
      end
    end
  end
end
