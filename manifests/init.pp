# Module 'libreswan' installs and configures libreswan to provide IPsec
# tunnels. It is very important you read the documentation that comes with
# libreswan before attempting to use this module.
#
# https://libreswan.org
#
# At this time the current version of libreswan is 3.1.7.
#
#
# === Welcome to SIMP!
# This module is a component of the System Integrity Management Platform, a
# a managed security compliance framework built on Puppet.
#
# ---
# libreswan is designed to install and configure the ipsec service from libreswan.
# It will also configure and maintain the NSS database used by ipsec if you have
# chosen to let simp manage your PKI certificates.
#
# To add and start tunnels that will be managed by the ipsec service see the manifest
# libreswan::add_connection.
# ---
#
# This module is optimally designed for use within a larger SIMP ecosystem, but
# it can be used independently:
#
# * When included within the SIMP ecosystem,
#   security compliance settings will be managed from the Puppet server.
#
# * If used independently, all SIMP-managed security subsystems are disabled by
#   default, and must be explicitly opted into by administrators. Please review
#   the +client_nets+, +simp_firewall+, +nssdb_password+, and +$use_*+
#   parameters for details.
#
#
# @param service_name [String] The name of the ipsec service.
#
# @param package_name [String] The name of the libreswan package.
#
# @param client_nets [Array] A whitelist of subnetworks (in CIDR notataion) with
# permitted acccess explicitly for ipsec communication
#
# @param simp_firewall [Boolean] Whether to add appropriate rules to
#  allow ipsec traffic to the SIMP-controlled firewall
#
# @param use_simp_pki [Boolean] Whether to use SIMP's PKI infrastructure to
#  manage certificates used by ipsec
#
# @param use_fips [Boolean] Whether server is in FIPS mode.  Affects digest algorithms
# allowed to be used by ipsec.
#
# @param use_haveged [Boolean] Whether to use haveged to ensure adequate entropy
#
# @param nssdb_password [String] Password for the NSS database used by ipsec
#
# @param certsource [AbsolutePath] Used if use_simp_pki is true to copy certs locally for ipsec.
#
# @param ipsecdir [AbsolutePath] The directory to store all ipsec configuration information.
#
# The other parameters are all setting for the ipsec.conf file. See the
# libreswan doumentation https://libreswan.org/man/ipsec.conf.5.html
# for more information regarding these variables.
# Any variable set to undefined will not appear in the configuration
# file and will default to the value set by libreswan. Those set will
# appear in the configuration file but can be over written using the
# hiera yaml files.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Jeanne Greulich <jeanne.greulich@onyxpoint.com>
#
class libreswan (
  $service_name        = $::libreswan::params::service_name,
  $package_name        = $::libreswan::params::package_name,
  $client_nets         = defined('$::client_nets') ? { true => getvar('::client_nets'), default => hiera('client_nets', ['127.0.0.1/32']) },
  $simp_firewall       = defined('$::simp_firewall') ? { true => getvar('::simp_firewall'), default => hiera('simp_firewall',false) },
  $use_fips            = defined('$::use_fips') ? { true => getvar('::use_fips'), default => hiera('use_fips',false) },
  $use_simp_pki        = defined('$::use_simp_pki') ? { true  => getvar('::use_simp_pki'), default => hiera('use_simp_pki',false) },
  $use_haveged         = defined('$::use_haveged') ? { true => getvar('::use_haveged'), default => hiera('use_haveged',true) },
  $nssdb_password      = passgen('nssdb_password'),
  $certsource          = '/etc/pki/ipsec',
  $pkiroot             = '/etc/pki',
  # Possible Values in ipsec.conf file
  $myid                = undef,
  $protostack          = 'netkey',
  $interfaces          = undef,
  $listen              = undef,
  $ikeport             = '500',
  $nflog_all           = undef,
  $nat_ikeport         = '4500',
  $keep_alive          = undef,
  $virtual_private     = ['10.0.0.0/8','192.168.0.0/16','172.16.0.0/12'],
  $myvendorid          = undef,
  $nhelpers            = undef,
#seedbits
#secctx-attr-type
  $plutofork           = undef,
  $crlcheckinterval    = undef,
  $strictcrlpolicy     = undef,
  $ocsp_enable         = undef,
  $ocsp_strict         = undef,
  $ocsp_timeout        = undef,
  $ocsp_uri            = undef,
  $ocsp_trustname      = undef,
  $syslog              = undef,
  $klipsdebug          = 'none',
  $plutodebug          = 'none',
  $uniqueids           = undef,
  $plutorestartoncrash = undef,
  $logfile             = undef,
  $logappend           = undef,
  $logtime             = undef,
  $ddos_mode           = undef,
  $ddos_ike_treshold   = undef,  # incorrect spelling in libreswan 3.1.5 source code verified
#max-halfopen-ike
#shuntlifetime
#xfrmlifetime
  $dumpdir             = '/var/run/pluto',
  $statsbin            = undef,
  $ipsecdir            = '/etc/ipsec.d',
  $secretsfile         = '/etc/ipsec.secrets',
  $perpeerlog          = undef,
  $perpeerlogdir       = '/var/log/pluto/peer',
  $fragicmp            = undef,
  $hidetos             = undef,
  $overridemtu         = undef,

) inherits ::libreswan::params {

  # TODO validate these in the same order they appear in the parameter
  # list
  validate_string( $service_name )
  validate_string( $package_name )
  validate_array( $client_nets )
  validate_net_list( $client_nets )
  validate_bool( $simp_firewall )
  validate_bool( $use_simp_pki )
  validate_bool( $use_fips )
  validate_bool( $use_haveged )
  # config setup section of ipsec.conf
  if $myid { validate_string($myid)}
  if $strictcrlpolicy { libreswan_validate_yesno($strictcrlpolicy) }
  if $hidetos { libreswan_validate_yesno($hidetos) }
  if $plutofork { libreswan_validate_yesno($plutofork) }
  if $uniqueids { libreswan_validate_yesno($uniqueids) }

  #TODO validate list which can contain IP addresses prefixed by "!".  Right
  # now validation is done in template that uses this variable
  validate_array($virtual_private)
  if $plutorestartoncrash { libreswan_validate_yesno($plutorestartoncrash) }
  if $fragicmp { libreswan_validate_yesno($fragicmp) }
  if $listen {
    # This should be a single IPv4 or IPv6 address
    # TODO reject CIDR addresses
    validate_string($listen)
    validate_net_list($listen)
  }
  if $perpeerlog { libreswan_validate_yesno($perpeerlog) }
  validate_absolute_path($perpeerlogdir)
  if $nhelpers { validate_integer($nhelpers)}
  if $overridemtu { validate_integer($overridemtu)}
  if $keep_alive { validate_integer($keep_alive)}
  if $crlcheckinterval { validate_integer($crlcheckinterval)}
  if $myvendorid { validate_string($myvendorid)}
  if $statsbin { validate_string($statsbin)}
  if $ocsp_enable { libreswan_validate_yesno($ocsp_enable) }
  if $ocsp_strict { libreswan_validate_yesno($ocsp_strict) }
  if $ocsp_timeout { validate_integer($ocsp_timeout) }
  if $ocsp_uri {
    validate_string($ocsp_uri) # must be single URI
    validate_uri_list($ocsp_uri)
  }
  if $ocsp_trustname{ validate_string($ocsp_trustname) }

  #TODO build validator for <facility>.<level>
  if $syslog { validate_string($syslog)}

  validate_string($klipsdebug)
  validate_string($plutodebug)
  if $logfile { validate_absolute_path ($logfile) }
  if $logappend { libreswan_validate_yesno($logappend) }
  if $logtime { libreswan_validate_yesno($logtime) }
  if $ddos_mode { validate_array_member($ddos_mode,['busy','unlimited','auto']) }
  if $ddos_ike_treshold { validate_integer($ddos_ike_treshold) }
  validate_absolute_path($ipsecdir)
  validate_absolute_path($secretsfile)
  validate_absolute_path($dumpdir)
  validate_absolute_path($certsource)
  validate_absolute_path($pkiroot)
  validate_array_member($protostack,['netkey','klips','mast'])
  validate_integer($ikeport)
  if $nflog_all { validate_integer($nflog_all) }
  validate_integer($nat_ikeport)

  if $interfaces {
    validate_array($interfaces)
    validate_re_array($interfaces,['^%none$', '^%defaultroute$', '(\w+=\w+)'])
  }
  # set the token for the NSS database.
  if $::libreswan::use_fips {
    $token = 'NSS FIPS 140-2 Certificate DB' }
  else {
    $token = 'NSS Certificate DB'
  }

  if $::libreswan::use_haveged {
    include '::haveged'
  }

  $nsspassword = "${ipsecdir}/nsspassword"

  include '::libreswan::install'
  include '::libreswan::config'
  include '::libreswan::service'
  Class[ '::libreswan::install' ] ->
  Class[ '::libreswan::config'  ] ~>
  Class[ '::libreswan::service' ]->
  Class[ '::libreswan' ]

  if $simp_firewall {
    include '::libreswan::config::firewall'
    Class[ '::libreswan::config::firewall' ] ~>
    Class[ '::libreswan::service'  ]
  }

  if $use_simp_pki {
    include '::libreswan::config::pki'
    include '::libreswan::config::pki::nsspki'
    Class[ '::libreswan::config::pki' ] ~>
    Class[ '::libreswan::config::pki::nsspki' ]
  }
}
