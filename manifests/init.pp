# Module 'libreswan' installs and configures libreswan for use with IPSEC
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
# To add and start tunnels that will be managed by the ipsec service see the module
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
#   the +client_nets+ and +$enable_*+ parameters for details.
#
#
# @param service_name [String] The name of the ipsec service.
#
# @param package_name [String] The name of the libreswan package.
#
# @param client_nets [Array] A whitelist of subnets (in CIDR notation) permitted access.
#
# @param simp_firewall [Boolean] If true, manage firewall rules to acommodate ipsec.
#
# @param enable_pki [Boolean] If true, manage PKI/PKE configuration for ipsec.
#
# @param use_fips [Boolean] If true, configure the system to be FIPS compliant.
#
# @param use_simp_pki [Boolean] If true, manage manage the pki certificates for this system.
#
# @param certsource [AbsolutePath] Used if use_simp_pki is true to copy certs locally for ipsec.
#
# @param nsspassword [String]Password used for IPSEC NSS database.
#
# @param ipsecdir [AbsolutePath] The directory to store all IPSEC configuration information.
#
# The other parameters are all setting for the ipsec.conf file. See the
# Libreswan doumentation https://libreswan.org/man/ipsec.conf.5.html
# for more information reguarding these variables.
# Any variable set to undefined will not appear in the configuration
# file and will default to the value set by Libreswan. Those set will
# appear in the configuration file but can be over written using the
# hiera yaml files.
#
# @param ikeport [Undef]
# @param nat_ikeport [Undef]
# @param keep_alive [Undef]
# @param virtual_private [Undef]
# @param myvendorid [Undef]
# @param nhelpers [Undef]
# @param plutofork [Undef]
# @param crlcheckinterval [Undef]
# @param strictcrlpolicy [Undef]
# @param syslog [Undef]
# @param klipsdebug [Undef]
# @param plutodebug [Undef]
# @param uniqueids [Undef]
# @param plutorestartoncrash [Undef]
# @param plutostderrlog [Undef]
# @param plutostderrlogtime [Undef]
# @param force_busy [Undef]
# @param dumpdir [Undef]
# @param statsbin [Undef]
# @param secretsfile [Undef]
# @param perpeerlog [Undef]
# @param perpeerlogdir [Undef]
# @param fragicmp [Undef]
# @param hidetos [Undef]
# @param overridemtu [Undef]
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
  # Possible Values in ipsec.conf file
  $myid                = undef,
  $protostack          = 'netkey',
  $interfaces          = undef,
  $listen              = undef,
  $ikeport             = '500',
  $nat_ikeport         = '4500',
  $keep_alive          = undef,
  $retransmits         = 'yes',
  $virtual_private     = ['10.0.0.0/8','192.168.0.0/16','172.16.0.0/12'],
  $myvendorid          = undef,
  $nhelpers            = undef,
  $plutofork           = undef,
  $crlcheckinterval    = undef,
  $strictcrlpolicy     = undef,
  $syslog              = undef,
  $klipsdebug          = 'none',
  $plutodebug          = 'none',
  $uniqueids           = undef,
  $plutorestartoncrash = undef,
  $plutostderrlog      = undef,
  $plutostderrlogtime  = undef,
  $force_busy          = undef,
  $dumpdir             = '/var/run/pluto',
  $statsbin            = undef,
  $ipsecdir            = '/etc/ipsec.d',
  $secretsfile         = '/etc/ipsec.secrets',
  $perpeerlog          = undef,
  $perpeerlogdir       = '/var/log/pluto/peer',
  $fragicmp            = undef,
  $hidetos             = undef,
  $overridemtu         = undef,
  $ipsec_client_nets   = ['127.0.0.1/32'],
  # Other Variables
  $certsource          = '/etc/pki/ipsec',
  $pkiroot             = '/etc/pki',

) inherits ::libreswan::params {

  validate_string( $service_name )
  validate_string( $package_name )
  validate_array( $client_nets )
  validate_array( $ipsec_client_nets )
  validate_bool( $simp_firewall )
  validate_bool( $use_simp_pki )
  validate_bool( $use_fips )
  validate_bool( $use_haveged )
  # config setup section of ipsec.conf
  if $strictcrlpolicy {
    validate_re($strictcrlpolicy,
      '(yes|no)$',
      "${strictcrlpolicy} is not supported for strictcrlpolicy")
  }
  if $force_busy {
    validate_re($force_busy,
      '(yes|no)$',
      "${force_busy} is not supported for force_busy")
  }
  if $hidetos {
    validate_re($hidetos,
    '(yes|no)$',"${hidetos} is not supported for hidetos")
  }
  if $plutofork {
    validate_re($plutofork,
      '(yes|no)$',
      "${plutofork} is not supported for plutofork")
  }
  if $uniqueids {
    validate_re($uniqueids, '(yes|no)$', "${uniqueids} is not supported for uniqueids")
  }
  if $retransmits {
    validate_re($retransmits, '(yes|no)$', "${retransmits} is not supported for retransmits")
  }
  if $plutorestartoncrash {
    validate_re($plutorestartoncrash, '(yes|no)$', "${plutorestartoncrash} is not supported for plutorestartoncrash")
  }
  if $fragicmp {
    validate_re($fragicmp, '(yes|no)$', "${fragicmp} is not supported for fragicmp")
  }
  if $listen { validate_ipv4_address($listen) }
  if $perpeerlog {
    validate_re($perpeerlog, '(yes|no)$', "${perpeerlog} is not supported for perpeerlog")
  }
  if $nhelpers { validate_integer($nhelpers)}
  if $overridemtu { validate_integer($overridemtu)}
  if $keep_alive { validate_integer($keep_alive)}
  if $crlcheckinterval { validate_integer($crlcheckinterval)}
  if $myvendorid { validate_string($myvendorid)}
  if $statsbin { validate_string($statsbin)}
  if $syslog { validate_string($syslog)}
  if $plutostderrlog { validate_absolute_path ($plutostderrlog) }
  validate_absolute_path($ipsecdir)
  validate_absolute_path($secretsfile)
  validate_absolute_path($dumpdir)
  validate_absolute_path($certsource)
  validate_absolute_path($pkiroot)
  validate_array_member($protostack,['netkey','klips','mast'])
  validate_integer($ikeport)
  validate_integer($nat_ikeport)
  validate_re($retransmits,'(yes|no)$',"${retransmits} invalid for retransmits")
  case $interfaces {
    undef           : {}
    '%none'         : {}
    '%defaultroute' : {}
    default         : {
      validate_re($interfaces,
        '((\w+=\w+)|(\%defaultroute))(\s+((\w+=\w+)|(\%defaultroute)))*',
        "${interfaces} is not supported")
    }
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
