# Module 'libreswan' installs and configures libreswan to provide IPsec
# tunnels. It is very important you read the documentation that comes with
# libreswan before attempting to use this module.
#
# https://libreswan.org
#
# At this time the current version of libreswan is 3.1.7.
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
#   the simp global catalysts for more details.
#
# @param service_name  The name of the ipsec service.
#
# @param package_name  The name of the libreswan package.
#
# @param trusted_nets  A whitelist of subnetworks (in CIDR notataion) with
# permitted acccess explicitly for ipsec communication
#
# @param firewall  Whether to add appropriate rules to
#  allow ipsec traffic to the SIMP-controlled firewall
#
# @param fips  Whether server is in FIPS mode.  Affects digest algorithms
# allowed to be used by ipsec.
#
# @param use_certs  Wether you are going to use certificates for
#     ipsec.  Default true.  If set to false, the pki management is
#     skipped completely.
#
# @param pki   SIMP PKI option.
#   If 'simp' then use  SIMP's PKI infrastructure to manage certificates used by ipsec.
#   If true then it will copy certs from app_pki_external_source to app_pki_dir
#     when puppet runs and restart the necessary services.  See pki::copy to
#     see the structure required for the source directory.
#   If false you must set variables
#     libreswan::config::pki::app_pki_ca
#     libreswan::config::pki::app_pki_cert
#     libreswab::config::pki::app_pki_key
#     (or put your keys in the defaut location)
#     you will need to manualy restart services to pick up the new certs.
#
# @param haveged  Whether to use haveged to ensure adequate entropy
#
# @param nssdb_password  Password for the NSS database used by ipsec
#
# @param app_pki_dir
# @param app_pki_external_source
# @param myid
# @param protostack
# @param interfaces
# @param listen
# @param ikeport
# @param nflog_all
# @param nat_ikeport
# @param keep_alive
# @param virtual_private
# @param myvendorid
# @param nhelpers
# @param plutofork
# @param crlcheckinterval
# @param strictcrlpolicy
# @param ocsp_enable
# @param ocsp_strict
# @param ocsp_timeout
# @param ocsp_uri
# @param ocsp_trustname
# @param syslog
# @param klipsdebug
# @param plutodebug
# @param uniqueids
# @param plutorestartoncrash
# @param logfile
# @param logappend
# @param logtime
# @param ddos_mode
# @param ddos_ike_treshold
# @param dumpdir
# @param statsbin
#
# @param ipsecdir  The directory to store all ipsec configuration information.
#
# @param secretsfile
# @param perpeerlog
# @param perpeerlogdir
# @param fragicmp
# @param hidetos
# @param overridemtu
#
# * See the libreswan doumentation https://libreswan.org/man/ipsec.conf.5.html
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
  String                          $service_name            = $::libreswan::params::service_name,
  String                          $package_name            = $::libreswan::params::package_name,
  Simplib::Netlist                $trusted_nets            = simplib::lookup('simp_options::trusted_nets', {'default_value' => ['127.0.0.1/32'] }),
  Boolean                         $firewall                = simplib::lookup('simp_options::firewall', {'default_value' => false }),
  Boolean                         $fips                    = simplib::lookup('simp_options::fips', {'default_value' => false }),
  Boolean                         $use_certs               = true,
  Variant[Boolean,Enum['simp']]   $pki                     = simplib::lookup('simp_options::pki', {'default_value' => false }),
  Boolean                         $haveged                 = simplib::lookup('simp_options::haveged', {'default_value' => false }),
  String                          $nssdb_password          = passgen('nssdb_password'),
  Stdlib::Absolutepath            $app_pki_dir             = '/etc/pki/ipsec',
  Stdlib::Absolutepath            $app_pki_external_source =  simplib::lookup('simp_options::pki::source', {'default_value' => '/etc/pki/simp' }),
  # Possible Values in ipsec.conf file
  Optional[String]                $myid                    = undef,
  Enum['netkey','klips','mast']   $protostack              = 'netkey',
  Optional[Libreswan::Interfaces] $interfaces              = undef,
  Optional[Simplib::IP]           $listen                  = undef,
  Simplib::Port                   $ikeport                 = 500,
  Optional[Integer]               $nflog_all               = undef,
  Simplib::Port                   $nat_ikeport             = 4500,
  Optional[Integer]               $keep_alive              = undef,
#
  Libreswan::VirtualPrivate       $virtual_private         = ['%v4:10.0.0.0/8','%v4:192.168.0.0/16','%v4:172.16.0.0/12'],
  Optional[String]                $myvendorid              = undef,
  Optional[Integer]               $nhelpers                = undef,
#seedbits
#secctx-attr-type
  Optional[Enum['yes','no']]      $plutofork               = undef,
  Optional[Integer]               $crlcheckinterval        = undef,
  Optional[Enum['yes','no']]      $strictcrlpolicy         = undef,
  Optional[Enum['yes','no']]      $ocsp_enable             = undef,
  Optional[Enum['yes','no']]      $ocsp_strict             = undef,
  Optional[Integer]               $ocsp_timeout            = undef,
  Optional[Simplib::Uri]          $ocsp_uri                = undef,
  Optional[String]                $ocsp_trustname          = undef,
  Optional[String]                $syslog                  = undef,
  String                          $klipsdebug              = 'none',
  String                          $plutodebug              = 'none',
  Optional[Enum['yes','no']]      $uniqueids               = undef,
  Optional[Enum['yes','no']]      $plutorestartoncrash     = undef,
  Optional[Stdlib::Absolutepath]  $logfile                 = undef,
  Optional[Enum['yes','no']]      $logappend               = undef,
  Optional[Enum['yes','no']]      $logtime                 = undef,
  Optional[Enum['busy',
    'unlimited','auto']]          $ddos_mode               = undef,
  Optional[Integer]               $ddos_ike_treshold       = undef,  # incorrect spelling in libreswan 3.1.5 source code verified
#max-halfopen-ike
#shuntlifetime
#xfrmlifetime
  Stdlib::Absolutepath            $dumpdir                 = '/var/run/pluto',
  Optional[String]                $statsbin                = undef,
  Stdlib::Absolutepath            $ipsecdir                = '/etc/ipsec.d',
  Stdlib::Absolutepath            $secretsfile             = '/etc/ipsec.secrets',
  Optional[Enum['yes','no']]      $perpeerlog              = undef,
  Stdlib::Absolutepath            $perpeerlogdir           = '/var/log/pluto/peer',
  Optional[Enum['yes','no']]      $fragicmp                = undef,
  Optional[Enum['yes','no']]      $hidetos                 = undef,
  Optional[Integer]               $overridemtu             = undef,

) inherits ::libreswan::params {

  # set the token for the NSS database.
  if $fips {
    $token = 'NSS FIPS 140-2 Certificate DB' }
  else {
    $token = 'NSS Certificate DB'
  }

  if $haveged {
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

  if $firewall {
    include '::libreswan::config::firewall'
    Class[ '::libreswan::config::firewall' ] ~>
    Class[ '::libreswan::service'  ]
  }

  if $use_certs {
    include '::libreswan::config::pki'
    include '::libreswan::config::pki::nsspki'
    Class[ '::libreswan::config::pki' ] ~>
    Class[ '::libreswan::config::pki::nsspki' ]
  }
}
