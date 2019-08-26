# Module 'libreswan' installs and configures libreswan to provide IPsec
# tunnels. It is very important you read the documentation that comes with
# libreswan before attempting to use this module.
#
# https://libreswan.org
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
# @param pki
#   * If 'simp', include SIMP's pki module and use pki::copy to manage
#     application certs in /etc/pki/simp_apps/libreswan/x509
#   * If true, do *not* include SIMP's pki module, but still use pki::copy
#     to manage certs in /etc/pki/simp_apps/libreswan/x509
#   * If false, do not include SIMP's pki module and do not use pki::copy
#     to manage certs.  You will need to appropriately assign a subset of:
#     * app_pki_dir
#     * app_pki_key
#     * app_pki_cert
#     * app_pki_ca
#     * app_pki_ca_dir
#
# @param haveged  Whether to use haveged to ensure adequate entropy
#
# @param nssdb_password  Password for the NSS database used by ipsec
#
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
# @param block_cidrs List of CIDRs to which communication should never be allowed
# @param clear_cidrs List of CIDRs to which communication should always be in the clear
# @param clear_private_cidrs List of CIDRs to which communication will be in the clear, or, if the other side initiates IPSEC, use encryption
# @param private_cidrs List of CIDRs to which communication should always be private
# @param private_clear_cidrs List of CIDRs to which communication should be private if possible but in the clear otherwise
#
# * See the libreswan doumentation https://libreswan.org/man/ipsec.conf.5.html
# for more information regarding these variables.
# Any variable set to undefined will not appear in the configuration
# file and will default to the value set by libreswan. Those set will
# appear in the configuration file but can be over written using the
# hiera yaml files.
#
# @author https://github.com/simp/pupmod-simp-libreswan/graphs/contributors
#
class libreswan (
  String                                 $service_name            = $::libreswan::params::service_name,
  String                                 $package_name            = $::libreswan::params::package_name,
  Simplib::Netlist                       $trusted_nets            = simplib::lookup('simp_options::trusted_nets', {'default_value' => ['127.0.0.1/32'] }),
  Boolean                                $firewall                = simplib::lookup('simp_options::firewall', {'default_value' => false }),
  Boolean                                $fips                    = simplib::lookup('simp_options::fips', {'default_value' => false }),
  Boolean                                $use_certs               = true,
  Variant[Boolean,Enum['simp']]          $pki                     = simplib::lookup('simp_options::pki', {'default_value' => false }),
  Boolean                                $haveged                 = simplib::lookup('simp_options::haveged', {'default_value' => false }),
  String                                 $nssdb_password          = simplib::passgen('nssdb_password'),
  # Possible Values in ipsec.conf file
  Optional[String]                       $myid                    = undef,
  Enum['netkey','klips','mast']          $protostack              = 'netkey',
  Optional[Libreswan::Interfaces]        $interfaces              = undef,
  Optional[Simplib::IP]                  $listen                  = undef,
  Simplib::Port                          $ikeport                 = 500,
  Optional[Integer]                      $nflog_all               = undef,
  Simplib::Port                          $nat_ikeport             = 4500,
  Optional[Integer]                      $keep_alive              = undef,
#
  Libreswan::VirtualPrivate              $virtual_private         = ['%v4:10.0.0.0/8','%v4:192.168.0.0/16','%v4:172.16.0.0/12'],
  Optional[String]                       $myvendorid              = undef,
  Optional[Integer]                      $nhelpers                = undef,
#seedbits
#secctx-attr-type
  Optional[Enum['yes','no']]             $plutofork               = undef,
  Optional[Integer]                      $crlcheckinterval        = undef,
  Optional[Enum['yes','no']]             $strictcrlpolicy         = undef,
  Optional[Enum['yes','no']]             $ocsp_enable             = undef,
  Optional[Enum['yes','no']]             $ocsp_strict             = undef,
  Optional[Integer]                      $ocsp_timeout            = undef,
  Optional[Simplib::Uri]                 $ocsp_uri                = undef,
  Optional[String]                       $ocsp_trustname          = undef,
  Optional[String]                       $syslog                  = undef,
  String                                 $klipsdebug              = 'none',
  String                                 $plutodebug              = 'none',
  Optional[Enum['yes','no']]             $uniqueids               = undef,
  Optional[Enum['yes','no']]             $plutorestartoncrash     = undef,
  Optional[Stdlib::Absolutepath]         $logfile                 = undef,
  Optional[Enum['yes','no']]             $logappend               = undef,
  Optional[Enum['yes','no']]             $logtime                 = undef,
  Optional[Enum['busy',
    'unlimited','auto']]                 $ddos_mode               = undef,
  Optional[Integer]                      $ddos_ike_treshold       = undef,  # incorrect spelling in libreswan 3.1.5 source code verified
#max-halfopen-ike
#shuntlifetime
#xfrmlifetime
  Stdlib::Absolutepath                   $dumpdir                 = '/var/run/pluto',
  Optional[String]                       $statsbin                = undef,
  Stdlib::Absolutepath                   $ipsecdir                = '/etc/ipsec.d',
  Stdlib::Absolutepath                   $secretsfile             = '/etc/ipsec.secrets',
  Optional[Enum['yes','no']]             $perpeerlog              = undef,
  Stdlib::Absolutepath                   $perpeerlogdir           = '/var/log/pluto/peer',
  Optional[Enum['yes','no']]             $fragicmp                = undef,
  Optional[Enum['yes','no']]             $hidetos                 = undef,
  Optional[Integer]                      $overridemtu             = undef,
  Optional[Array[Simplib::IP::V4::CIDR]] $block_cidrs             = undef,
  Optional[Array[Simplib::IP::V4::CIDR]] $clear_cidrs             = undef,
  Optional[Array[Simplib::IP::V4::CIDR]] $clear_private_cidrs     = undef,
  Optional[Array[Simplib::IP::V4::CIDR]] $private_cidrs           = undef,
  Optional[Array[Simplib::IP::V4::CIDR]] $private_clear_cidrs     = ['0.0.0.0/0'],

) inherits ::libreswan::params {

  simplib::assert_metadata($module_name)

  # set the token for the NSS database.
  if $fips or $facts['fips_enabled'] {
    $token = 'NSS FIPS 140-2 Certificate DB' }
  else {
    $token = 'NSS Certificate DB'
  }

  if $haveged {
    include '::haveged'

    Class[ '::haveged' ] -> Class[ '::libreswan::service' ]
  }

  $nsspassword = "${ipsecdir}/nsspassword"

  contain '::libreswan::install'
  contain '::libreswan::config'
  contain '::libreswan::service'

  Class[ '::libreswan::install' ] -> Class[ '::libreswan::config'  ]
  Class[ '::libreswan::config'  ] ~> Class[ '::libreswan::service' ]

  if $firewall {
    contain '::libreswan::config::firewall'

    Class[ '::libreswan::config::firewall' ] ~> Class[ '::libreswan::service'  ]
  }

  if $pki {
    contain '::libreswan::config::pki'
    contain '::libreswan::config::pki::nsspki'

    Class[ '::libreswan::config::pki' ] ~> Class[ '::libreswan::config::pki::nsspki' ]
    Class[ '::libreswan::config::pki::nsspki' ] ~> Class[ '::libreswan::service' ]
  }
}
