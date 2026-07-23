# @summary Manage libreswan IPSEC settings without overwriting the config file or disrupting the service.
#
# A bare `include libreswan` installs the libreswan package and does nothing
# else. All configuration management, service management, firewall management,
# and PKI management are opt-in via class parameters.
#
# Configuration fields in `/etc/ipsec.conf` are managed in-place with
# `file_line` (one resource per field). Fields whose parameters are `undef`
# are not managed at all — the value in the package-provided file is left
# untouched. To remove a previously-managed field, pass its key in
# `purge_settings`. To remove a policy file in `${ipsecdir}/policies`, pass
# its name in `purge_policies`.
#
# See @link https://libreswan.org/man/ipsec.conf.5.html for the meaning of
# each ipsec.conf field.
#
# @param service_name
#   The name of the IPSEC service.
#
# @param package_name
#   The name of the libreswan package.
#
# @param service_ensure
#   `ensure` for the `ipsec` service. If `undef` (the default), the service
#   resource is not declared and the running state is not managed.
#
# @param service_enable
#   `enable` for the `ipsec` service. If `undef` (the default), the service
#   resource is not declared and the boot state is not managed.
#
# @param trusted_nets
#   Subnetworks (in CIDR notation) permitted to reach the IPSEC ports.
#   Only consumed when `firewall => true`.
#
# @param firewall
#   When `true`, declare firewall rules opening the IKE/NAT-T/ESP/AH paths.
#
# @param fips
#   Whether the IPSEC subsystem should be configured for FIPS mode. Only
#   consumed when `pki` is enabled.
#
# @param pki
#   * `'simp'`  — include `simp/pki` and copy certs into the app PKI dir.
#   * `true`    — do not include `simp/pki`, but still copy certs.
#   * `false`   — do not manage certs at all.
#
# @param haveged
#   When `true`, include `haveged` to provide entropy.
#
# @param nss_scripts
#   When `true`, install the NSS helper scripts under `/usr/local/scripts/nss/`.
#   These were always installed before 4.0.0. They are also pulled in
#   automatically by `libreswan::nss::init_db`, so most sites do not need to
#   set this directly.
#
# @param nssdb_password
#   Password used to protect the NSS database.
#
# @param ikeport
#   IKE port used in firewall rules. Not emitted to `ipsec.conf`.
#
# @param nat_ikeport
#   NAT-T port used in firewall rules. Not emitted to `ipsec.conf`.
#
# @param ipsecdir
#   Operational path to the IPSEC configuration directory. Used by the policy
#   files, PKI, and NSS code paths. Not emitted as a setting in `ipsec.conf`;
#   to override the in-file `ipsecdir =` line, manage it out-of-band.
#
# @param nssdir
#   Operational path to the directory where the NSS database used by
#   libreswan is stored. Used by the PKI and NSS code paths. Not emitted as a
#   setting in `ipsec.conf` — the module data matches each OS's package
#   default (libreswan >= 4 on EL9+ uses ``/var/lib/ipsec/nss``; EL8 builds
#   keep the legacy ``/etc/ipsec.d`` location).
#
# @param secretsfile
#   Operational path to the IPSEC secrets file. Used by the PKI code path.
#   Not emitted as a setting in `ipsec.conf`.
#
# @param purge_settings
#   Field names to remove from `/etc/ipsec.conf` if present.
#
# @param purge_policies
#   Policy file names (under `${ipsecdir}/policies`) to remove if present.
#
# @param myid
# @param protostack
# @param interfaces
# @param listen
# @param nflog_all
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
# @param fragicmp
# @param hidetos
# @param overridemtu
# @param block_cidrs
# @param clear_cidrs
# @param clear_private_cidrs
# @param private_cidrs
# @param private_clear_cidrs
#
# @author https://github.com/simp/pupmod-simp-libreswan/graphs/contributors
#
class libreswan (
  String[1]                                          $service_name,
  String[1]                                          $package_name,
  Optional[Enum['running','stopped']]                $service_ensure             = undef,
  Optional[Boolean]                                  $service_enable             = undef,
  Simplib::Netlist                                   $trusted_nets               = ['127.0.0.1/32'],
  Boolean                                            $firewall                   = false,
  Boolean                                            $fips                       = false,
  Variant[Boolean,Enum['simp']]                      $pki                        = false,
  Boolean                                            $haveged                    = false,
  Boolean                                            $nss_scripts                = false,
  String[1]                                          $nssdb_password             = simplib::passgen('nssdb_password'),
  Simplib::Port                                      $ikeport                    = 500,
  Simplib::Port                                      $nat_ikeport                = 4500,
  Stdlib::Absolutepath                               $ipsecdir                   = '/etc/ipsec.d',
  Stdlib::Absolutepath                               $nssdir,
  Stdlib::Absolutepath                               $secretsfile                = '/etc/ipsec.secrets',
  Array[String[1]]                                   $purge_settings             = [],
  Array[String[1]]                                   $purge_policies             = [],
  Optional[String[1]]                                $myid                       = undef,
  Optional[Enum['netkey','klips','mast']]            $protostack                 = undef,
  Optional[Libreswan::Interfaces]                    $interfaces                 = undef,
  Optional[Simplib::IP]                              $listen                     = undef,
  Optional[Integer]                                  $nflog_all                  = undef,
  Optional[Integer]                                  $keep_alive                 = undef,
  Optional[Libreswan::VirtualPrivate]                $virtual_private            = undef,
  Optional[String[1]]                                $myvendorid                 = undef,
  Optional[Integer]                                  $nhelpers                   = undef,
  Optional[Enum['yes','no']]                         $plutofork                  = undef,
  Optional[Integer]                                  $crlcheckinterval           = undef,
  Optional[Enum['yes','no']]                         $strictcrlpolicy            = undef,
  Optional[Enum['yes','no']]                         $ocsp_enable                = undef,
  Optional[Enum['yes','no']]                         $ocsp_strict                = undef,
  Optional[Integer]                                  $ocsp_timeout               = undef,
  Optional[Simplib::Uri]                             $ocsp_uri                   = undef,
  Optional[String[1]]                                $ocsp_trustname             = undef,
  Optional[String[1]]                                $syslog                     = undef,
  Optional[String[1]]                                $plutodebug                 = undef,
  Optional[Enum['yes','no']]                         $uniqueids                  = undef,
  Optional[Enum['yes','no']]                         $plutorestartoncrash        = undef,
  Optional[Stdlib::Absolutepath]                     $logfile                    = undef,
  Optional[Enum['yes','no']]                         $logappend                  = undef,
  Optional[Enum['yes','no']]                         $logtime                    = undef,
  Optional[Enum['busy','unlimited','auto']]          $ddos_mode                  = undef,
  Optional[Integer]                                  $ddos_ike_treshold          = undef,
  Optional[Stdlib::Absolutepath]                     $dumpdir                    = undef,
  Optional[String[1]]                                $statsbin                   = undef,
  Optional[Enum['yes','no']]                         $fragicmp                   = undef,
  Optional[Enum['yes','no']]                         $hidetos                    = undef,
  Optional[Integer]                                  $overridemtu                = undef,
  Optional[Array[Simplib::IP::V4::CIDR]]             $block_cidrs                = undef,
  Optional[Array[Simplib::IP::V4::CIDR]]             $clear_cidrs                = undef,
  Optional[Array[Simplib::IP::V4::CIDR]]             $clear_private_cidrs        = undef,
  Optional[Array[Simplib::IP::V4::CIDR]]             $private_cidrs              = undef,
  Optional[Array[Simplib::IP::V4::CIDR]]             $private_clear_cidrs        = undef,
) {
  simplib::assert_metadata($module_name)

  if $fips or $facts['fips_enabled'] {
    $token = 'NSS FIPS 140-2 Certificate DB'
  }
  else {
    $token = 'NSS Certificate DB'
  }

  # pluto reads the NSS password file from the config directory (ipsecdir),
  # even when the NSS database itself lives in $nssdir
  $nsspassword = "${ipsecdir}/nsspassword"

  contain 'libreswan::install'
  contain 'libreswan::config'

  Class['libreswan::install'] -> Class['libreswan::config']

  if $service_ensure =~ NotUndef or $service_enable =~ NotUndef {
    contain 'libreswan::service'
    Class['libreswan::config'] ~> Class['libreswan::service']
  }

  if $haveged {
    include 'haveged'
    if $service_ensure =~ NotUndef or $service_enable =~ NotUndef {
      Class['haveged'] -> Class['libreswan::service']
    }
  }

  if $firewall {
    contain 'libreswan::config::firewall'
    if $service_ensure =~ NotUndef or $service_enable =~ NotUndef {
      Class['libreswan::config::firewall'] ~> Class['libreswan::service']
    }
  }

  if $pki {
    contain 'libreswan::config::pki'
    contain 'libreswan::config::pki::nsspki'

    Class['libreswan::config::pki'] ~> Class['libreswan::config::pki::nsspki']
    if $service_ensure =~ NotUndef or $service_enable =~ NotUndef {
      Class['libreswan::config::pki::nsspki'] ~> Class['libreswan::service']
    }
  }

  if $nss_scripts {
    include 'libreswan::nss'
  }
}
