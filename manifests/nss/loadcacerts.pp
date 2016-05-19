# == Class ipsec_tunnel::config::nss::loadcacerts
#
# This class is meant to be called from ipsec_tunnel.
# for the machine and Certificate Authorities into
# the NSS database.
# [*name*]
#   The friendly name of the CA certificate
#   Type: String
#   Default: The name used in the module definition.
#
# [*dbdir*]
#   The name of the ipsec_tunnel service.
#   Type: String
#   Default:  +$::ipsec_tunnel::params::service_name+
#
# [*nsspwd_file*]
#   Type: String
#   Default:  +$dbdir/nsspassword+
#   The name of the ipsec_tunnel package.
#
# [*cert*]
#   Type: Absolute Path
#   Default:  none this is required.
#   The absolute path to the public portion CA certificate.
#
# [*certtype*]
#   Type: String
#   Default: +PEM+
#   The type o format the certificate is in.  PEM and DER are currently acceptable.
#
#
define ipsec_tunnel::nss::loadcacerts(
  $dbdir,
  $cacert,
  $nsspwd_file = "${dbdir}/nsspassword",
  $cacert_type = 'PEM',
) {
  validate_absolute_path($dbdir)
  validate_absolute_path($nsspwd_file)
  validate_absolute_path($cacert)
  validate_array_member( $cacert_type,['DER','PEM'])

# Need to check if already there????
# Import CA certificate into NSS DB.
  case $cacert_type {
    'PEM': {
      $cacert_enter="certutil -A -a -i ${cacert} -d sql:${dbdir} -f ${nsspwd_file} -n ${name} -t \'C,,\'"
      }
    'DER': {
      $cacert_enter="certutil -A -i ${cacert} -d sql:${dbdir} -f ${nsspwd_file} -n ${name} -t \'C,,\'"
      }
    default: {
      fail("unsupported CA certificate type ${cacert_type}")
      }
    }
  exec { 'Enter CA cert in NSS DB':
    command => $cacert_enter,
    path    => ['/bin', '/sbin'],
    }
}
