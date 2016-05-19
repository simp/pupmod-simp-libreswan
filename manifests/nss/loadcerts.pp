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
define ipsec_tunnel::nss::loadcerts(
  $dbdir,
  $cert,
  $token=$::ipsec_tunnel::token,
  $certtype = 'PEM',
  $cacert = false,
  $key = undef,
  $nsspwd_file ="${dbdir}/nsspassword",
) {
  validate_absolute_path($dbdir)
  validate_string($token)
  validate_bool($cacert)
  validate_absolute_path($cert)
  validate_array_member($certtype,['PEM','DER','P12'])
  if $key {validate_absolute_path($key)}

  $nickname = $title

  if $cacert {
  #if it is a Certificate Authority
    case $certtype {
      'PEM': {
        exec { "Load ${nickname} to ${dbdir}" :
          command     => "certutil -A -a -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
          refreshonly => true,
          path        => ['/bin', '/sbin'],
        }
      }
      'DER': {
        exec { "Load ${nickname} to ${dbdir}" :
          command     => "certutil -A -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
          refreshonly => true,
          path        => ['/bin', '/sbin'],
        }
      }
      default: {
        fail("unsupported CA certificate type ${certtype}")
      }
    }
  } else {
  # It is a server certificate
    case $certtype {
      'PEM': {
        $p12cert = "${dbdir}/pki/${nickname}.p12"
        # Change to P12 so both key and cert loaded.
        file { "${dbdir}/pki":
          ensure => directory,
          mode   => '0700',
          owner  => root,
        }
        $p12pwd = 'pass:'
        exec { "Convert ${nickname} to P12" :
          command     => "openssl pkcs12 -export -in ${cert} -inkey ${key} -out ${p12cert} -passout ${p12pwd} -name ${nickname}",
          path        => ['/bin', '/sbin'],
          refreshonly => true,
          before      => Exec["Load ${nickname} to ${dbdir}"],
          require     => File["${dbdir}/pki"],
        }
        exec { "Load ${nickname} to ${dbdir}" :
          command     => "pk12util -i ${p12cert} -h \"${token}\" -d sql:${dbdir} -k ${nsspwd_file} -W \"\" -n ${nickname}",
          refreshonly => true,
          path        => ['/bin', '/sbin'],
        }
      }
      'P12': {
        exec { "Load ${nickname} to ${dbdir}" :
          command     => "pk12util -i ${cert} -h \"${token}\" -d sql:${dbdir} -k ${nsspwd_file} -W \"\" -n ${nickname}",
          refreshonly => true,
          path        => ['/bin', '/sbin'],
        }
      }
      default: {
        fail("unsupported Server certificate type ${certtype}")
      }
    }
  }
}
