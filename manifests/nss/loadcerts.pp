# == Class libreswan::config::nss::loadcacerts
#
# This class is used to load a server certificate
# into the NSS database located in the directory
# indicated by parameter dbdir.
# [*name*]
#   The friendly name of the certificate
#   Usually the FQDN of the server.
#   Type: String
#   Default: The name used in the module definition.
#
# [*dbdir*]
#   The directory where the NSS Database is located.
#   Type: String
#   Default:  none
#
# [*nsspwd_file*]
#   The file which contains the password if there is one.
#   Type: String
#   Default:  +${dbdir}/nsspassword+
#   The name of the ipsec package.
#
# [*cert*]
#   Type: Absolute Path
#   Default:  none this is required.
#   The absolute path to the public portion of the cert.
#
# [*key*]
#   Type: Absolute Path
#   Default:  none this is required.
#   The absolute path to the private portion of the cert.
#
# [*certtype*]
#   Type: String
#   Default: +PEM+
#   The format the certificate is in.  PEM and P12 are currently acceptable.
#
#
define libreswan::nss::loadcerts(
  $dbdir,
  $cert,
  $token = 'NSS Certificate DB',
  $certtype = 'PEM',
  $key = undef,
  $nsspwd_file = "${dbdir}/nsspassword",
) {
  validate_absolute_path($dbdir)
  validate_string($token)
  validate_absolute_path($cert)
  validate_array_member($certtype,['PEM','P12'])
  validate_absolute_path($key)

  $nickname = $title

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
          notify      => Exec["Load ${nickname} to ${dbdir}"],
          require     => File["${dbdir}/pki"],
          refreshonly => true
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
