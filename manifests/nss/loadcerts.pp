# This class is used to load a server certificate
# into the NSS database located in the directory
# indicated by parameter dbdir.
#
# @param dbdir  The directory where the NSS Database is located.
#
# @param nsspwd_file  The file which contains the password if there is one.
#
# @param cert  The absolute path to the public portion of the cert.
#
# @param key  The absolute path to the private portion of the cert.
#
# @param certtype  The format the certificate is in.
#   PEM and P12 are currently acceptable.
#
define libreswan::nss::loadcerts(
  Stdlib::Absolutepath              $dbdir,
  Stdlib::Absolutepath              $cert,
  String                            $token       = 'NSS Certificate DB',
  Enum['PEM','P12']                 $certtype    = 'PEM',
  Optional[Stdlib::Absolutepath]    $key         = undef,
  Stdlib::Absolutepath              $nsspwd_file = "${dbdir}/nsspassword",
) {

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
        path        => ['/bin', '/sbin', '/usr/bin'],
        notify      => Exec["Load ${nickname} to ${dbdir}"],
        require     => File["${dbdir}/pki"],
        refreshonly => true
      }
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "pk12util -i ${p12cert} -h \"${token}\" -d sql:${dbdir} -k ${nsspwd_file} -W \"\" -n ${nickname}",
        refreshonly => true,
        path        => ['/bin', '/sbin', '/usr/bin'],
      }
    }
    'P12': {
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "pk12util -i ${cert} -h \"${token}\" -d sql:${dbdir} -k ${nsspwd_file} -W \"\" -n ${nickname}",
        refreshonly => true,
        path        => ['/bin', '/sbin', '/usr/bin'],
      }
    }
    default: {
      fail("unsupported Server certificate type ${certtype}")
    }
  }

}
