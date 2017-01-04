# This class is called by the system using the NSS database
# located in dbdir. The default is the IPSEC database
# dir. This module will load the CA certs into the database.
#
# @param dbdir  The directory where the DB is located
#
# @param nsspwd_file
#
# @param cert  The absolute path to the public portion CA certificate.
#
# @param token
#
# @param certtype  The format the certificate is in. PEM and DER are currently acceptable.
#
define libreswan::nss::loadcacerts(
  Stdlib::Absolutepath   $dbdir,
  Stdlib::Absolutepath   $cert,
  String                 $token       = 'NSS Certificate DB',
  Enum['PEM','DER']      $certtype    = 'PEM',
  Stdlib::Absolutepath   $nsspwd_file = "${dbdir}/nsspassword",
) {

  $nickname = $title

  case $certtype {
    'PEM': {
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "certutil -A -a -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
        path        => ['/bin', '/sbin', '/usr/bin'],
        refreshonly => true
      }
    }
    'DER': {
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "certutil -A -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
        path        => ['/bin', '/sbin', '/usr/bin'],
        refreshonly => true
      }
    }
    default: {
      fail("unsupported CA certificate type ${certtype}")
    }
  }

}
