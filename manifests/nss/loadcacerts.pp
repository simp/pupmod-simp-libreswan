# This class is called by the system using the NSS database
# located in dbdir. The default is the IPSEC database
# dir. This module will load the CA certs into the database.
#
# @param dbdir [String] The directory where the DB is located
#
# @param nsspwd_file [String]
#
# @param cert [AbsolutePath] The absolute path to the public portion CA certificate.
#
# @param certtype [String] The format the certificate is in. PEM and DER are currently acceptable.
#
define libreswan::nss::loadcacerts(
  $dbdir,
  $cert,
  $token       = 'NSS Certificate DB',
  $certtype    = 'PEM',
  $nsspwd_file = "${dbdir}/nsspassword",
) {
  validate_absolute_path($dbdir)
  validate_string($token)
  validate_absolute_path($cert)
  validate_array_member($certtype,['PEM','DER'])

  $nickname = $title

  case $certtype {
    'PEM': {
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "certutil -A -a -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
        path        => ['/bin', '/sbin'],
        refreshonly => true
      }
    }
    'DER': {
      exec { "Load ${nickname} to ${dbdir}" :
        command     => "certutil -A -i ${cert} -h \"${token}\" -d sql:${dbdir} -f ${nsspwd_file} -n ${nickname} -t \'C,,\'",
        path        => ['/bin', '/sbin'],
        refreshonly => true
      }
    }
    default: {
      fail("unsupported CA certificate type ${certtype}")
    }
  }

}
