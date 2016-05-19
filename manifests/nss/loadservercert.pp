# == Class ipsec_tunnel::nss::loadservercert
#
# This class is meant to be called from ipsec_tunnel.
# It will load a PKI cert in either .p12 format or .pem
# format into the  NSS database locaed where the parameter 
# the NSS database.  
#
# [*title*]:  The title of this instance will be used as the friendly name 
# of the certificate.  It should be the FQDN of the server whose cert
# is being loaded.
#
# [*dbdir*]
#   The name of the ipsec_tunnel service.
#   Type: String
#   Default:  +$::ipsec_tunnel::params::service_name+
#
# [*nsspwd_file*]
#   Type: String
#   Default:  +$::ipsec_tunnel::params::package_name+
#   The name of the ipsec_tunnel package.
#
# [*cert*]
#   Type: Absolute Path
#   Default:  none this is required.
#   The absolute path to the public portion of the certificate file.  This
#   should always be defined.
#
# [*key*]
#   Type: Absolute Path
#   Default: +undef+
#   The absolute path to the key file that goes with the certificate file.  If
#   using PK12 format leave key undef.
#
# [*certtype*]
#   Type: String
#   Default: +PEM+
#   The type o format the certificate is in.  PEM and P12 are currently acceptable.
#
define ipsec_tunnel::nss::loadservercert(
  $dbdir,
  $cert,
  $key = undef,
  $nsspwd_file = "${dbdir}/nsspassword",
  $certtype = 'PEM',
) {

  validate_absolute_path($dbdir)
  validate_absolute_path($nsspwd_file)
  validate_absolute_path($cert)
  validate_array_member( $certtype,['P12','PEM'])
  if $key { validate_absolute_path($key)}

  # Need a .p12 cert to put machine cert in DB.
  case $certtype {
    'P12': {
      exec {"Enter ${title} Cert in NSS DB":
        command => "pk12util -i ${cert}  -d sql:${dbdir} -f ${nsspwd_file} -n ${title}",
        path    => ['/bin', '/sbin'],
        }
      }
    'PEM': {
      file { '/etc/pki/pk12' :
        ensure => directory,
        mode   => '0750',
        owner  =>  root,
        }
      exec { "convert PEM to PK12 ${title}":
        path    => ['/bin', '/sbin'],
        creates => "/etc/pki/pk12/${title}.p12",
        require => File['/etc/pki/pk12'],
        command => "openssl pkcs12 -export -in ${cert} -inkey ${key} -out /etc/pki/pk12/${title}.p12  -name ${title}",
        }
      exec { "Enter ${title} Cert in NSS DB":
        command =>  "pk12util -i /etc/pki/pk12/${title}.p12 -d sql:${dbdir} -f ${nsspwd_file} -n ${title}",
        path    => ['/bin', '/sbin'],
        require =>  Exec["convert PEM to PK12 ${title}"],
        }
      }
    default: { fail("unsupported server certificate type  ${certtype}")
      }
    }
}
