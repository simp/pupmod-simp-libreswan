# If use_simp-pki is set this module will ensure that there
# the PKI certificates are loaded into the NSS Database used
# by the IPSEC process.
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
# @param app_pki_external_source
#   * If pki = 'simp' or true, this is the directory from which certs will be
#     copied, via pki::copy.  Defaults to /etc/pki/simp/x509.
#
#   * If pki = false, this variable has no effect.
#
# @param app_pki_dir
#   This variable controls the basepath of $app_pki_key, $app_pki_cert,
#   $app_pki_ca, $app_pki_ca_dir, and $app_pki_crl.
#   It defaults to /etc/pki/simp_apps/libreswan/x509.
#
# @param app_pki_key
#   Path and name of the private SSL key file
#
# @param app_pki_cert
#   Path and name of the public SSL certificate
#
# @param app_pki_ca
#   Path and name of the CA.
#
class libreswan::config::pki(
  Stdlib::Absolutepath            $app_pki_external_source  = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath            $app_pki_dir              = '/etc/pki/simp_apps/libreswan/x509',
  Stdlib::Absolutepath            $app_pki_cert             = "${app_pki_dir}/public/${::fqdn}.pub",
  Stdlib::Absolutepath            $app_pki_key              = "${app_pki_dir}/private/${::fqdn}.pem",
  Stdlib::Absolutepath            $app_pki_ca               = "${app_pki_dir}/cacerts/cacerts.pem"
){

  if $::libreswan::pki {
    ::pki::copy { 'libreswan' :
      source => $app_pki_external_source,
      pki    => $::libreswan::pki,
    }
  }
}

