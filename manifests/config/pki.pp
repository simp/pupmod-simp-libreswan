# @summary Ensure that the `simp/pki` PKI certificates are loaded into the IPSEC NSS Database.
#
# @param app_pki_external_source
#   * If `$pki` = `'simp'` or `true`, this is the directory from which certs
#   will be copied, via `pki::copy`.
#   * If `$pki` = `false`, this variable has no effect.
#
# @param app_pki_dir
#   Controls the base path of the other `app_pki_*` parameters.
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
  String               $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath $app_pki_dir             = '/etc/pki/simp_apps/libreswan/x509',
  Stdlib::Absolutepath $app_pki_cert            = "${app_pki_dir}/public/${facts['facts['networking']['fqdn']']}.pub",
  Stdlib::Absolutepath $app_pki_key             = "${app_pki_dir}/private/${facts['facts['networking']['fqdn']']}.pem",
  Stdlib::Absolutepath $app_pki_ca              = "${app_pki_dir}/cacerts/cacerts.pem"
){

  if $libreswan::pki {
    pki::copy { 'libreswan' :
      source => $app_pki_external_source,
      pki    => $libreswan::pki,
    }
  }
}

