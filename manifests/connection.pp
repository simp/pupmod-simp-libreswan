# @summary Create a connection file in the IPSEC configuration directory.
#
# You can can set up defaults for all of your connections by using the name
# 'default'. This will create a file `default.conf` with a `'conn %default'`
# header.  Then, all settings in default.conf will be used as defaults for
# connections specified in other files.
#
# Not all available, connection-related, libreswan settings are defined
# here. However, should you need a missing setting you can manually
# create a correctly-formatted, connection configuration file in the
# IPSEC configuration directory.  This file must have a `.conf` suffix.
#
# * Manually generated configuration files are not managed, or purged, by Puppet.
#
# @param dir
#   The absolute path to the IPSEC configuration directory.
#
# The following parameters correspond to libreswan settings for which
# the default values are different from the libreswan defaults. You
# can override the defaults by passing in different data in the
# definition parameters.
#
# @param keyingtries
#   The number of times a connection will try to reconnect before exiting.
#
# @param ike
#   The ciphers used in the connection.
#
# @param phase2alg
#   The ciphers used in the second part of the connection.
#
# The rest of the parameters map one-to-one to libreswan settings and
# are `undef`.
#
# Any `undef` parameter will not appear in the generated configuration file for
# the connection. See libreswan documentation for the setting defaults when
# omitted from a connection's configuration.
# https://libreswan.org/man/ipsec.conf.5.html, the `CONN:SETTINGS` section
#
# @param left
# @param right
# @param connaddrfamily
# @param leftaddresspool
# @param leftsubnet
# @param leftsubnets
# @param leftprotoport
# @param leftsourceip
# @param leftupdown
# @param leftcert
# @param leftrsasigkey
# @param leftrsasigkey2
# @param leftsendcert
# @param leftnexthop
# @param leftid
# @param leftca
# @param rightid
# @param rightrsasigkey
# @param rightrsasigkey2
# @param rightca
# @param rightaddresspool
# @param rightsubnets
# @param rightsubnet
# @param rightprotoport
# @param rightsourceip
# @param rightupdown
# @param rightcert
# @param rightsendcert
# @param rightnexthop
# @param auto
# @param authby
# @param type
# @param ikev2
# @param mobike
# @param phase2
# @param ikepad
# @param fragmentation
# @param sha2_truncbug
# @param narrowing
# @param sareftrack
# @param leftxauthserver
# @param rightxauthserver
# @param leftxauthusername
# @param rightxauthusername
# @param leftxauthclient
# @param rightxauthclient
# @param leftmodecfgserver
# @param rightmodecfgserver
# @param leftmodecfgclient
# @param rightmodecfgclient
# @param xauthby
# @param xauthfail
# @param modecfgpull
# @param modecfgdns Support 3.23+ DNS configuration
# @param modecfgdns1 Support <= 3.22 domain configuration
# @param modecfgdns2 Support <= 3.22 domain configuration
# @param modecfgdomain Support <= 3.22 domain configuration
# @param modecfgdomains Support 3.23+ domains configuration
# @param modecfgbanner
# @param nat_ikev1_method
# @param dpddelay
# @param dpdtimeout
# @param dpdaction
# @param ipsec_interface
# @param vti_routing
# @param mark
# @param vti_shared
# @param esp
#
define libreswan::connection (
  Stdlib::Absolutepath                 $dir                = '/etc/ipsec.d',
  Integer                              $keyingtries        = 10,
  String                               $ike                = 'aes-sha2',
  Optional[String]                     $phase2alg          = undef,
  Optional[Libreswan::ConnAddr]        $left               = undef,
  Optional[Libreswan::ConnAddr]        $right              = undef,
  Optional[Enum['ipv4','ipv6']]        $connaddrfamily     = undef,
  Optional[Array[Simplib::IP,2,2]]     $leftaddresspool    = undef,
  Optional[Variant[
    Enum['%no','%priv'],
    Pattern['^vhost:*'],
    Pattern['^vnet:*'],
    Simplib::IP::CIDR]]                $leftsubnet         = undef,
  Optional[Array[Simplib::IP::CIDR]]   $leftsubnets        = undef,
  Optional[String]                     $leftprotoport      = undef,
  Optional[Simplib::IP]                $leftsourceip       = undef,
  Optional[String]                     $leftupdown         = undef,
  Optional[String]                     $leftcert           = undef,
  Optional[String]                     $leftrsasigkey      = undef,
  Optional[String]                     $leftrsasigkey2     = undef,
  Optional[Enum['yes', 'no',
    'never','always','sendifasked']]   $leftsendcert       = undef,
  Optional[Variant[
    Enum['%direct','%defaultroute'],
    Simplib::IP]]                      $leftnexthop        = undef,
  Optional[String]                     $leftid             = undef,
  Optional[String]                     $leftca             = undef,
  Optional[String]                     $rightid            = undef,
  Optional[String]                     $rightrsasigkey     = undef,
  Optional[String]                     $rightrsasigkey2    = undef,
  Optional[String]                     $rightca            = undef,
  Optional[Array[Simplib::IP,2,2]]     $rightaddresspool   = undef,
  Optional[Array[Simplib::IP::CIDR]]   $rightsubnets       = undef,
  Optional[Variant[
    Enum['%no','%priv'],
    Pattern['^vhost:*'],
    Pattern['^vnet:*'],
    Simplib::IP::CIDR]]                $rightsubnet        = undef,
  Optional[String]                     $rightprotoport     = undef,
  Optional[Simplib::IP]                $rightsourceip      = undef,
  Optional[String]                     $rightupdown        = undef,
  Optional[String]                     $rightcert          = undef,
  Optional[Enum['yes', 'no',
    'never','always','sendifasked']]   $rightsendcert      = undef,
  Optional[Variant[
    Enum['%direct','%defaultroute'],
    Simplib::IP]]                      $rightnexthop       = undef,
  Optional[Enum['add','start',
    'ondemand', 'ignore']]             $auto               = undef,
  Optional[Enum['rsasig','secret',
    'secret|rsasig', 'never', 'null']] $authby             = undef,
  Optional[Enum['tunnel','transport',
    'passthough','reject','drop']]     $type               = undef,
  Optional[Enum['insist','permit',
    'propose','never','yes', 'no']]    $ikev2              = undef,
  Optional[Enum['yes', 'no']]          $mobike             = undef,
  Optional[Enum['esp', 'ah']]          $phase2             = undef,
  Optional[Enum['yes','no']]           $ikepad             = undef,
  Optional[Enum['yes','no','force']]   $fragmentation      = undef,
  Optional[Enum['yes','no']]           $sha2_truncbug      = undef,
  Optional[Enum['yes','no']]           $narrowing          = undef,
  Optional[Enum['yes','no',
    'conntrack']]                      $sareftrack         = undef,
  Optional[Enum['yes','no']]           $leftxauthserver    = undef,
  Optional[Enum['yes','no']]           $rightxauthserver   = undef,
  Optional[String]                     $leftxauthusername  = undef,
  Optional[String]                     $rightxauthusername = undef,
  Optional[Enum['yes','no']]           $leftxauthclient    = undef,
  Optional[Enum['yes','no']]           $rightxauthclient   = undef,
  Optional[Enum['yes','no']]           $leftmodecfgserver  = undef,
  Optional[Enum['yes','no']]           $rightmodecfgserver = undef,
  Optional[Enum['yes','no']]           $leftmodecfgclient  = undef,
  Optional[Enum['yes','no']]           $rightmodecfgclient = undef,
  Optional[Enum['file','pam',
    'alwaysok']]                       $xauthby            = undef,
  Optional[Enum['hard','soft']]        $xauthfail          = undef,
  Optional[Enum['yes','no']]           $modecfgpull        = undef,
  Optional[Array[Simplib::IP]]         $modecfgdns         = undef,
  Optional[Simplib::IP]                $modecfgdns1        = undef,
  Optional[Simplib::IP]                $modecfgdns2        = undef,
  Optional[String]                     $modecfgdomain      = undef,
  Optional[Array[String]]              $modecfgdomains     = undef,
  Optional[String]                     $modecfgbanner      = undef,
  Optional[Enum['drafts','rfc',
    'both']]                           $nat_ikev1_method   = undef,
  Optional[Pattern[/\d+[smh]$/]]       $dpddelay           = undef,
  Optional[Pattern[/\d+[smh]$/]]       $dpdtimeout         = undef,
  Optional[Enum['hold', 'clear',
    'restart']]                        $dpdaction          = undef,
  Optional[String]                     $vti_interface      = undef,
  Optional[Enum['yes', 'no']]          $vti_routing        = undef,
  Optional[Enum['yes', 'no']]          $vti_shared         = undef,
  Optional[String]                     $mark               = undef,
  Optional[String]                     $esp                = undef,
  Optional[String]                     $ikelifetime        = undef,
  Optional[String]                     $salifetime         = undef,
) {
  include 'libreswan'


  # TODO Create custom type for *protoport to allow following types of permutations:
  #   *protoport=17   *protoport=17/1701  *protoport=17/%any  *protoport=tcp
  #   *protoport=tcp/22  *protoport=tcp/%any


  if $title == 'default' {
    $conn_name = '%default'
  }
  else {
    $conn_name = $name
  }

  $conn_file_name =  "${dir}/${name}.conf"

  file { $conn_name:
    ensure  => file,
    path    => $conn_file_name,
    mode    => '0600',
    owner   => root,
    content => template('libreswan/etc/ipsec.d/connection.conf.erb'),
    notify  => Class['libreswan::service']
  }
}
