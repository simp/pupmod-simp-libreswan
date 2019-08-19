# Define to create a connection file in the ipsec configuration
# directory. The name of the connection must be unique.
#
# You can can set up defaults for all of your connections by using the
# name 'default'. This will create a file default.conf with a
# 'conn %default' header.  Then, all settings in default.conf will be
# used as defaults for connections specified in other files.
#
# Not all available, connection-related, libreswan settings are defined
# here. However, should you need a missing setting you can manually
# create a correctly-formatted, connection configuration file in the
# ipsec configuration directory.  This file must have a ".conf" suffix.
#
# NOTE: Manually generated configuration files are not managed by Puppet.
#
# @param dir  The absolute path to the ipsec configuration
# directory.
#
# The following parameters correspond to libreswan settings for which
# the default values are different from the libreswan defaults. You
# can override the defaults by passing in different data in the
# definition parameters.
#
# @param keyingtries  The number of times a connection will try to
#    reconnect before exiting.
#
# @param ike  The ciphers used in the connection
#    changed from 3Des or aes/sha or md5/and diffie hellman
#
# @param phase2alg  The ciphers used in the second part of the connection.
#
# The rest of the parameters map one-to-one to libreswan settings and
# are undef. Any undef parameter will not appear in the generated
# configuration file for the connection. See libreswan documentation for
# the setting defaults when omitted from a connection's configuration.
#   https://libreswan.org/man/ipsec.conf.5.html, the CONN:SETTINGS section
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
# @param modecfgdns1
# @param modecfgdns2
# @param modecfgdomain
# @param modecfgbanner
# @param nat_ikev1_method
#
define libreswan::connection (
  Stdlib::Absolutepath                 $dir                = '/etc/ipsec.d',
  Integer                              $keyingtries        = 10,
  String                               $ike                = 'aes-sha2;dh24',
  String                               $phase2alg          = 'aes-sha2;dh24',
  # TODO reorder parameters more logically
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
    'passthrough','reject','drop']]     $type               = undef,
  Optional[Enum['insist','permit',
    'propose','never','yes', 'no']]    $ikev2              = undef,
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
  Optional[Simplib::IP]                $modecfgdns1        = undef,
  Optional[Simplib::IP]                $modecfgdns2        = undef,
  Optional[String]                     $modecfgdomain      = undef,
  Optional[String]                     $modecfgbanner      = undef,
  Optional[Enum['drafts','rfc',
    'both']]                           $nat_ikev1_method   = undef,
  Optional[Enum['hold','passthrough']] $negotiationshunt   = undef,
  Optional[Enum['none','passthrough',
    'drop','reject']]                  $failureshunt       = undef,
  Optional[Enum['no','yes']]           $rekey              = undef,
  Optional[Enum['rsasig','secret',
    'null']]                           $leftauth           = undef,
  Optional[Enum['rsasig','secret',
    'null']]                           $rightauth          = undef,
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
    notify  => Service[$::libreswan::service_name]
  }
}
