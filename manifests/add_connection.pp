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
# @param dir [AbsolutePath] The absolute path to the ipsec configuration
# directory.
#
# The following parameters correspond to libreswan settings for which
# the default values are different from the libreswan defaults. You
# can override the defaults by passing in different data in the
# definition parameters.
#
# @param keyingtries [Integer] The number of times a connection will try to
#    reconnect before exiting.
#
# @param ike [String] The ciphers used in the connection
#    changed from 3Des or aes/sha or md5/and diffie hellman
#
# @param phase2alg [String] the ciphers used in the second part of the connection.
#
# The rest of the parameters map one-to-one to libreswan settings and
# are undef. Any undef parameter will not appear in the generated
# configuration file for the connection. See libreswan documentation for
# the setting defaults when omitted from a connection's configuration.
#   https://libreswan.org/man/ipsec.conf.5.html, the CONN:SETTINGS section
#
#
define libreswan::add_connection (
  $dir                = '/etc/ipsec.d',
  $keyingtries        = '10',
  $ike                = 'aes-sha2;dh24',
  $phase2alg          = 'aes-sha2;dh24',
  # TODO reorder parameters more logically
  $left               = undef,
  $right              = undef,
  $connaddrfamily     = undef,
  $leftaddresspool    = undef,
  $leftsubnet         = undef,
  $leftsubnets        = undef,
  $leftprotoport      = undef,
  $leftsourceip       = undef,
  $leftupdown         = undef,
  $leftcert           = undef,
  $leftrsasigkey      = undef,
  $leftrsasigkey2     = undef,
  $leftsendcert       = undef,
  $leftnexthop        = undef,
  $leftid             = undef,
  $leftca             = undef,
  $rightid            = undef,
  $rightrsasigkey     = undef,
  $rightrsasigkey2    = undef,
  $rightca            = undef,
  $rightaddresspool   = undef,
  $rightsubnet        = undef,
  $rightsubnets       = undef,
  $rightprotoport     = undef,
  $rightsourceip      = undef,
  $rightupdown        = undef,
  $rightcert          = undef,
  $rightsendcert      = undef,
  $rightnexthop       = undef,
  $auto               = undef,
  $authby             = undef,
  $type               = undef,
  $ikev2              = undef,
  $phase2             = undef,
  $ikepad             = undef,
  $fragmentation      = undef,
  $sha2_truncbug      = undef,
  $narrowing          = undef,
  $sareftrack         = undef,
  $leftxauthserver    = undef,
  $rightxauthserver   = undef,
  $leftxauthusername  = undef,
  $rightxauthusername = undef,
  $leftxauthclient    = undef,
  $rightxauthclient   = undef,
  $leftmodecfgserver  = undef,
  $rightmodecfgserver = undef,
  $leftmodecfgclient  = undef,
  $rightmodecfgclient = undef,
  $xauthby            = undef,
  $xauthfail          = undef,
  $modecfgpull        = undef,
  $modecfgdns1        = undef,
  $modecfgdns2        = undef,
  $modecfgdomain      = undef,
  $modecfgbanner      = undef,
  $nat_ikev1_method   = undef,
) {
  include 'libreswan'

  # TODO reorder validations more logically

  #TODO left/right validations do not allow magic values to identify an
  # interface: %<interface name>, e.g. %eth0
  #TODO validate is a valid IP addr but not a masked routing address
  #TODO when validate_net_list() regex logic is fixed....
  # if $left {
  #   validate_string
  #   validate_net_list($left, '^(%any|%defaultroute|%opportunistic|%opportunisticgroup|%group)$)')
  # }
  case $left {
    undef  :  {}
    '%any' :  {}
    '%defaultroute' :  {}
    '%opportunistic' :  {}
    '%opportunisticgroup' :  {}
    '%group' :  {}
    default  :  {
      validate_string($left) # must be single IP address
      validate_net_list($left)
    }
  }
  #TODO when validate_net_list() regex logic is fixed....
  # if $right {
  #   validate_string
  #   validate_net_list($right, '^(%any|%defaultroute|%opportunistic|%opportunisticgroup|%group)$)')
  # }
  case $right {
    undef  :  {}
    '%any' :  {}
    '%defaultroute' :  {}
    '%opportunistic' :  {}
    '%opportunisticgroup' :  {}
    '%group' :  {}
    default :  {
      validate_string($right) # must be single IP address
      validate_net_list($right)
    }
  }

  # TODO Create custom validator to allow following types of permutations:
  #   *protoport=17   *protoport=17/1701  *protoport=17/%any  *protoport=tcp
  #   *protoport=tcp/22  *protoport=tcp/%any
  if $leftprotoport { validate_string($leftprotoport)}
  if $rightprotoport { validate_string($rightprotoport)}

  #TODO validate is a valid IP addr but not a masked routing address
  if $leftsourceip { 
    validate_string($leftsourceip)
    validate_net_list($leftsourceip)
  }
  if $rightsourceip { 
    validate_string($rightsourceip)
    validate_net_list($rightsourceip)
  }
  if $leftupdown         { validate_string($leftupdown)}
  if $rightupdown        { validate_string($rightupdown)}
  if $authby             { validate_array_member($authby, ['rsasig','secret', 'secret|rsasig', 'never', 'null'])}
  if $auto               { validate_array_member($auto, ['add','start','ondemand','ignore'])}
  if $leftcert           { validate_string($leftcert)}
  if $rightcert          { validate_string($rightcert)}
  if $leftrsasigkey      { validate_string($leftrsasigkey) }
  if $leftrsasigkey2     { validate_string($leftrsasigkey2) }
  if $rightrsasigkey     { validate_string($rightrsasigkey) }
  if $rightrsasigkey2    { validate_string($rightrsasigkey2) }
  if $leftsendcert       { validate_array_member($leftsendcert, ['yes','no','never','always','sendifasked'])}
  if $rightsendcert      { validate_array_member($rightsendcert, ['yes','no','never','always','sendifasked'])}
  if $leftid             { validate_string($leftid)}
  if $rightid            { validate_string($rightid)}
  if $leftca             { validate_string($leftca)}
  if $rightca            { validate_string($rightca)}
  if $connaddrfamily     { validate_re($connaddrfamily,'^(ipv4|ipv6)$',"${connaddrfamily} is not supported for connaddrfamily") }
  if $type               { validate_array_member($type, ['tunnel','transport','passthough','reject','drop'])}

  # *subnets can be a single value in a String or multiple values in an Array
  if $leftsubnets        { validate_net_list($leftsubnets) }
  if $rightsubnets       { validate_net_list($rightsubnets) }

  if $leftsubnet         { 
    validate_string($leftsubnet)  # Single CIDR
    validate_net_list($leftsubnet, '(vhost:|vnet:|%priv|%no)') #WARNING regex doesn't work yet
  }
  if $rightsubnet        {
    validate_string($rightsubnet) # Single CIDR
    validate_net_list($rightsubnet, '(vhost:|vnet:|%priv|%no)') #WARNING regex doesn't work yet
  }

  # *addresspool is really supposed to be only 2 IP address values in an Array
  #TODO validate full IP addresses (CIDR notation not allowed)
  #TODO validation Array length is 2
  #
  if $leftaddresspool {
    validate_array($leftaddresspool)
    validate_net_list($leftaddresspool)
  }
  if $rightaddresspool {
    validate_array($rightaddresspool)
    validate_net_list($rightaddresspool)
  }

  #TODO when validate_net_list() regex logic is fixed....
  # if $leftnexthop {
  #   validate_string
  #   validate_net_list($leftnexthop, '^(%direct|%defaultroute)$)')
  # }
  case $leftnexthop {
    undef           : {}
    '%direct'       : {}
    '%defaultroute' : {}
    default         : { 
      validate_string($leftnexthop)
      validate_net_list($leftnexthop)
    }
  }

  #TODO when validate_net_list() regex logic is fixed....
  # if $rightnexthop {
  #   validate_string
  #   validate_net_list($rightnexthop, '^(%direct|%defaultroute)$)')
  # }
  case $rightnexthop {
    undef           : {}
    '%direct'       : {}
    '%defaultroute' : {}
    default         : { 
      validate_string($rightnexthop)
      validate_net_list($rightnexthop)
    }
  }

  if $ikev2              { validate_array_member($ikev2, ['insist','permit','propose','never','yes', 'no'])}
  if $ikepad             { libreswan_validate_yesno($ikepad) }
  if $narrowing          { libreswan_validate_yesno($narrowing) }
  if $phase2             { validate_array_member($phase2, ['esp', 'ah'])}
  if $sha2_truncbug      { libreswan_validate_yesno($sha2_truncbug) }
  if $nat_ikev1_method   { validate_array_member($nat_ikev1_method, ['drafts','rfc','both'])}
  if $fragmentation      { validate_array_member($fragmentation, ['yes','no','force'])}
  if $sareftrack         { validate_array_member($sareftrack, ['yes','no','conntrack'])}
  if $leftxauthserver    { libreswan_validate_yesno($leftxauthserver) }
  if $rightxauthserver   { libreswan_validate_yesno($rightxauthserver) }
  if $leftxauthusername  { validate_string($leftxauthusername) }
  if $rightxauthusername { validate_string($rightxauthusername) }
  if $leftxauthclient    { libreswan_validate_yesno($leftxauthclient) }
  if $rightxauthclient   { libreswan_validate_yesno($rightxauthclient) }
  if $leftmodecfgserver  { libreswan_validate_yesno($leftmodecfgserver) }
  if $rightmodecfgserver { libreswan_validate_yesno($rightmodecfgserver) }
  if $leftmodecfgclient  { libreswan_validate_yesno($leftmodecfgclient) }
  if $rightmodecfgclient { libreswan_validate_yesno($rightmodecfgclient) }
  if $xauthby            { validate_array_member($xauthby, ['file','pam','alwaysok']) }
  if $xauthfail          { validate_array_member($xauthfail, ['hard','soft']) }
  if $modecfgpull        { libreswan_validate_yesno($modecfgpull) }
  if $modecfgdns1        {
    validate_string($modecfgdns1)
    validate_net_list($modecfgdns1)
  }
  if $modecfgdns2        {
    validate_string($modecfgdns2)
    validate_net_list($modecfgdns2)
  }
  if $modecfgdomain      { validate_string($modecfgdomain)}
  if $modecfgbanner      { validate_string($modecfgbanner)}

  validate_string($phase2alg)
  validate_string($ike)
  validate_integer($keyingtries)

  validate_absolute_path($dir)

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
