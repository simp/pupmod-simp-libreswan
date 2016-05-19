# == Define: ipsectunnel::add_connection
#
# Define to set up connection files in the ipsec
# directory.  The name of the connection must be unique.
#
# You can can set up defaults for your connections by using the name
# default.  This will create a file default.conf with a  conn %default
# header and all settings will be used as defaults for any connection.
#
# Not all settings from libreswan that are available for connections
# are defined here.  A connection can also be created by placing a file
# in the correct format in the ipsec directory and giving it a .conf suffix.
#
#  == Parameters
#
# [*dir*]  The absolute path to the IPSEC directory.
#          Default = /etc/ipsec.d
# All the other parameters are possible values for the "conn" section
# in the ipsec configuration.  You can define as many different 
# connects as needed.
#
# Read the Libreswan Documentation for details of the settings
# https://libreswan.org/man/ipsec.conf.5.html  the 
#    CONN:SETTINGS section
# 
# The following settings, because they have defaults other than
# what was set in libreswan will always appear in a connection file.
# you can still override the defaults by passing in different data
# in the definition parameters.
# [*keyingtries*] The number of times a connection will try to
#    reconnect before exiting.
#    Default: 10 ( 0 or forever in Libreswan)
# [*ike*]   The ciphers used in the connection
#    Default aes256-sha1:dh24
#    changed from 3Des or aes/sha or md5/and diffie hellman
# [*phase2alg*] the ciphers used in the second part of the connection.
#    Default aes256-sha1:dh24
#
# The rest of the parameters are undef.  See Libreswan documentation
# or defaults and definitions.
#
# [*left*]  The IP Address of the local connection.
# [*type*]  The type of connection:  passthrough, tunnel
# [*left*]
# [*right*]
# [*connaddrfamily*]
# [*leftsubnet*]
# [*leftsubnets*]
# [*leftprotoport*]
# [*leftsourceip*]
# [*leftupdown*]
# [*leftcert*]
# [*leftrsasigkey*]
# [*leftsendcert*]
# [*leftid*]
# [*leftca*]
# [*rightid*]
# [*rightrsasigkey*]
# [*rightca*]
# [*rightsubnet*]
# [*rightsubnets*]
# [*rightprotoport*]
# [*rightsourceip*]
# [*rightupdown*]
# [*rightcert*]
# [*righsendcert*]
# [*auto*]
# [*authby*]
# [*type*]
# [*ike2*]
# phase2
# phase2alg
#
# == Authors
#
define ipsec_tunnel::add_connection (
  $dir = '/etc/ipsec.d',
  $keyingtries = '10',
  $ike = 'aes-sha2;dh24',
  $phase2alg = 'aes-sha2;dh24',
  $left = undef,
  $right = undef,
  $connaddrfamily = undef,
  $leftsubnet = undef,
  $leftsubnets = undef,
  $leftprotoport = undef,
  $leftsourceip = undef,
  $leftupdown = undef,
  $leftcert = undef,
  $leftrsasigkey = undef,
  $leftrsasigkey2 = undef,
  $leftsendcert = undef,
  $leftnexthop = undef,
  $leftid = undef,
  $leftca = undef,
  $rightid = undef,
  $rightrsasigkey = undef,
  $rightrsasigkey2 = undef,
  $rightca = undef,
  $rightsubnet = undef,
  $rightsubnets = undef,
  $rightprotoport = undef,
  $rightsourceip = undef,
  $rightupdown = undef,
  $rightcert = undef,
  $rightsendcert = undef,
  $rightnexthop = undef,
  $auto = undef,
  $authby = undef,
  $type = undef,
  $ike2 = undef,
  $phase2 = undef,
  $ikepad = undef,
  $ike_frag = undef,
  $sha2_truncbug = undef,
  $narrowing = undef,
  $sareftrack = undef,

) {
  include 'ipsec_tunnel'

  case $right {
    undef  :  {}
    '%any' :  {}
    '%defaultroute' :  {}
    '%opportunistic' :  {}
    '%opportunisticgroup' :  {}
    '%group' :  {}
    default:  {validate_ipv4_address($right)}
  }
  case $left {
    undef  :  {}
    '%any' :  {}
    '%defaultroute' :  {}
    '%opportunistic' :  {}
    '%opportunisticgroup' :  {}
    '%group' :  {}
    default:  {validate_ipv4_address($left)}
  }
  if $leftprotoport   { validate_port($leftprotoport)}
  if $rightprotoport  { validate_port($rightprotoport)}
  if $leftsourceip    { validate_ipv4_address($leftsourceip)}
  if $rightsourceip   { validate_ipv4_address($rightsourceip)}
  if $leftupdown      { validate_string($leftupdown)}
  if $rightupdown     { validate_string($rightupdown)}
  if $authby          { validate_array_member($authby, ['rsasig','secrets'])}
  if $auto            { validate_array_member($auto, ['add','start','ondemand','ignore'])}
  if $leftcert        { validate_string($leftcert)}
  if $rightcert       { validate_string($rightcert)}
  if $leftrsasigkey   { validate_array_member($leftrsasigkey, ['%cert','%none','%dns','%dnsonload','%dnsondemand'])}
  if $leftrsasigkey2   { validate_array_member($leftrsasigkey2, ['%cert','%none','%dns','%dnsonload','%dnsondemand'])}
  if $rightrsasigkey  { validate_array_member($rightrsasigkey, ['%cert','%none','%dns','%dnsonload','%dnsondemand'])}
  if $rightrsasigkey2  { validate_array_member($rightrsasigkey2, ['%cert','%none','%dns','%dnsonload','%dnsondemand'])}
  if $leftsendcert    { validate_array_member($leftsendcert, ['yes','no','never','always','ifasked'])}
  if $rightsendcert    { validate_array_member($rightsendcert, ['yes','no','never','always','ifasked'])}
  if $leftid          { validate_string($leftid)}
  if $rightid         { validate_string($rightid)}
  if $leftca          { validate_string($leftca)}
  if $rightca         { validate_string($rightca)}
  if $connaddrfamily  { validate_re($connaddrfamily,'^(ipv4|ipv6)$',"${connaddrfamily} is not supported for hidetos") }
  if $type            { validate_array_member($type, ['tunnel','transport','passthough','reject','drop'])}
  if $leftsubnets     { validate_net_list($leftsubnets)}
  if $rightsubnets    { validate_net_list($rightsubnets)}
  if $leftsubnet      { validate_net_list($leftsubnet)}
  if $rightsubnet     { validate_net_list($rightsubnet)}
  if $leftnexthop      { validate_ipv4_address($leftnexthop)}
  if $rightnexthop     { validate_ipv4_address($rightnexthop)}
  if $ikev2            { validate_array_member($ikev2, ['insist','permit','propose','never','yes', 'no'])}
  if $ikepad  { validate_re($ikepad,'^(yes|no)$',"${ikepad} is not supported for hidetos") }
  if $narrowing  { validate_re($narrowing,'^(yes|no)$',"${narrowing} is not supported for hidetos") }
  if $sha2_truncbug  { validate_re($sha2_truncbug,'^(yes|no)$',"${sha2_truncbug} is not supported for hidetos") }
  if $nat_ikev1_method            { validate_array_member($nat_ikev1_method, ['draft','rfc','both'])}
  if $ike_frag            { validate_array_member($ike_frag, ['yes','no','force'])}
  if $sareftrack            { validate_array_member($sareftrack, ['yes','no','conntrack'])}

  validate_string($phase2alg)
  validate_string($ike)
  validate_integer($keyingtries)

  validate_absolute_path($dir)

  if $title == 'default' { $conn_name = '%default' }
  else                  { $conn_name = $name }

  $conn_file_name =  "${dir}/${name}.conf"

  file { $conn_name:
    ensure  => file,
    name    => $conn_file_name,
    mode    => '0600',
    owner   => root,
    content => template('ipsec_tunnel/etc/ipsec.d/connection.conf.erb')
  }
}
