# @summary Manage a single `key = value` setting line in an ipsec.conf-style file.
#
# Used internally by `libreswan::config`. Set `ensure => absent` (and pass `key`)
# to remove a line.
#
# @param path
#   Absolute path to the file to edit.
#
# @param value
#   The value to set for `key`. Required when `ensure => present`.
#
# @param key
#   The configuration key. Defaults to `$title`. Pass explicitly when using
#   `ensure => absent` with a title prefix (e.g. `purge-protostack`).
#
# @param ensure
#   `present` to set the line, `absent` to remove it.
#
define libreswan::config::setting (
  Stdlib::Absolutepath  $path,
  Optional[ScalarData]  $value  = undef,
  String[1]             $key    = $title,
  Enum[present, absent] $ensure = present,
) {
  if $ensure == present and $value =~ Undef {
    fail("libreswan::config::setting[${title}]: \$value is required when ensure => present")
  }

  $_match = "^\\s*${regsubst($key, '[.\\-]', '\\\\\\0', 'G')}\\s*="

  $_match_for_absence = $ensure ? {
    'absent' => true,
    default  => undef,
  }

  file_line { "libreswan ${path} ${key}":
    ensure            => $ensure,
    path              => $path,
    line              => "  ${key} = ${value}",
    match             => $_match,
    match_for_absence => $_match_for_absence,
  }
}
