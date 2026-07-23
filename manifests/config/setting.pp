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
# @param after
#   Regex matching the line a *new* line is inserted after (an existing line
#   with the same key is replaced in place wherever it is). When unset, or
#   when no line matches, new lines are appended at end of file.
#
define libreswan::config::setting (
  Stdlib::Absolutepath          $path,
  Optional[ScalarData]          $value  = undef,
  String[1]                     $key    = $title,
  Enum['present', 'absent']     $ensure = 'present',
  Optional[String[1]]           $after  = undef,
) {
  if $ensure == 'present' and $value =~ Undef {
    fail("libreswan::config::setting[${title}]: \$value is required when ensure => 'present'")
  }

  $_match = "^\\s*${regsubst($key, '[.\\-]', '\\\\\\0', 'G')}\\s*="

  $_extra = $ensure ? {
    'absent' => { 'match_for_absence' => true },
    default  => {},
  }

  file_line { "libreswan ${path} ${key}":
    ensure => $ensure,
    path   => $path,
    line   => "  ${key} = ${value}",
    match  => $_match,
    after  => $after,
    *      => $_extra,
  }
}
