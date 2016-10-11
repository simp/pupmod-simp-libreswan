module Puppet::Parser::Functions
  newfunction(:libreswan_validate_yesno, :doc => <<-'ENDHEREDOC') do |args|
   Validate that a passed String contains 'yes' or 'no', exactly.

    The following values will pass:

      libreswan_validate_yesno('yes')
      libreswan_validate_yesno('no')

    The following values will fail:

      libreswan_validate_yesno(' yes ')
      libreswan_validate_yesno('yes', 'yes')
      libreswan_validate_yesno('Yes')
      libreswan_validate_yesno('No')
      libreswan_validate_yesno('YES')
      libreswan_validate_yesno('NO')

    ENDHEREDOC

    if (args.length != 1)
      raise Puppet::ParseError,('libreswan_validate_yesno(): Must pass a string.')
    end

    unless (args[0].is_a?(String))
      raise Puppet::ParseError,("libreswan_validate_yesno(): arg must be a String")
    end

    if (args[0] != 'yes' and args[0] != 'no')
      raise Puppet::ParseError,("libreswan_validate_yesno(): '#{args[0]}' is not 'yes' or 'no'")
    end

  end
end
