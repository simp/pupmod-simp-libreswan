require 'spec_helper'

describe 'libreswan_validate_yesno' do
  ['yes', 'Yes', 'yEs', 'yeS', 'YEs', 'yES', 'YeS', 'YES',
      'no', 'No', 'nO', 'NO'].each do |test_string|
    it "validates a #{test_string} argument as a yes/no variant" do
      expect { subject.call([test_string]) }.to_not raise_error
    end
  end

  it 'accepts yes/no strings with whitespace' do
    [' yes', 'no ', "\tyes\t"].each do |test_string|
      expect { subject.call([test_string]) }.to_not raise_error
    end
  end

  it 'rejects no arguments' do
    expect { subject.call([]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): Must pass a string/)
  end

  it 'rejects too many arguments' do
      expect { subject.call([['yes', 'yes']]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): arg must be a String/)
  end

  it 'rejects non-yes/no strings' do
    ['true', 'false', ""].each do |test_string|
      expect { subject.call([test_string]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): '#{test_string}' is not 'yes' or 'no'/)
    end
  end
end
