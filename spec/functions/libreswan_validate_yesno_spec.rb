require 'spec_helper'

describe 'libreswan_validate_yesno' do
  it "validates a 'yes' argument" do
    expect { subject.call(['yes']) }.to_not raise_error
  end

  it "validates a 'no' argument" do
    expect { subject.call(['no']) }.to_not raise_error
  end

  it 'rejects no arguments' do
    expect { subject.call([]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): Must pass a string/)
  end

  it 'rejects too many arguments' do
      expect { subject.call([['yes', 'yes']]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): arg must be a String/)
  end

  it 'rejects yes/no strings with whitespace' do
    [' yes', 'no ', "\tyes\t"].each do |test_string|
      expect { subject.call([test_string]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): '#{test_string}' is not 'yes' or 'no'/)
    end
  end

  it 'rejects yes/no strings with incorrect cases' do
    ['Yes', 'YES', 'No', 'NO'].each do |test_string|
      expect { subject.call([test_string]) }.to raise_error(Puppet::ParseError, /libreswan_validate_yesno\(\): '#{test_string}' is not 'yes' or 'no'/)
    end
  end
end
