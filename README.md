# Hkdf

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/hkdf`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'hkdf', github: 'Yamaguchi/hkdf/'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install specific_install
    $ gem specific_install -l 'https://github.com/Yamaguchi/hkdf.git'

## Usage

### Use OpenSSL implementation

    root@5cd510b346b2:~/hkdf# ./bin/console
    irb(main):001:0> ikm = ["0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"].pack("H*")
    => "\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v"
    irb(main):002:0> salt = ["000102030405060708090a0b0c"].pack("H*")
    => "\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f"
    irb(main):003:0> info = ["f0f1f2f3f4f5f6f7f8f9"].pack("H*")
    => "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9"
    irb(main):004:0> length = 42
    => 42
    irb(main):005:0> Hkdf.hkdf(ikm, salt: salt, info: info, length: length, hash: "sha256", hash_len: 32)
    => "<\xB2_%\xFA\xAC\xD5z\x90COd\xD06/*--\n\x90\xCF\x1AZL]\xB0-V\xEC\xC4\xC5\xBF4\x00r\b\xD5\xB8\x87\x18Xe"

### Use Custom HMAC function

You can use any hmac function (such as blake2b...), instead of functions supported by openssl.

    root@5cd510b346b2:~/hkdf# ./bin/console
    irb(main):001:0> require "ruby_hmac"
    => true
    irb(main):002:0> require "hmac-sha2"
    => true
    irb(main):003:0> ikm = ["0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"].pack("H*")
    => "\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v"
    irb(main):004:0> salt = ["000102030405060708090a0b0c"].pack("H*")
    => "\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f"
    irb(main):005:0> info = ["f0f1f2f3f4f5f6f7f8f9"].pack("H*")
    => "\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9"
    irb(main):006:0> length = 42
    => 42
    irb(main):007:0> Hkdf.hkdf(ikm, salt: salt, info: info, length: length) { |key, data| HMAC::SHA256.new(key).update(data).digest }
    => "<\xB2_%\xFA\xAC\xD5z\x90COd\xD06/*--\n\x90\xCF\x1AZL]\xB0-V\xEC\xC4\xC5\xBF4\x00r\b\xD5\xB8\x87\x18Xe"

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Yamaguchi/hkdf. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the Hkdf project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Yamaguchi/hkdf/blob/master/CODE_OF_CONDUCT.md).
