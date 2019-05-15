
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "hkdf"

Gem::Specification.new do |spec|
  spec.name          = "hkdf"
  spec.version       = Hkdf::VERSION
  spec.authors       = ["Hajime Yamaguchi"]
  spec.email         = ["gen.yamaguchi0@gmail.com"]

  spec.summary       = ''
  spec.description   = ''
  spec.homepage      = ''

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "ruby-hmac", "0.4.0"
end
