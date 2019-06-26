Gem::Specification.new do |s|
  s.name          = 'logstash-codec-postfix'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'This codec parses postfix logs'
  s.description   = 'You can also use this codec to parse auth and syslog logs'
  s.homepage      = 'https://github.com/pietrogu/logstash-codec-postfix'
  s.authors       = ['']
  s.email         = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "codec" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-line'
  s.add_development_dependency 'logstash-devutils'
end
