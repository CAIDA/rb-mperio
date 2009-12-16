#!/usr/bin/env ruby

# $Id: rb-wartslib.gemspec,v 1.35 2009/04/24 22:59:06 youngh Exp $

require 'rubygems'

#---------------------------------------------------------------------------

MY_VERSION = "0.2.0"

MY_EXTRA_FILES = ["README", "CHANGES", "COPYING"]

candidates = Dir.glob("{bin,lib,test}/**/*")
candidates << "ext/extconf.rb"
candidates.concat Dir.glob("ext/*.[ch]")
#candidates.concat Dir.glob("docs/*.{html,css,rb}")
candidates.concat MY_EXTRA_FILES

MY_FILES = candidates.delete_if do |item|
  item.include?("CVS") || item.include?("rdoc") || item =~ /\~$/ ||
    File.directory?(item)
end

#---------------------------------------------------------------------------

spec = Gem::Specification.new do |s|
  s.name      = "rb-mperio"
  s.version   = MY_VERSION
  s.author    = "Young Hyun"
  s.email     = "youngh@rubyforge.org"
  s.homepage  = "http://rb-mperio.rubyforge.org/"
  s.rubyforge_project  = "rb-mperio"
  s.platform  = Gem::Platform::RUBY
  s.summary   = "Ruby extension for interacting with mper"
  s.description = <<-EOF
This is a Ruby extension for interacting with mper.
EOF
  s.files     = MY_FILES
  s.require_path = "lib"
  s.extensions = ["ext/extconf.rb"]
  #s.test_file = "test/ts_wartslib.rb"
  s.has_rdoc  = false
  s.extra_rdoc_files = MY_EXTRA_FILES
end

#===========================================================================

if $0 == __FILE__
  gem_name = "rb-mperio-#{MY_VERSION}.gem"
  File.delete gem_name if File.exists? gem_name
  Gem::Builder.new(spec).build

  tar_name = "rb-mperio-#{MY_VERSION}.tar"
  puts "creating #{tar_name}.gz"
  File.delete tar_name if File.exists? tar_name
  File.delete "#{tar_name}.gz" if File.exists? "#{tar_name}.gz"
  tar_contents = MY_FILES.join(" ")
  system "tar cf #{tar_name} #{tar_contents}"
  system "gzip -9 #{tar_name}"
end
