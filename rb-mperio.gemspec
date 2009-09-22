#!/usr/bin/env ruby

# $Id: rb-wartslib.gemspec,v 1.35 2009/04/24 22:59:06 youngh Exp $

require 'rubygems'

#---------------------------------------------------------------------------

MY_VERSION = "1.3.0"  # be sure to update scext.c:WARTS_LIB_VERSION

MY_EXTRA_FILES = ["README", "CHANGES", "COPYING"]

candidates = Dir.glob("{bin,lib,test}/**/*")
candidates << "ext/extconf.rb"
candidates.concat Dir.glob("ext/*.[ch]")
candidates.concat Dir.glob("docs/*.{html,css,rb}")
candidates.concat Dir.glob("docs/gen-*")
candidates.concat MY_EXTRA_FILES

MY_FILES = candidates.delete_if do |item|
  item.include?("CVS") || item.include?("rdoc") || item =~ /\~$/ ||
    item =~ /tut-.+\.rb\.html$/ || File.directory?(item)
end

#---------------------------------------------------------------------------

spec = Gem::Specification.new do |s|
  s.name      = "rb-wartslib"
  s.version   = MY_VERSION
  s.author    = "Young Hyun"
  s.email     = "youngh@rubyforge.org"
  s.homepage  = "http://rb-wartslib.rubyforge.org/"
  s.rubyforge_project  = "rb-wartslib"
  s.platform  = Gem::Platform::RUBY
  s.summary   = "Ruby extension for reading/writing warts files"
  s.description = <<-EOF
This is a Ruby extension for reading/writing warts files.  Warts files are
output by scamper, a tool for performing large-scale traceroute- and
ping-based network measurements (see http://www.wand.net.nz/scamper/).
This extension will be useful to network researchers, operators, and users
who need to analyze or process warts files.
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
  gem_name = "rb-wartslib-#{MY_VERSION}.gem"
  File.delete gem_name if File.exists? gem_name
  Gem::Builder.new(spec).build

  tar_name = "rb-wartslib-#{MY_VERSION}.tar"
  puts "creating #{tar_name}.gz"
  File.delete tar_name if File.exists? tar_name
  File.delete "#{tar_name}.gz" if File.exists? "#{tar_name}.gz"
  tar_contents = MY_FILES.join(" ")
  system "tar cf #{tar_name} #{tar_contents}"
  system "gzip -9 #{tar_name}"
end
