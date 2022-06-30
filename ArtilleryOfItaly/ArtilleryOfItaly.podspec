Pod::Spec.new do |s|
  s.name                = "ArtilleryOfItaly"
  s.version = "1.0"
  s.summary             = "ArtilleryOfItaly"
  s.description         = <<-DESC
                            xxxxxx
                         DESC
  s.homepage            = "ArtilleryOfItaly.git"
  s.source              = { :git => "ArtilleryOfItaly.git" , :branch => "#{s.version}"}
  s.license             = {
                        :type => 'license',
                        :text => <<-LICENSE

                        LICENSE
  }
  s.author              = ""
  s.requires_arc        = true
  s.platform            = :macos, "10.15"
  s.libraries           = "z"

  s.resources = "ArtilleryOfItaly/ArtilleryOfItaly/Info.plist"
  s.source_files = 'ArtilleryOfItaly/ArtilleryOfItaly/*.{h,m}','ArtilleryOfItaly/ArtilleryOfItaly/Header Files/*.{h}','ArtilleryOfItaly/ArtilleryOfItaly/Source Files/*.{c}'
#  s.vendored_library  = 'ArtilleryOfItaly/ArtilleryOfItaly/libdwarf.a'

  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/WBBrightMirror",
    #'DEFINES_MODULE' => 'YES'

  }

end
