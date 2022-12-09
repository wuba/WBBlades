
Pod::Spec.new do |s|

  s.name         = "WBAppSize"
      s.version="11.2.0"
  s.summary      = "WBAppSize"
  s.homepage     = "http"

  s.description  = <<-DESC
                    WBAppSize
                   DESC

  s.license      = {
    :type => 'license',
    :text => <<-LICENSE

    LICENSE
  }
  s.header_dir = 'WBAppSize'
  s.authors      = "WBAppSize"
  s.platform            = :macos, "10.15"
  s.requires_arc        = true
  s.source              = { :git => "xxx@xxx.xxx.com:xxx/xxx.git" , :branch => "#{s.version}"}
  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/WBAppSize",
}
  s.resources    = '**/*.{bundle,xcassets,plist,json,xib}'
  s.source_files = '**/*.{h,m,mm,c,cc,cpp,swift}'
  s.swift_versions = ['5.0', '5.1', '5.2', '5.3']
#  s.private_header_files = "WBBlades/WBBlades/Tools/WBBladesTool.h"
   s.dependency  'WBBlades'
end
