
Pod::Spec.new do |s|

  s.name         = "WBBlades"
      s.version="11.2.0"
  s.summary      = "WBBlades"
  s.homepage     = "http"

  s.description  = <<-DESC
                    WBBlades
                   DESC

  s.license      = {
    :type => 'license',
    :text => <<-LICENSE

    LICENSE
  }
  s.header_dir = 'WBBlades'
  s.authors      = "WBBlades"
  s.platform            = :macos, "10.15"
  s.requires_arc        = true
  s.source              = { :git => "xxx@xxx.xxx.com:xxx/xxx.git" , :branch => "#{s.version}"}
  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/WBBlades",
    'DEFINES_MODULE' => 'YES'
}
  s.subspec 'Capstone' do |capstone|
    capstone.source_files       = 'Capstone/**/*.{h,m,mm,swift,c,cc,cpp}'
    capstone.private_header_files ='Capstone/**/*.{h}'
    capstone.xcconfig = {'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) CAPSTONE_HAS_ARM64=1'}
    capstone.requires_arc = true
   end
  s.subspec 'Link' do |link|
      link.source_files       = 'Link/**/*.{h,m,mm,swift,c,cc,cpp}'
      link.requires_arc = true
   end
  s.subspec 'Model' do |model|
     model.source_files       = 'Model/**/*.{h,m,mm,swift,c,cc,cpp}'
     model.requires_arc          = true
   end
  s.subspec 'Scan' do |scan|
    scan.source_files       = 'Scan/**/*.{h,m,mm,swift,c,cc,cpp}'
    scan.requires_arc          = true
   end
  s.subspec 'Tools' do |tools|
    tools.source_files       = 'Tools/**/*.{h,m,mm,swift,c,cc,cpp}'
    tools.private_header_files = "Tools/WBBladesTool.h"
    tools.requires_arc          = true
   end
  s.subspec 'ClassDump' do |classdump|
    classdump.source_files       = 'ClassDump/**/*.{h,m,mm,swift,c,cc,cpp}'
    classdump.requires_arc          = true
   end
#  s.private_header_files = "WBBlades/WBBlades/Tools/WBBladesTool.h"
  s.dependency  'WBBladesCrash'
end
