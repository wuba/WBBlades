Pod::Spec.new do |s|
  s.name                = "WBBladesCrash"
  s.version = "1.0"
  s.summary             = "WBBladesCrash"
  s.description         = <<-DESC
                            xxxxxx
                         DESC
  s.homepage            = "WBBladesCrash.git"
  s.source              = { :git => "WBBladesCrash.git" , :branch => "#{s.version}"}
  s.license             = {
                        :type => 'license',
                        :text => <<-LICENSE

                        LICENSE
  }
  s.author              = "58tongcheng"
  s.requires_arc        = true
  s.platform            = :macos, "10.15"


  s.resources = "WBBladesCrash/Resource/*"
  s.source_files = 'WBBladesCrash/*.{swift,h}','WBBladesCrash/**/*.{swift}'
  # s.vendored_frameworks  = 'WBBladesCrash/ThirdParty/Alamofire/*.framework'
  # s.exclude_files = ""

  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/WBBladesCrash",
    'DEFINES_MODULE' => 'YES'

  }

  s.module_name = 'WBBladesCrash'
  s.swift_versions = ['5.0', '5.1', '5.2','5.3']
end
