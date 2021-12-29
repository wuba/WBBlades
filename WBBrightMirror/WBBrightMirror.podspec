Pod::Spec.new do |s|
  s.name                = "WBBrightMirror"
  s.version = "1.0"
  s.summary             = "WBBrightMirror"
  s.description         = <<-DESC
                            xxxxxx
                         DESC
  s.homepage            = "git@igit.58corp.com:58_ios_team/WBBrightMirror.git"
  s.source              = { :git => "git@igit.58corp.com:58_ios_team/WBBrightMirror.git" , :branch => "#{s.version}"}
  s.license             = {
                        :type => '58license',
                        :text => <<-LICENSE

                        LICENSE
  }
  s.author              = "58tongcheng"
  s.requires_arc        = true
  s.platform            = :macos, "10.12"


  s.resources = "WBBrightMirror/Resource/*"
  s.source_files = 'WBBrightMirror/*.{swift,h}','WBBrightMirror/**/*.{swift}'
  # s.vendored_frameworks  = 'WBBrightMirror/ThirdParty/Alamofire/*.framework'
  # s.exclude_files = ""

  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => "${PODS_ROOT}/Headers/Public/WBBrightMirror",
    'DEFINES_MODULE' => 'YES'

  }

  s.module_name = 'WBBrightMirror'
  s.swift_versions = ['5.0', '5.1', '5.2','5.3']
end
