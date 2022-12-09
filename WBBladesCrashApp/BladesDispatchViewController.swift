//
//  BladesDispatchViewController.swift
//  WBBladesCrashApp
//
//  Created by 竹林七闲 on 2022/4/11.
//

import Cocoa
import WBAppSize
class BladesDispatchViewController: NSViewController {

    @IBOutlet weak var welcomeLabel: NSTextField!
    @IBOutlet var introduceTextView: NSTextView!
    @IBOutlet weak var functionLabel: NSTextField!
    @IBOutlet weak var githubStarBtn: SYFlatButton!
    @IBOutlet weak var unusedClassBtn: SYFlatButton!
    @IBOutlet weak var libarySizeBtn: SYFlatButton!
    @IBOutlet weak var crashParseBtn: SYFlatButton!
    @IBOutlet weak var libarayDependency: SYFlatButton!
    @IBOutlet weak var languageChangeBtn: NSPopUpButton!
    @IBOutlet weak var diagnoseBtn: SYFlatButton!
    @IBOutlet weak var cleanCacheBtn: SYFlatButton!
    var imageView: NSImageView?
    var backGroundView: NSView?
    override func viewDidLoad() {

        // Do view setup here.
        super.viewDidLoad()
        diagnoseBtn.title = TextDictionary.valueForKey(key: "diagnoseBtnTitle")
        unusedClassBtn.title = TextDictionary.valueForKey(key: "unusedClassBtnTitle")
        libarySizeBtn.title = TextDictionary.valueForKey(key: "libarySizeBtnTitle")
        crashParseBtn.title = TextDictionary.valueForKey(key: "crashParseBtnTitle")
        libarayDependency.title = TextDictionary.valueForKey(key: "libarayDependencyTitle")
        functionLabel.stringValue = TextDictionary.valueForKey(key: "functionLabelTitle")
        introduceTextView.string = TextDictionary.valueForKey(key: "introduceTextViewTitle")
        welcomeLabel.stringValue = TextDictionary.valueForKey(key: "welcome")
        githubStarBtn.title = TextDictionary.valueForKey(key: "gitHub")
        languageChangeBtn.removeAllItems()
        languageChangeBtn.addItems(withTitles: ["English","中文"])
        if TextDictionary.mode == .chinese{
            languageChangeBtn.selectItem(at: 1)
        }
        self.setBackgroudColor(color:.init(red: CGFloat(247)/CGFloat(255), green: CGFloat(247)/CGFloat(255), blue: CGFloat(247)/CGFloat(255), alpha: 1.0))
    }
    
    override func viewDidAppear() {
        super.viewDidAppear()
                
        let cacheSize = Int(cacheFileSize())
        cleanCacheBtn.isHidden = cacheSize <= 1//<=1M,不展示清除缓存按钮
        if !cleanCacheBtn.isHidden {
            if(cacheSize < 1024) {
                cleanCacheBtn.title = "清理缓存\(cacheSize)M"
            }else {
                cleanCacheBtn.title = "清理缓存\(cacheSize/1024)G"
            }
        }
    }
    
    @IBAction func libraryParseBegin(_ sender: Any) {
        self.view.window?.contentViewController = BladesLibrarySizeViewController()
    }

    @IBAction func crashParseBegin(_ sender: Any) {
        self.view.window?.contentViewController = NSStoryboard.main?.instantiateController(withIdentifier: NSStoryboard.SceneIdentifier("ViewController")) as? NSViewController
    }
    
    @IBAction func unusedClassCheck(_ sender: Any) {
        self.view.window?.contentViewController = BladesUnusedClassCheckViewController()
    }

    @IBAction func dependencyLibsCheck(_ sender: Any) {
        let vc = BladesLibrarySizeViewController()
        vc.type = .dependency
        self.view.window?.contentViewController = vc
    }

    @IBAction func autoHookBegin(_ sender: Any) {
        let vc = BladesAutoHookViewController()
        self.view.window?.contentViewController = vc
    }

    @IBAction func diagnosePackage(_ sender: Any) {
        let vc = WBAppSize.AppSizeDiagnoseVC()
        self.view.window?.contentViewController = vc
    }

    
    @IBAction func githubStarBegin(_ sender: Any) {
        NSWorkspace.shared.open(URL(string:"https://github.com/wuba/WBBlades")!)
    }

    @IBAction func languageChangeClicked(_ sender: NSPopUpButton) {
        let itemIndex = sender.indexOfSelectedItem
        if itemIndex == 0{
            TextDictionary.mode = .english
        }else{
            TextDictionary.mode = .chinese
        }

        self.goBack()
    }
    
    @IBAction func cleanCacheBtnDidClick(_ sender: Any) {
        let cacheSize = Int(cacheFileSize())
        var cacheDesc = ""
        if(cacheSize < 1024) {
            cacheDesc = "\(cacheSize)M"
        }else {
            cacheDesc = "\(cacheSize/1024)G"
        }


        let alert:NSAlert = NSAlert()
        alert.messageText = "确认清理缓存文件(\(cacheDesc))？"
        alert.addButton(withTitle: "自动清理")
        alert.addButton(withTitle: "手动清理")
        alert.addButton(withTitle: "取消")
        
        let response = alert.runModal()
        if response == NSApplication.ModalResponse.alertFirstButtonReturn {
            let desktopDirectory = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true)[0]
            let deskCahcePath = desktopDirectory + "/wbbladestmp"
            let filemanager = FileManager.default
            if filemanager.fileExists(atPath: deskCahcePath) {
                do{
                    let deskCahcePathURL = NSURL.fileURL(withPath: deskCahcePath)
                    try filemanager.removeItem(at: deskCahcePathURL)
                    cleanCacheBtn.title = "已清理缓存"
                }catch {
                }
            }
        }else if (response == NSApplication.ModalResponse.alertSecondButtonReturn) {
            let desktopDirectory = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true)[0]
            let deskCahcePath = desktopDirectory + "/wbbladestmp"
            let fileURL = URL(fileURLWithPath: deskCahcePath)
            NSWorkspace.shared.open(fileURL)
        }
    }
    
    func cacheFileSize() -> CGFloat {
        let desktopDirectory = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.desktopDirectory, FileManager.SearchPathDomainMask.userDomainMask, true)[0]
        let deskCahcePath = desktopDirectory + "/wbbladestmp"
        let folderpath = deskCahcePath as NSString
        
        let filemanager = FileManager.default
        if filemanager.fileExists(atPath: deskCahcePath) {
            let childFolderList:[String] = filemanager.subpaths(atPath: deskCahcePath) ?? []
            var folderSize: UInt64 = 0
            for (_,fileName) in childFolderList.enumerated() {
                let fileAbsolutePath = folderpath.strings(byAppendingPaths: [fileName])
                folderSize += fileSize(filePath: fileAbsolutePath[0])
            }
            return CGFloat(folderSize)/(1024.0*1024.0)
        }
        return 0.0
    }
    
    func fileSize(filePath:String) -> UInt64 {
        let filemanager = FileManager.default
        if filemanager.fileExists(atPath: filePath) {
            do {
                let attr = try filemanager.attributesOfItem(atPath: filePath)
                let size = attr[FileAttributeKey.size] as! UInt64
                return size
            } catch {
                return 0
            }
        }
        return 0
    }
}
