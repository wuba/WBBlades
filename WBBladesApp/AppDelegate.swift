//
//  AppDelegate.swift
//  WBBrightMirrorProject
//
//  Created by 朴惠姝 on 2021/4/22.
//

import Cocoa
import WBBrightMirror

@main
class AppDelegate: NSObject, NSApplicationDelegate {




    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            let windows = sender.windows
            if windows.count > 0 {
                let window = windows[0]
                window.makeKeyAndOrderFront(self)
            }
        }
        return true
    }
    
    //MARK:-
    //MARK:Menu
    @IBAction func cleanAllCache(_ sender: Any) {
        WBBrightMirrorManager.cleanAllCache()
        UserDefaults.standard.removeObject(forKey: kInputProcessCacheKey)
        UserDefaults.standard.removeObject(forKey: kInputUUIDCacheKey)
        
        let windows = NSApplication.shared.windows
        var window: NSWindow?
        if windows.count > 0 {
            for wins in windows.reversed() {
                if wins.className != "NSMenuWindowManagerWindow" {
                    window = wins
                    break;
                }
            }
        }
        
        guard let curWindow = window else {
            return
        }
        
        let tips = NSTextField()
        tips.stringValue = "缓存已清除完毕！"
        tips.isBordered = false
        tips.backgroundColor = NSColor.init(red: 0, green: 0, blue: 0, alpha: 0.6)
        tips.textColor = .white
        tips.alignment = .center
        tips.frame = NSMakeRect((curWindow.contentView?.frame.size.width ?? 300 - 180)*0.5, 20.0, 180, 20)
        curWindow.contentView?.addSubview(tips)
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0, execute:{
            tips.removeFromSuperview()
        })
    }
    
    @IBAction func helpClicked(_ sender: Any) {
        HelpViewManager.openMainPageHelpView()
    }
    
}

