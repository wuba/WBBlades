//
//  HelpViewManager.swift
//  WBBladesCrashProject
//
//  Created by wbblades on 2021/5/28.
//

import Cocoa

enum HelpType: Int {
    case MainPage = 0
    case SystemCrash = 1
    case BuglyCrash = 2
    case BuglyTop = 3
}

class HelpViewManager{
    
    static var helpWindow: NSWindowController?
    
    class func openMainPageHelpView() {
        creatHelpViewController()
        
        guard let helpVC = helpWindow?.contentViewController as? HelpViewController else {
            return
        }
        helpVC.selectTabAndScrollTo(selectTab: .MainPage, buglyHelpType: .unknown)
    }
    
    class func openSystemCrashHelpView() {
        creatHelpViewController()
        
        guard let helpVC = helpWindow?.contentViewController as? HelpViewController else {
            return
        }
        helpVC.selectTabAndScrollTo(selectTab: .SystemCrash, buglyHelpType: .unknown)
    }
    
    class func openBuglyHelpView(type:HelpBuglyItemType) {
        creatHelpViewController()
        
        guard type != .unknown else {
            return
        }
        
        guard let helpVC = helpWindow?.contentViewController as? HelpViewController else {
            return
        }
        helpVC.selectTabAndScrollTo(selectTab: .BuglyCrash, buglyHelpType: type)
    }
    
    class func openBuglyTopHelpView() {
        creatHelpViewController()
        
        guard let helpVC = helpWindow?.contentViewController as? HelpViewController else {
            return
        }
        helpVC.selectTabAndScrollTo(selectTab: .BuglyTop, buglyHelpType: .unknown)
    }
    
    class func creatHelpViewController(){
        if helpWindow != nil {
            helpWindow?.window?.center()
            helpWindow?.window?.orderFront(nil)
            return
        }
        
        let vcWindow = NSStoryboard.main?.instantiateController(withIdentifier: "HelpWindowController") as? NSWindowController
        vcWindow?.window?.center()
        vcWindow?.window?.orderFront(nil)
        vcWindow?.showWindow(nil)
        helpWindow = vcWindow
    }
}
