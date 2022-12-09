//
//  HelpViewController.swift
//  WBBladesCrashProject
//
//  Created by wbblades on 2021/5/28.
//

import Cocoa

enum HelpBuglyItemType {
    case unknown
    case process
    case startAddress
    case UUID
}

class HelpViewController: NSViewController {
    
    @IBOutlet weak var tabView: NSTabView!
    @IBOutlet weak var systemCrashScrollView: NSScrollView!
    @IBOutlet weak var buglyCrashScrollView: NSScrollView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Do any additional setup after loading the view.
        createSubViewWithPlistName(plistName: "SystemCrash", parentScrollView: systemCrashScrollView)
        createSubViewWithPlistName(plistName: "BuglyCrash", parentScrollView: buglyCrashScrollView)
    }
    
    func createSubViewWithPlistName(plistName: String, parentScrollView: NSScrollView) -> Void {
        let path = Bundle.main.path(forResource: plistName, ofType: "plist") ?? ""
        let plistArray = NSArray.init(contentsOfFile: path) as? Array<Dictionary<String,Any>> ?? []
        
        var y: CGFloat = parentScrollView.documentView?.frame.height ?? 0
        var subViewArray: Array<Dictionary <String,Any>> = []
        
        for item in plistArray{
            let type = item["type"] as? String
            if type == "text" {
                let title = item["title"] as? String ?? ""
                let content = item["content"] as? String ?? ""
                if title.count > 0 {
                    let label = NSTextField.init(labelWithString: title)
                    label.font = NSFont.boldSystemFont(ofSize: 17.0)
                    
                    let contentNSString = NSString.init(string: title)
                    let textSize = contentNSString.boundingRect(with: NSMakeSize(parentScrollView.frame.size.width-20.0*2, CGFloat(MAXFLOAT)), options: .usesLineFragmentOrigin, attributes:[NSAttributedString.Key.font:NSFont.boldSystemFont(ofSize: 17.0)])
                    y -= textSize.height
                    let model = ["width":textSize.width+10.0,
                                 "height":textSize.height,
                                 "view":label] as [String : Any]
                    subViewArray.append(model)
                }
                
                if content.count > 0 {
                    let label = NSTextField.init(labelWithString: content)
                    label.font = NSFont.systemFont(ofSize: 15.0)
                    label.lineBreakMode = .byCharWrapping
                    
                    let contentNSString = NSString.init(string: content)
                    let textSize = contentNSString.boundingRect(with: NSMakeSize(parentScrollView.frame.size.width-20.0*2, CGFloat(MAXFLOAT)), options: .usesLineFragmentOrigin, attributes:[NSAttributedString.Key.font:label.font ?? NSFont.systemFont(ofSize: 15.0)])
                    y -= textSize.height
                    let model = ["width":textSize.width+10.0,
                                 "height":textSize.height,
                                 "view":label] as [String : Any]
                    subViewArray.append(model)
                }
                
            }else if type == "image" {
                let content = item["content"] as? String ?? ""
                if content.count > 0 {
                    let width = item["width"] as? CGFloat ?? 0.0
                    let height = item["height"] as? CGFloat ?? 0.0
                    let newHeight = height*1.56
                    let imageView = NSImageView.init(image: NSImage.init(named: content) ?? NSImage.init())
                    y -= (15.0+newHeight)
                    let model = ["width":width*1.56,
                                 "height":15.0+newHeight,
                                "view":imageView] as [String : Any]
                    subViewArray.append(model)
                }
            }
            y -= 10.0
        }
        
        var scrollHeight = parentScrollView.frame.size.height
        if y < 0 {
            scrollHeight += abs(y)
        }
        parentScrollView.documentView?.setFrameSize(NSMakeSize(parentScrollView.frame.size.width, scrollHeight))
        
        for subView in subViewArray {
            let width = subView["width"] as? CGFloat ?? 0.0
            let height = subView["height"] as? CGFloat ?? 0.0
            let view = subView["view"] as? NSView ?? NSView.init()
            scrollHeight -= (height + 10.0)
            view.frame = NSMakeRect(20, scrollHeight, width, height)
            parentScrollView.documentView?.addSubview(view)
        }
        
        parentScrollView.documentView?.scroll(NSMakePoint(0, parentScrollView.documentView?.frame.size.height ?? 0.0))
    }
    
    func selectTabAndScrollTo(selectTab: HelpType, buglyHelpType: HelpBuglyItemType) -> Void {
        let tabIndex = selectTab.rawValue
        tabView.selectTabViewItem(at: tabIndex)
        
        switch tabIndex {
        case 1:
            systemCrashScrollView.contentView.scroll(NSMakePoint(0, systemCrashScrollView.documentView?.frame.size.height ?? 0.0))
            break
        case 2:
            if buglyHelpType == .process {
                buglyCrashScrollView.contentView.scroll(NSMakePoint(0, 950))
            }else if buglyHelpType == .startAddress {
                buglyCrashScrollView.contentView.scroll(NSMakePoint(0, 660))
            }else if buglyHelpType == .UUID {
                buglyCrashScrollView.contentView.scroll(NSMakePoint(0, 100))
            }else{
                buglyCrashScrollView.contentView.scroll(NSMakePoint(0, buglyCrashScrollView.documentView?.frame.size.height ?? 0.0))
            }
            break
        default:
            break
        }
    }
    
}
