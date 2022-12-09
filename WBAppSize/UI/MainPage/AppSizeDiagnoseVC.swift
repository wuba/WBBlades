//
//  AppSizeDiagnoseVC.swift
//  AppSizeManager
//
//  Created by wbblades on 2022/2/28.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa
import WBBladesCrash

public class AppSizeDiagnoseVC: NSViewController, ItemSizeViewDelegate,DiagnoseCellDelegate,ChildCellDelegate {
    
    // UI数据
    var diagData : DiagnoseDataManager!
    // 色块列表
    var colorViewList : [NSView] = []
    // 色块对应的文案列表
    var typenameList : [NSTextField] = []
    @IBOutlet var sizeTitle: NSTextField!
    // 4个色块
    @IBOutlet weak var colorView0: NSView!
    @IBOutlet weak var colorView1: NSView!
    @IBOutlet weak var colorView2: NSView!
    @IBOutlet weak var colorView3: NSView!
    // 4个色块对应的文案
    @IBOutlet weak var typenameLabel0: NSTextField!
    @IBOutlet weak var typenameLabel1: NSTextField!
    @IBOutlet weak var typenameLabel2: NSTextField!
    @IBOutlet weak var typenameLabel3: NSTextField!
    // APP路径输入框
    @IBOutlet weak var filePathField: NSTextField!
    // 展示APP各模块的大小
    @IBOutlet weak var appsizeProfileView: NSView!
    
    @IBOutlet weak var diagSizeText: NSTextField!
    // 展示诊断结果
    @IBOutlet weak var diagResultOutlineView: NSOutlineView!
    /**
    点击诊断按钮
     */
    @IBOutlet var diagnoseBtn: NSButton!
    @IBAction func diagnose(_ sender: Any) {
        let appPath : String = self.filePathField.stringValue
        if appPath.isEmpty {
            let alert = NSAlert()
            alert.messageText = ASTextDictionary.valueForKey(key: "diagnoseAppPlaceHolder")
            alert.runModal()
            return
        }
        let loadingView = DiagnoseLoading.createFromNib()!
        loadingView.frame = self.view.bounds
        self.view.addSubview(loadingView)
        loadingView.autoresizingMask = [.height, .width]
        loadingView.startLoading()

        self.diagData.diagnoseApp(withApp: appPath) { hintStr in
            DispatchQueue.main.async {
                loadingView.showHintInfo(hint: hintStr)
            }
        } andFinishBlock: {
            DispatchQueue.main.async {
                //刷新UI
                loadingView.stopLoading()
                loadingView.removeFromSuperview()
                self.drawAppSizeProfile()
                self.diagResultOutlineView.reloadData()
                self.diagSizeText.stringValue = String(format: ASTextDictionary.valueForKey(key: "diagnoseResultMainTitle"), String(format: "%0.2fM", self.diagData.totalOptimSize))
            }
        }
    }

    override init(nibName nibNameOrNil:NSNib.Name?, bundle nibBundleOrNil:Bundle?) {
        super.init(nibName:nibNameOrNil, bundle:nibBundleOrNil)
        self.diagData = DiagnoseDataManager()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    public override func viewDidLoad() {
        super.viewDidLoad()
    
        self.sizeTitle.stringValue = ASTextDictionary.valueForKey(key: "packetSizeDistribution")
        self.filePathField.placeholderString = ASTextDictionary.valueForKey(key: "diagnoseAppPlaceHolder")
        self.diagnoseBtn.title = ASTextDictionary.valueForKey(key: "diagnoseStartBtnTitle")
        self.diagSizeText.stringValue = String(format: ASTextDictionary.valueForKey(key: "diagnoseResultMainTitle"), "0.0M")

        // Do view setup here.
        self.appsizeProfileView.wantsLayer = true;
        self.appsizeProfileView.layer?.backgroundColor = NSColor.fromHexString("3CFF7E")?.cgColor;
        self.filePathField.stringValue = ""

        colorViewList.append(colorView0)
        colorViewList.append(colorView1)
        colorViewList.append(colorView2)
        colorViewList.append(colorView3)
        typenameList.append(typenameLabel0)
        typenameList.append(typenameLabel1)
        typenameList.append(typenameLabel2)
        typenameList.append(typenameLabel3)
    }
    
    public override func updateViewConstraints() {
        super.updateViewConstraints()
        guard self.diagData.sizeItemList != nil else{
            return
        }
        self.drawAppSizeProfile()
    }
    
    public override func viewWillLayout() {
        super.viewWillLayout()
        guard self.diagData.sizeItemList != nil else{
            return
        }
        self.drawAppSizeProfile()
    }
    
    /**
     展示APP各模块大小数据
     */
    func drawAppSizeProfile() -> Void {
        let sizeItemList = self.diagData.sizeItemList
        let totalSize = self.diagData.totalSize
        var xStart : Double = 0
        let parentViewWidth = self.appsizeProfileView.frame.width
        for sizeView in self.appsizeProfileView.subviews {
            guard let sizeView = sizeView as? ItemSizeView else {
                continue
            }
            sizeView.removeFromSuperview()
        }
        for i in 0..<sizeItemList!.count {
            let sizeItem = sizeItemList?[i] ?? nil
            let sizeView = ItemSizeView.createFromNib()
            sizeView?.delegate = self;
            
            var width = 0.0
            if totalSize! > 0 {
                width = (CGFloat)((sizeItem?.itemSize ?? 0) * UInt(parentViewWidth)/totalSize!)
            }
            if let sizeView = sizeView as? ItemSizeView {
                sizeView.frame = NSRect.init(x: xStart, y: 0, width: width, height: self.appsizeProfileView.frame.height)
                sizeView.configItem(sizeItem: sizeItem!)
                let cv = colorViewList[i] as? NSView
                cv?.wantsLayer = true;
                cv?.layer?.backgroundColor = NSColor.fromHexString(sizeItem?.itemColor ?? "", alpha: 1)?.cgColor
                let tn = typenameList[i] as? NSTextField
                tn?.stringValue = String(format: "%@ %.2fM", sizeItem?.itemName ?? "", Double(sizeItem?.itemSize ?? 0)/1000000.0)
                self.appsizeProfileView.addSubview(sizeView)
            }
            xStart += width
        }
    }
    
    
    
    
    func itemSizeViewClicked(item: SizeProfileModel?)
    {
        let detailWC = ASFileListWindowController()
        detailWC.mainBundle = self.diagData.dataResult;
        detailWC.showWindow(nil)
    }
    
// MARK: -  DiagnoseCellDelegate
    func textMigrateConfig() {
        let tmwind = TextMigrateWindowController()
        tmwind.showWindow(nil)
    }
    
    func ltoConfig() {
        let tmwind = LTOOptimizeWindowController()
        tmwind.showWindow(nil)
    }
    
    func locationDirConfig(filePath: String) {
        NSWorkspace.shared.selectFile(filePath, inFileViewerRootedAtPath:"")
    }

    func stripConfig() {
        let tmwind = StripWindowController()
        tmwind.showWindow(nil)
    }
    
    func cellClicked(filePath: String) {
        NSWorkspace.shared.selectFile(filePath, inFileViewerRootedAtPath:"")
    }

}


// MARK: -  Table View Delegate & Datasource
    
extension AppSizeDiagnoseVC: NSOutlineViewDelegate, NSOutlineViewDataSource {
public func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        let FIRSTCELLID = NSUserInterfaceItemIdentifier.init(rawValue: "FirstCellID")
        let SECONDCELLID = NSUserInterfaceItemIdentifier.init(rawValue: "SECONDCellID")
        var cellView: (NSView & DiagCellProtocol)?
        if let item = item as? DiagnoseModel {
            if item.level == NodeType.First {
                cellView = outlineView.makeView(withIdentifier: FIRSTCELLID, owner: nil) as? NSView & DiagCellProtocol
                if cellView == nil {
                    cellView = DiagnoseItemCellView.createFromNib()
                    cellView?.identifier = FIRSTCELLID
                }
                if let cellView = cellView as? DiagnoseItemCellView {
                    cellView.delegate = self
                }
            } else {
                cellView = outlineView.makeView(withIdentifier: SECONDCELLID, owner: nil) as? NSView & DiagCellProtocol
                if cellView == nil {
                    cellView = ChildDiagnoseCellView.createFromNib()
                    cellView?.identifier = SECONDCELLID
                }
                if let cellView = cellView as? ChildDiagnoseCellView {
                    cellView.delegate = self
                }
            }
            cellView?.configCellView(model: item)
        }
        return cellView
    }
    
public   func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
       if item == nil {
           return self.diagData.diagnoseResult.count
       } else {
           if let item = item as? DiagnoseModel {
               return item.childModels?.count ?? 0
           }
       }
       return 0
    }
    
public    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        if let item = item as? DiagnoseModel {
            return item.childModels?.count ?? 0 > 0
        }
        return self.diagData.diagnoseResult.count > 0
    }
    
public    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        if item == nil {
            return self.diagData.diagnoseResult[index]
        }
        else {
            if let item = item as? DiagnoseModel {
                if item.childModels?.count ?? 0 >= index  {
                    return item.childModels?[index] as Any
                }
            }
        }
        return item as Any
    }
    
public    func outlineView(_ outlineView: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
        if let item = item as? DiagnoseModel {
            if item.level == NodeType.First {
                return 80
            } else {
                return 40
            }
        }
        return 80.0
    }
    
    @IBAction func goback(_ sender: Any) {
        self.goBack()
    }

}
    
