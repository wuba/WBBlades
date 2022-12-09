//
//  BladesUnusedClassCheckViewController.swift
//  WBBladesCrashApp
//
//  Created by wbblades on 2022/4/12.
//

import Cocoa
import WBBlades
import WBBladesCrash

class BladesUnusedClassCheckViewController: NSViewController {

    @IBOutlet weak var appPathTextField: NSTextField!
    @IBOutlet var resultLogTextView: NSTextView!
    @IBOutlet weak var selectedLibPathTextField: NSTextField!
    @IBOutlet var selectedLibPathTextView: NSTextView!
    
    @IBOutlet weak var progressTipsLabel: NSTextField!
    
    @IBOutlet weak var specifiedLibDescLabel: NSTextField!
    @IBOutlet weak var specfiedLibDescLabel2: NSTextField!
    @IBOutlet weak var startCheckButton: SYFlatButton!
    @IBOutlet weak var unusedClassCheckTitleLabel: NSTextField!
    @IBOutlet weak var resetButton: SYFlatButton!
    
    @IBOutlet weak var helpLinkBtn: SYFlatButton!
    @IBOutlet weak var helpIconBtn: NSButton!
    
    var unUsedClassResultSet: Array<Dictionary<String,NSNumber>>!
    var selectedLibPathsArray: Array<String> = [] //用户指定的lib库路径
    var selectedLibNames: String = "" //用于展示到界面上的lib名称
    var scaning: Bool? //当前是否正在检测中
    
    override func viewDidLoad() {
        super.viewDidLoad()

        self.setBackgroudColor(color: .init(red: CGFloat(247)/CGFloat(255), green: CGFloat(247)/CGFloat(255), blue: CGFloat(247)/CGFloat(255), alpha: 0.8))
        
        appPathTextField.placeholderString = TextDictionary.valueForKey(key: "unusedClassPathPlaceholder")
        startCheckButton.title = TextDictionary.valueForKey(key: "unusedClassStartButton")
        unusedClassCheckTitleLabel.stringValue = TextDictionary.valueForKey(key: "unusedClassCheckTitle")
        if TextDictionary.mode == Language.english {
            selectedLibPathTextField.placeholderString = TextDictionary.valueForKey(key: "unusedClassLibPathPlaceholder")
            specifiedLibDescLabel.stringValue = TextDictionary.valueForKey(key: "specifiedLibPathDesc1")
            specfiedLibDescLabel2.stringValue = TextDictionary.valueForKey(key: "specifiedLibPathDesc2")
        }
        resetButton.title = TextDictionary.valueForKey(key: "unusedClassResetBtn")
        
        helpLinkBtn.isHidden = true
        helpIconBtn.isHidden = true
        appPathTextField.showTextFieldBoarder()
        selectedLibPathTextField.showTextFieldBoarder()
        selectedLibPathTextView.showTextViewBoarder()
        resultLogTextView.showTextViewBoarder()
        
        WBBladesInterface.shareInstance().addObserver(self, forKeyPath: "unusedClassInfos", options: .new, context: nil)
        DispatchQueue.main.async {
            self.appPathTextField.becomeFirstResponder()
        }
    }
    
    @IBAction func goback(_ sender: Any) {
        self.goBack()
    }
    
    @IBAction func beginScanUnusedClass(_ sender: Any) {
        guard let appPath = appPathTextField?.stringValue, appPath.count > 0,!appPath.contains(" ") else {
            return
        }
        progressTipsLabel.stringValue = TextDictionary.valueForKey(key: "unusedClassState")
        scaning = true
        resultLogTextView.string = "";
        helpLinkBtn.isHidden = true
        helpIconBtn.isHidden = true
        
        DispatchQueue.global().async {
            //开始扫描无用类
            self.unUsedClassResultSet = WBBladesInterface.scanUnusedClass(withAppPath: appPath, fromLibs: self.selectedLibPathsArray)
            //检测完成
            self.scaning = false
            DispatchQueue.main.async {
                //扫描完成，处理显示结果
                var allUnusedClsStr = ""
                var unusedCount = 0
                for dict in self.unUsedClassResultSet {
                    for (key ,_) in dict {
                        allUnusedClsStr += "\(key)"
                        allUnusedClsStr += "\n"
                    }
                    unusedCount += dict.count
                    allUnusedClsStr += "\n"
                }
                                                
                if TextDictionary.mode == Language.chinese {
                    self.resultLogTextView.string = self.resultLogTextView.string+"\n\n"+"检测到的无用类：\n"+allUnusedClsStr;
                    self.progressTipsLabel.stringValue = "已检测出\(unusedCount)个无用类"
                } else {
                    self.resultLogTextView.string = self.resultLogTextView.string+"\n\n"+"Analysed unused class：\n"+allUnusedClsStr;
                    self.progressTipsLabel.stringValue = "Have analysed\(unusedCount) unused class"
                }
                
                self.helpLinkBtn.isHidden = false
                self.helpIconBtn.isHidden = false
            }
        }
    }
    
    @IBAction func addSlectedLibPathAction(_ sender: Any) {
        guard let libpath = selectedLibPathTextField?.stringValue, libpath.count > 0 else {
            return
        }
        //保存lib完整路径
        selectedLibPathsArray.append(libpath)
        
        //获取lib名称
        let libName = URL(string: libpath)?.lastPathComponent ?? ""
        if selectedLibNames.count > 0 {
            selectedLibNames += ","
        }
        selectedLibNames += libName
        selectedLibPathTextView.string = selectedLibNames
        
        //清空静态库选择框
        selectedLibPathTextField.stringValue = ""
    }
    
    @IBAction func resetButtonDidClick(_ sender: Any) {
        appPathTextField.stringValue = ""
        
        selectedLibPathsArray = [];
        selectedLibPathTextField.stringValue = ""
        selectedLibNames = ""
        selectedLibPathTextView.string = ""
        
        self.resultLogTextView.string = ""
        self.progressTipsLabel.stringValue = ""
        
        helpLinkBtn.isHidden = true
        helpIconBtn.isHidden = true
    }
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard let obj = object as? WBBladesInterface else {
            return
        }
        if let scan = scaning, !scan {
            return
        }
        if let content = obj.unusedClassInfos {
            DispatchQueue.main.async {
                self.resultLogTextView.string = content
            }
        }
    }
    
    @IBAction func helpLinkBtnClick(_ sender: Any) {
        NSWorkspace.shared.open(URL(string:"https://github.com/wuba/WBBlades")!)
    }
    
    deinit {
        WBBladesInterface.shareInstance().removeObserver(self, forKeyPath: "unusedClassInfos")
        WBBladesInterface.shareInstance().unusedClassInfos = ""
    }
}
