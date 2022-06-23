//
//  BladesLibrarySizeViewController.swift
//  WBBladesCrashApp
//
//  Created by 竹林七闲 on 2022/4/11.
//

import Cocoa
import WBBlades

enum DisplayType {
    case size
    case dependency
}
class BladesLibrarySizeViewController: NSViewController {
    var type: DisplayType = .size;
    var resultPath = ""

    @IBOutlet weak var openBtn: SYFlatButton!
    @IBOutlet weak var startButton: SYFlatButton!
    @IBOutlet weak var librayPathTextFiled: NSTextField!
    @IBOutlet var librarySizeTextView: NSTextView!
    @IBOutlet weak var resultTipsView: NSTextField!
    @IBAction func goBack(_ sender: Any) {
        self.goBack()
    }

    @IBAction func startAnalzing(_ sender: Any) {

        if librayPathTextFiled.stringValue.count > 0 {
            let librayPath = librayPathTextFiled.stringValue
            self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "Analysis")
            DispatchQueue.global().async {
                if self.type == .size {
                    WBBladesInterface.scanStaticLibrary(byInputPath: librayPath)
                    DispatchQueue.main.async {
                        self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "DetectFinish")
                        self.openBtn.alphaValue = 1
                    }
                }else if self.type == .dependency{
                    self.resultPath = WBBladesInterface.scanDependLibs(librayPath)
                    DispatchQueue.main.async {
                        if self.resultPath.count > 0{
                            let pre = TextDictionary.valueForKey(key: "AnalysisFinsh")
                            self.resultTipsView.stringValue = "\(pre)\(self.resultPath)"
                            self.openBtn.alphaValue = 1
                        }else{
                            self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "NoneDenpency")
                        }
                    }
                }
            }
        }

    }

    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.window?.makeFirstResponder(librarySizeTextView)
        // Do view setup here.
        self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "startDetect")
        switch (self.type){
        case .size:
            librayPathTextFiled.placeholderString = TextDictionary.valueForKey(key: "librayText")
            break
        case .dependency:
            librayPathTextFiled.placeholderString = TextDictionary.valueForKey(key: "librayText")
            break
        }

        self.startButton.title = TextDictionary.valueForKey(key: "startButtonNormal")
        self.openBtn.title = TextDictionary.valueForKey(key: "open")
        self.openBtn.alphaValue = 0
        WBBladesInterface.shareInstance().addObserver(self, forKeyPath: "libarySizeInfos", options: .new, context: nil)
        DispatchQueue.main.async {
            self.librayPathTextFiled.becomeFirstResponder()
        }
        self.setBackgroudColor(color:.init(red: CGFloat(247)/CGFloat(255), green: CGFloat(247)/CGFloat(255), blue: CGFloat(247)/CGFloat(255), alpha: 1.0))
        self.librayPathTextFiled.showTextFieldBoarder()
        self.librarySizeTextView.showTextViewBoarder()
    }

    override  func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        guard let obj = object as? WBBladesInterface else {
            return
        }
        if let content = obj.libarySizeInfos {
            DispatchQueue.main.async {
                self.librarySizeTextView.string = content
                self.librarySizeTextView.scrollToEndOfDocument(nil)
            }
        }
    }

    deinit {
        WBBladesInterface.shareInstance().removeObserver(self, forKeyPath: "libarySizeInfos")
        WBBladesInterface.shareInstance().libarySizeInfos = ""
    }

    @IBAction func openSaveFile(_ sender: Any) {
        if self.type == .dependency {
            NSWorkspace.shared.selectFile(resultPath, inFileViewerRootedAtPath: "")
            return
        }
        var outPutPath = NSSearchPathForDirectoriesInDomains(.desktopDirectory, .userDomainMask, true).first!
        outPutPath.append("/WBBladesResult.plist")
        let fileURL = URL(fileURLWithPath: outPutPath)
        NSWorkspace.shared.open(fileURL)
    }
}
