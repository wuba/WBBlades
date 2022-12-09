//
//  BladesAutoHookViewController.swift
//  WBBladesCrashApp
//
// Created by 竹林七闲 on 2022/10/9.
//

import Cocoa
import WBBlades

class BladesAutoHookViewController: NSViewController {
    var resultPath = ""
    var MachOName = ""

    @IBOutlet weak var openBtn: SYFlatButton!
    @IBOutlet weak var startButton: SYFlatButton!
    @IBOutlet weak var librayPathTextFiled: NSTextField!
    @IBOutlet var librarySizeTextView: NSTextView!
    @IBOutlet weak var resultTipsView: NSTextField!
    @IBAction func goBack(_ sender: Any) {
        WBBladesInterface.endAutoHookProcess()
        self.goBack()
    }

    @IBAction func startAnalzing(_ sender: Any) {

        if librayPathTextFiled.stringValue.count > 0 {
            let librayPath = librayPathTextFiled.stringValue
            self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "Analysis")
            self.openBtn.alphaValue = 0;
            MachOName = librayPath.components(separatedBy: "/").last ?? ""
            WBBladesInterface.autoHook(byInputPaths: librayPath)
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.window?.makeFirstResponder(librarySizeTextView)
        // Do view setup here.
        self.resultTipsView.stringValue = TextDictionary.valueForKey(key: "startDetectMachO")
        librayPathTextFiled.placeholderString = TextDictionary.valueForKey(key: "MachOText")


        self.startButton.title = TextDictionary.valueForKey(key: "startButtonNormal")
        self.openBtn.title = TextDictionary.valueForKey(key: "open")
        self.openBtn.alphaValue = 0
        WBBladesInterface.shareInstance().addObserver(self, forKeyPath: "autoHookInfos", options: .new, context: nil)
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
        if let content = obj.autoHookInfos {
            DispatchQueue.main.async {
                self.librarySizeTextView.string = content
                self.librarySizeTextView.scrollToEndOfDocument(nil)
                if obj.autoHookFinished {
                    self.openBtn.alphaValue = 1
                    var outPutPath = NSSearchPathForDirectoriesInDomains(.desktopDirectory, .userDomainMask, true).first!
                    outPutPath.append("/WBBladers-RuntimeProject")
                    if self.MachOName.count > 0 {
                        outPutPath.append("/\(self.MachOName)")
                    }
                    self.resultTipsView.stringValue = outPutPath
                }
            }
        }
    }

    deinit {
        WBBladesInterface.shareInstance().removeObserver(self, forKeyPath: "autoHookInfos")
        WBBladesInterface.shareInstance().autoHookInfos = ""
    }

    @IBAction func openSaveFile(_ sender: Any) {
        var outPutPath = NSSearchPathForDirectoriesInDomains(.desktopDirectory, .userDomainMask, true).first!
        outPutPath.append("/WBBladers-RuntimeProject")
        if MachOName.count > 0 {
            outPutPath.append("/\(MachOName)")
        }
        let fileURL = URL(fileURLWithPath: outPutPath)
        NSWorkspace.shared.open(fileURL)
    }
    
}
