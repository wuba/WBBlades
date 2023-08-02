//
//  GPTTokenViewController.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/6.
//

import Cocoa

class GPTTokenViewController: NSViewController {
    private let gptAPI = GPTRequestService()
    private var isConnectingGPT = false {
        willSet {
            if (newValue) {
                self.keyVerifyBtn.isHidden = true
                self.networkingView.isHidden = false
                self.networkingView.startAnimation(nil)

            }
            else {
                self.keyVerifyBtn.isHidden = false
                self.networkingView.isHidden = true
                self.networkingView.stopAnimation(nil)
            }
        }
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
        guard let keyStr = UserDefaults().value(forKey: "GPT_API_KEY") as? String else { return }
        gpt_apikey.stringValue = keyStr
        
    }
    
    @IBOutlet weak var gpt_apikey: NSSecureTextField!

    @IBOutlet weak var keyVerifyBtn: NSButton!
    @IBOutlet weak var networkingView: NSProgressIndicator!
        
    @IBOutlet var tipTextView: NSTextView!
    @IBAction func saveKey(_ sender: Any) {
        let text = gpt_apikey.stringValue
        UserDefaults().set(text, forKey: "GPT_API_KEY")
        self.isConnectingGPT = true
        Task { @MainActor in
            var errorText: String? = nil
            var responText: String = ""
            do {
                    responText = try await gptAPI.sendMessage(text: "", isChatMsg: false)
                }
            catch {
                errorText = error as? String
                if (errorText == nil) {
                    errorText = error.localizedDescription
                }
            }
            self.isConnectingGPT = false
            var tipText : String = "GPT API_KEY验证成功!"
            if (errorText != nil) {
                // 验证失败
                tipText = "GPT API_KEY验证失败!"
            }
            let alert = NSAlert()
            alert.addButton(withTitle: "确定")
            alert.messageText = tipText
            alert.beginSheetModal(for: self.view.window!) { [weak self] response in
                if response == .alertFirstButtonReturn, errorText == nil {
                    self?.closeWindow()
                    let notificationName = NSNotification.Name("SETGPTAPIKEYSUCCESS")
                    NotificationCenter.default.post(name: notificationName, object: nil)
                }
            }
        }
    }
    
    private func closeWindow() {
        GPTTokenWindowManager.share.close()
    }
}
