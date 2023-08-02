//
//  IntelligentReadmeViewController.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/5/30.
//

import Cocoa
import WBBlades
import AppKit

class IntelligentReadmeViewController: NSViewController {
    private var gptAPI = GPTRequestService()
    public var isConnectingGPT = false {
        willSet {
            if (newValue) {
                self.networkView.isHidden = false
                self.networkView.startAnimation(nil)
                self.sendBtn.isHidden = true

            }
            else {
                self.networkView.isHidden = true
                self.networkView.stopAnimation(nil)
                self.sendBtn.isHidden = false
            }
        }
        didSet {
            // oldValue
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
        self.msgTableView.scrollRowToVisible(gptAPI.historyList.count - 1)
        self.inputText.delegate = self
        self.sendBtn.isEnabled = false
        self.inputTextBgView.wantsLayer = true
        self.inputTextBgView.layer?.backgroundColor = NSColor.white.cgColor
        self.inputTextBgView.layer?.cornerRadius = 8
        self.inputTextBgView.layer?.masksToBounds = true
        self.inputText.font = NSFont.systemFont(ofSize: 14)
        self.inputText.placeholder = "说点什么..."
        self.inputText.contentHeightChange = { [weak self] height in
            guard let self = self else { return }
            self.inputHeightConstraints.constant = height
        }
        
        let notificationName = NSNotification.Name("SETGPTAPIKEYSUCCESS")
        NotificationCenter.default.addObserver(forName: notificationName, object: nil, queue: nil) { [weak self] (notification) in
            guard let self = self else { return }
            self.gptAPI = GPTRequestService()
            self.msgTableView.reloadData()
        }
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    override func viewDidAppear() {
        super.viewDidAppear()
        // 未设置 GPT_API_KEY, 弹窗提示设置
        if gptAPI.apiKey().isEmpty {
            showInputGPTTokenWindow()
        }
    }
    
    private func showInputGPTTokenWindow() {
        GPTTokenWindowManager.share.show()
    }
    
    @IBAction func goBack(_ sender: Any) {
        WBBladesInterface.endAutoHookProcess()
        self.goBack()
    }
    
    @IBOutlet weak var networkView: NSProgressIndicator!
    @IBOutlet weak var sendBtn: NSButton!
    @IBOutlet weak var inputTextBgView: NSView!
    @IBOutlet weak var inputText: GPTMessageTextView!
    @IBOutlet weak var inputHeightConstraints: NSLayoutConstraint!
    @IBOutlet weak var msgTableView: NSTableView!
    @IBAction func goback(_ sender: Any) {
        self.goBack()
    }
    @IBAction func sendBtnPressed(_ sender: Any) {
        guard !gptAPI.apiKey().isEmpty else {
            showInputGPTTokenWindow()
            return
        }
        guard !isConnectingGPT else {
            return
        }
        self.sendBtn.isEnabled = false
        let userText: String = inputText.string
        gptAPI.appendToHistoryList(userText: userText)
        self.msgTableView.reloadData()
        self.msgTableView.scrollRowToVisible(gptAPI.historyList.count - 1)
        Task { @MainActor in
            inputText.string = ""
            if (!userText.isEmpty) {
                self.isConnectingGPT = true
                var responText: String = ""
                var errorText: String? = nil
                do {
                    responText = try await gptAPI.sendMessage(text: userText, isChatMsg: true)
                }
                catch {
                    errorText = error as? String
                    if (errorText == nil) {
                        errorText = error.localizedDescription
                    }
                }
                gptAPI.appendToHistoryList(responseText: responText, errorText: errorText)
                self.isConnectingGPT = false
                self.msgTableView.reloadData()
                self.msgTableView.scrollRowToVisible(gptAPI.historyList.count - 1)
            }
        }
    }
    
    
}
    // MARK: -  Table View Delegate & Datasource
extension IntelligentReadmeViewController: NSTableViewDelegate, NSTableViewDataSource {
    
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let MSGCELLID = NSUserInterfaceItemIdentifier.init(rawValue: "GPTMSGCELLID")
        var cellView = tableView.makeView(withIdentifier: MSGCELLID, owner: nil) as? GPTMessageCell
        if cellView == nil {
            cellView = GPTMessageCell.createFromNib()
            cellView?.identifier = MSGCELLID
        }
        let item = gptAPI.historyList[row]
        cellView?.configCellView(model: item )
        return cellView
    }
    func numberOfRows(in tableView: NSTableView) -> Int {
        return gptAPI.historyList.count
    }
    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        var model = gptAPI.historyList[row]
        return model.textHeight + 40
    }
    
}
extension IntelligentReadmeViewController: NSOutlineViewDelegate, NSOutlineViewDataSource {
    public func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        let MSGCELLID = NSUserInterfaceItemIdentifier.init(rawValue: "GPTMSGCELLID")
        var cellView = outlineView.makeView(withIdentifier: MSGCELLID, owner: nil) as? GPTMessageCell
        if cellView == nil {
            cellView = GPTMessageCell.createFromNib()
            cellView?.identifier = MSGCELLID
        }
        cellView?.configCellView(model: item as! Message)
        return cellView
    }
        
    public func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        return gptAPI.historyList.count
    }
    
    public func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        if item == nil {
            return gptAPI.historyList[index]
        }
        return item as! Message
    }
        
    public func outlineView(_ outlineView: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
        var model = item as! Message
        return model.textHeight + 40
    }
}

extension IntelligentReadmeViewController: NSTextViewDelegate {
    
    func textView(_ textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if (commandSelector == #selector(insertNewline(_:))) {
            let text = textView.string
            if (!text.isEmpty) {
                self.sendBtnPressed(self.sendBtn!)
            }
            return true
        }
        return false
    }

    func textViewDidChangeSelection(_ notification: Notification) {
        guard let textView = notification.object as? NSTextView,
              textView === self.inputText else {
            return
        }
        let text = inputText.string
        if (!text.isEmpty) {
            self.sendBtn.isEnabled = true
        }
        else {
            self.sendBtn.isEnabled = false
        }
    }
    
}
        
