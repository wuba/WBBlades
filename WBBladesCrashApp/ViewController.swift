//
//  ViewController.swift
//  WBBrightMirrorProject
//
//  Created by 朴惠姝 on 2021/4/22.
//

import Cocoa
import WBBrightMirror

let LogTextViewContentChanged:String = "TextViewContentChanged"
let kInputProcessCacheKey = "kInputProcessCacheKey"
let kInputUUIDCacheKey = "kInputUUIDCacheKey"

class ViewController: NSViewController,NSTextViewDelegate, NSTableViewDelegate,NSTableViewDataSource {
    
    @IBOutlet var logTextView: LogTextView!
    @IBOutlet weak var logTextViewOriginY: NSLayoutConstraint!
    @IBOutlet weak var startBtn: NSButton!
    
    @IBOutlet weak var progressView: NSProgressIndicator!
    @IBOutlet weak var loadingView: NSProgressIndicator!
    @IBOutlet weak var progressLabel: NSTextField!
    
    @IBOutlet weak var symbolTableTipLabel: NSTextField!
    @IBOutlet weak var symbolTablePathView: NSTextField!
    
    @IBOutlet weak var inputProcessView: NSView!
    @IBOutlet weak var inputBackgroundView: NSView!
    
    @IBOutlet weak var inputProcessField: NSTextField!
    @IBOutlet weak var inputProcessCacheBtn: NSButton!
    @IBOutlet weak var inputStartAddressField: NSTextField!
    @IBOutlet weak var inputUUIDField: NSTextField!
    @IBOutlet weak var inputUUIDCacheBtn: NSButton!
    
    var curLogModel: WBBMLogModel!
    var curSymbolTable: String!
    var anaTimer: Timer!
    lazy var inputCacheView: NSScrollView = {
        let tableview = NSTableView.init(frame: NSMakeRect(0, 0, 144.0, 70.0))
        tableview.wantsLayer = true
        tableview.delegate = self
        tableview.dataSource = self
        let column = NSTableColumn.init(identifier: NSUserInterfaceItemIdentifier(rawValue: "RowViewIden"))
        column.width = inputProcessField.frame.size.width
        column.title = "历史记录"
        tableview.addTableColumn(column)
        tableview.gridStyleMask = .solidHorizontalGridLineMask
        
        let tableScrollView = NSScrollView.init(frame: NSMakeRect(0, 0, 144.0, 70.0))
        tableScrollView.backgroundColor = NSColor.white
        tableScrollView.documentView = tableview
        tableScrollView.hasVerticalScroller = true
        tableScrollView.autohidesScrollers = true
        tableScrollView.wantsLayer = true
        tableScrollView.borderType = .lineBorder
        
        self.view.addSubview(tableScrollView)
        return tableScrollView
    }()
    var inputCacheArray: Array<String>!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        initAllSubviews()
        initNotification()
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }
    
    func initAllSubviews() -> Void {
        loadingView.isHidden = true
        logTextView.registerForDraggedTypes([.fileURL,.string])
        logTextView.delegate = self
        showSymbolTableView(show: false)
        showInputProcess(show: false)
    }
    
    func showInputProcess(show: Bool) -> Void {
        if show {
            logTextView.isEditable = false
            symbolTablePathView.isEditable = false
            startBtn.isEnabled = false
            inputProcessView.isHidden = false;
            inputProcessView.wantsLayer = true
            inputProcessView?.layer?.backgroundColor = NSColor.init(red: 0, green: 0, blue: 0, alpha: 0.5).cgColor
            inputBackgroundView.wantsLayer = true
            inputBackgroundView.layer?.backgroundColor = NSColor.init(red: 248.0/255.0, green: 248.0/255.0, blue: 255.0/255.0, alpha: 1.0).cgColor
            inputBackgroundView.layer?.cornerRadius = 10.0
            
            if let _ = UserDefaults.standard.object(forKey: kInputProcessCacheKey) {
                inputProcessCacheBtn.isHidden = false
            }else{
                inputProcessCacheBtn.isHidden = true
            }

            if let _ = UserDefaults.standard.object(forKey: kInputUUIDCacheKey) {
                inputUUIDCacheBtn.isHidden = false
            }else{
                inputUUIDCacheBtn.isHidden = true
            }
        }else{
            logTextView.isEditable = true
            symbolTablePathView.isEditable = true
            startBtn.isEnabled = true
            inputProcessView.isHidden = true;
            inputProcessField.stringValue = ""
            inputStartAddressField.stringValue = ""
            inputUUIDField.stringValue = ""
        }
        
    }
    
    func showSymbolTableView(show: Bool) -> Void {
        if show {
            symbolTableTipLabel.isHidden = false
            symbolTablePathView.isHidden = false
            symbolTablePathView.stringValue = ""
            logTextViewOriginY.constant = 60.0
            progressLabel.stringValue = "没有匹配到相应的符号表文件，您可以拖入本地的包含符号表的文件，支持.app，.dsym，.symbol文件"
        }else{
            symbolTableTipLabel.isHidden = true
            symbolTablePathView.isHidden = true
            logTextViewOriginY.constant = 20.0
        }
    }
    
    func showTips(tipString: String) -> Void {
        let tips = NSTextField()
        tips.stringValue = tipString
        tips.isBordered = false
        tips.backgroundColor = NSColor.init(red: 255.0/255.0, green: 48.0/255.0, blue: 48.0/255.0, alpha: 1.0)
        tips.textColor = .white
        tips.alignment = .center
        tips.frame = NSMakeRect((self.view.frame.size.width - 300)*0.5, 100.0, 300, 20)
        tips.wantsLayer = true
        tips.layer?.cornerRadius = 2.0
        self.view.addSubview(tips)
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0, execute:{
            tips.removeFromSuperview()
        })
    }
    
    func initNotification() -> Void {
        NotificationCenter.default.addObserver(self, selector: #selector(scanCurrentLog), name: .init(LogTextViewContentChanged), object: nil)
    }
    
   
    //MARK:-
    //MARK:Event
    @IBAction func startBtnClicked(_ sender: NSButton) {
        var selected = false
        if sender.state.rawValue == 1 {
            sender.title = "暂停"
            selected = true
        }else{
            sender.title = "开始"
        }
        
        guard canStartAnalyzing() == true else {
            sender.title = "开始"
            sender.state = .off
            self.progressLabel.textColor = NSColor.red
            return
        }

        guard curLogModel.processName.count > 0 else {
            return
        }
        
        self.progressLabel.textColor = NSColor.labelColor
        
        loadingView.isHidden = !selected
        if selected && curSymbolTable == nil{
            loadingView.startAnimation(nil)
            startDownloading()//下载符号表
        }else if selected{
            loadingView.startAnimation(nil)
            startAnalyzing()//开始解析
        }else{//停止解析
            loadingView.stopAnimation(nil)
            self.progressView.doubleValue = 0
            self.progressLabel.stringValue = "解析被暂停"
            if anaTimer != nil {
                anaTimer.invalidate()
                anaTimer = nil
            }
            WBBrightMirrorManager.stopDownload(logModel: curLogModel)
            WBBrightMirrorManager.stopAnalyze(logModel: curLogModel)
        }
    }

    @IBAction func inputProcessConfirmClicked(_ sender: Any) {
        if inputProcessField.stringValue.count == 0 {
            showTips(tipString: "您必须输入进程名，否则无法进行解析.")
            return
        }
        curLogModel.processName = inputProcessField.stringValue
        WBBrightMirrorManager.checkBuglyProcessName(logModel: curLogModel)
        var processCaches: Array<String> = UserDefaults.standard.object(forKey: kInputProcessCacheKey) as? Array<String> ?? []
        if !processCaches.contains(curLogModel.processName) {
            processCaches.insert(curLogModel.processName, at: 0)
        }
        UserDefaults.standard.setValue(processCaches, forKey: kInputProcessCacheKey)
        UserDefaults.standard.synchronize()
        
        if inputStartAddressField.stringValue.count == 0 {
            showTips(tipString: "您没有输入进程起始地址，我们会计算，您需要耐心等待.")
        }else{
            curLogModel.extendParams["buglyStartAddress"] = inputStartAddressField.stringValue
        }
        
        if inputUUIDField.stringValue.count > 0 {
            curLogModel.processUUID = inputUUIDField.stringValue
            var uuidCaches: Array<String> = UserDefaults.standard.object(forKey: kInputUUIDCacheKey) as? Array<String> ?? []
            if !uuidCaches.contains(curLogModel.processUUID) {
                uuidCaches.append(curLogModel.processUUID)
            }
            UserDefaults.standard.setValue(uuidCaches, forKey: kInputUUIDCacheKey)
            UserDefaults.standard.synchronize()
        }
        
        self.showInputProcess(show: false)
        if curLogModel.processUUID.count > 0 {
            startBtn.title = "暂停"
            startBtn.state = .on
            self.startDownloading()
        }else{
            self.showSymbolTableView(show: true)
        }
    }
    
    @IBAction func inputProcessHelpClicked(_ sender: Any) {
        HelpViewManager.openBuglyHelpView(type: .process)
    }
    
    @IBAction func inputStartAddressHelpClicked(_ sender: Any) {
        HelpViewManager.openBuglyHelpView(type: .startAddress)
    }
    
    @IBAction func inputUUIDHelpClicked(_ sender: Any) {
        HelpViewManager.openBuglyHelpView(type: .UUID)
    }
    
    @IBAction func inputProcessCacheBtnClicked(_ sender: NSButton) {
        inputUUIDCacheBtn.state = .off
        if sender.state.rawValue == 1 {
            self.inputCacheView.isHidden = false
            self.inputCacheArray = UserDefaults.standard.object(forKey: kInputProcessCacheKey) as? Array ?? []
            let tableView = self.inputCacheView.documentView as? NSTableView
            tableView?.reloadData()
            self.inputCacheView.documentView?.scroll(NSMakePoint(0, -(self.inputCacheView.documentView?.frame.size.height ?? 0)))
            self.inputCacheView.frame = NSMakeRect(inputBackgroundView.frame.origin.x+inputProcessField.frame.origin.x, inputBackgroundView.frame.origin.y + inputProcessField.frame.origin.y-inputCacheView.frame.size.height, inputCacheView.frame.size.width, inputCacheView.frame.size.height)
        }else{
            self.inputCacheView.isHidden = true
        }
    }
    
    @IBAction func inputUUIDCacheBtnClicked(_ sender: NSButton) {
        inputProcessCacheBtn.state = .off
        if sender.state.rawValue == 1 {
            self.inputCacheView.isHidden = false
            self.inputCacheArray = UserDefaults.standard.object(forKey: kInputUUIDCacheKey) as? Array ?? []
            let tableView = self.inputCacheView.documentView as? NSTableView
            tableView?.reloadData()
            self.inputCacheView.documentView?.scroll(NSMakePoint(0, -(self.inputCacheView.documentView?.frame.size.height ?? 0)))
            self.inputCacheView.frame = NSMakeRect(inputBackgroundView.frame.origin.x+inputUUIDField.frame.origin.x, inputBackgroundView.frame.origin.y + inputUUIDField.frame.origin.y-inputCacheView.frame.size.height, inputCacheView.frame.size.width, inputCacheView.frame.size.height)
        }else{
            self.inputCacheView.isHidden = true
        }
    }
    
    //MARK:-
    //MARK:Analyze
    @objc
    func scanCurrentLog(notification: Notification?) -> Bool {
        if anaTimer != nil {
            anaTimer.invalidate()
            anaTimer = nil
        }
        
        guard let logModel: WBBMLogModel = WBBrightMirrorManager.scanLog(logString: self.logTextView.string) else{
            self.curLogModel = nil
            self.progressLabel.textColor = NSColor.red
            self.progressLabel.stringValue = "暂时不支持该类型日志，请您换一个日志再试试！"
            return false
        }
        
        if notification != nil {
            if let url = notification?.object as? URL {
                logModel.originalLogPath = url
            }
        }
        self.logTextView.textColor = NSColor.labelColor
        self.curLogModel = logModel
        self.progressView.doubleValue = 0
        self.logTextViewOriginY.constant = 20.0
        self.showSymbolTableView(show: false)
        
        if logModel.logType == .BuglyType {
            self.showInputProcess(show: true)
        }else{
            self.progressLabel.textColor = NSColor.labelColor
            self.progressLabel.stringValue = " 当前崩溃日志是 \(logModel.processName)(\(logModel.version))中发生的, 您可以点击“开始”进行自动解析."
        }
        return true
    }
    
    func canStartAnalyzing() -> Bool {
        if curLogModel == nil{
            guard scanCurrentLog(notification:nil) != false else {
                self.progressLabel.stringValue = "请拖入正确的日志文件"
                return false
            }
        }
        
        guard curLogModel.processName.count > 0 else {
            self.progressLabel.stringValue = "请输入必要字段，否则无法继续进行"
            return false
        }
        
        if symbolTablePathView.isHidden == false{
            if symbolTablePathView.stringValue.count == 0 {
                curSymbolTable = nil
                self.symbolTableTipLabel.textColor = NSColor.red
                if curLogModel.logType == .BuglyType {
                    self.progressLabel.stringValue = "您目前输入的是堆栈，需要指定包含符号表的文件，支持.app，.dsym，.symbol文件."
                }else{
                    self.progressLabel.stringValue = "您必须指定一个 \(curLogModel.processName)(\(curLogModel.version))的包含符号表的文件，支持.app，.dsym，.symbol文件."
                }
                return false
            }else if(!FileManager.default.fileExists(atPath: symbolTablePathView.stringValue)){
                curSymbolTable = nil
                self.symbolTableTipLabel.textColor = NSColor.red
                self.progressLabel.stringValue = "找不到该文件，请您拖入正确的符号表文件."
                return false
            }
        }else{
            curSymbolTable = nil
            return true
        }
        
        curSymbolTable = symbolTablePathView.stringValue
        return true
    }
    
    func startAnalyzing() -> Void {
        guard canStartAnalyzing() == true else {
            self.progressLabel.textColor = NSColor.red
            return
        }
        
        self.symbolTableTipLabel.textColor = NSColor.labelColor
        self.progressLabel.textColor = NSColor.labelColor
        
        if curSymbolTable == nil || curSymbolTable.count == 0{
            self.progressLabel.stringValue = "符号表文件下载成功，正在开始解析..."
            self.progressView.doubleValue = 60
        }else{
            self.progressLabel.stringValue = "正在解析日志，请不要退出程序..."
            self.progressView.doubleValue = 60
        }
        
        if curLogModel.logType == .BuglyType {
            WBBrightMirrorManager.checkBuglyAnalzeReady(logModel: curLogModel, symbolPath:curSymbolTable, baseAddress: curLogModel.extendParams["buglyStartAddress"] as? String) { [weak self] ready in
                if(ready){
                    self?.analyzeLog()
                }
            }
        }else{
            analyzeLog()
        }
    }
    
    func analyzeLog() -> Void {
        createAnaTimer()
        WBBrightMirrorManager.startAnalyze(logModel: curLogModel, symbolPath:curSymbolTable) { [weak self] succceed, symbolReady, outputPath in
            if symbolReady {
                self?.createAnaTimer()
                self?.progressLabel.stringValue = "日志已开始解析,请耐心等待..."
            }else{
                self?.loadingView.isHidden = true
                self?.loadingView.stopAnimation(nil)
                self?.startBtn.title = "开始"
                self?.startBtn.state = .off
                self?.anaTimer?.invalidate()
                self?.anaTimer = nil
                
                if succceed == false || outputPath == nil {
                    self?.progressLabel.stringValue = "解析失败，您可以重新尝试."
                    self?.progressView.doubleValue = 0
                    return
                }

                self?.progressView.doubleValue = 100
                self?.progressLabel.stringValue = "崩溃日志解析已成功100%，您可以拖入新的崩溃日志继续进行解析."
                let resultString = try? String.init(contentsOfFile: outputPath ?? "", encoding: .utf8)
                self?.logTextView.string = resultString ?? ""
                self?.logTextView.textColor = NSColor.init(red: 65.0/255.0, green: 105.0/255.0, blue: 225.0/255.0, alpha: 1.0)
                NSWorkspace.shared.selectFile(outputPath, inFileViewerRootedAtPath: "")
            }
        }
    }
    
    func startDownloading() -> Void {
        loadingView.startAnimation(nil)
        self.progressLabel.stringValue = "开始匹配对应的符号表文件，请稍等..."
        self.progressLabel.textColor = NSColor.labelColor
        WBBrightMirrorManager.downloadSymbol(logModel: curLogModel) { [weak self] progress in
            if self?.startBtn.state.rawValue == 0{
                return
            }
            self?.progressView.doubleValue = 60*progress
            if progress < 1.0 {
                self?.progressLabel.stringValue = String.init(format: "正在下载符号表文件，请你不要断开网络连接...%d%%", Int(progress*100))
            }else{
                self?.progressLabel.stringValue = String.init(format: "符号表文件下载成功，我们正在准备解析崩溃日志，请不要退出程序...%0.f%%", 60*progress)
            }
        }finishHandler: { [weak self] symbolPath in
            guard symbolPath != nil else{
                self?.startBtn.title = "开始"
                self?.startBtn.state = .off
                self?.loadingView.isHidden = true
                self?.progressLabel.stringValue = "没有匹配到相应的符号表文件或下载失败，您可以拖入本地的包含符号表的文件，支持.app，.dsym，.symbol文件"
                self?.showSymbolTableView(show: true)
                return
            }
        
            self?.startAnalyzing()
        }
    }
    
    //MARK:-
    //MARK:Timer
    func createAnaTimer() -> Void {
        if anaTimer != nil {
            anaTimer.invalidate()
            anaTimer = nil
        }
        
        count = 0
        anaTimer = Timer.scheduledTimer(timeInterval: 0.1, target: self, selector: #selector(analyzingTimer), userInfo: nil, repeats: true)
        anaTimer.fire()
    }
    
    var count = 0
    @objc
    func analyzingTimer() -> Void {
        if self.progressView.doubleValue > 89 && count < 13 {
            self.progressView.doubleValue = 90
            count += 1
        }else if count >= 13 && self.progressView.doubleValue > 98 {
            self.progressView.doubleValue = 99
            let prgString = String.init(format: "解析即将结束请耐心等待， 当前进度%0.f%%...", self.progressView.doubleValue)
            self.progressLabel.stringValue = prgString
        }else{
            self.progressView.doubleValue += 1.0
            let prgString = String.init(format: "符号表获取成功, 日志解析已开始 %0.f%%...", self.progressView.doubleValue)
            self.progressLabel.stringValue = prgString
        }
    }
    
    //MARK:-
    //MARK:TextView
    func textDidChange(_ notification: Notification) {
        if logTextView.string == "" {
            curLogModel = nil
            progressLabel.stringValue = "您可以拖入一个崩溃日志文件或拷贝具体的崩溃堆栈，点击“开始”，我们将自动进行解析"
            return
        }
        
        guard self.progressView.doubleValue != 100 && scanCurrentLog(notification:nil) != false else {
            return
        }
    }
    
    //MARK:-
    //MARK:Timer
    func numberOfRows(in tableView: NSTableView) -> Int {
        if inputCacheArray != nil {
            return inputCacheArray.count
        }
        return 0
    }
    
    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        var rowView = tableView.makeView(withIdentifier: NSUserInterfaceItemIdentifier(rawValue: "RowViewIden"), owner: self) as? NSTableRowView
        if rowView == nil {
            rowView = NSTableRowView.init()
            rowView?.identifier = NSUserInterfaceItemIdentifier(rawValue: "RowViewIden")
            rowView?.backgroundColor = NSColor.white
        }

        let text = NSTextField.init()
        rowView?.addSubview(text)
        return rowView
    }
    
    func tableView(_ tableView: NSTableView, objectValueFor tableColumn: NSTableColumn?, row: Int) -> Any? {
        return inputCacheArray[row]
    }
    
    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        return 28.0
    }
    
    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        let value = inputCacheArray[row]
        
        self.inputCacheView.isHidden = true
        if inputProcessCacheBtn.state.rawValue == 1 {
            self.inputProcessField.stringValue = value
            inputProcessCacheBtn.state = .off
        }else if inputUUIDCacheBtn.state.rawValue == 1{
            self.inputUUIDField.stringValue = value
            inputUUIDCacheBtn.state = .off
        }
        
        return false
    }
    
}
