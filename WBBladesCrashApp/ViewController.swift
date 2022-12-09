//
//  ViewController.swift
//  WBBladesCrashProject
//
//  Created by wbblades on 2021/4/22.
//

import Cocoa
import WBBladesCrash
import WBBlades

let LogTextViewContentChanged:String = "TextViewContentChanged"
let kInputProcessCacheKey = "kInputProcessCacheKey"
let kInputUUIDCacheKey = "kInputUUIDCacheKey"

class ViewController: NSViewController,NSTextViewDelegate, NSTableViewDelegate,NSTableViewDataSource {

    @IBOutlet var logTextView: LogTextView!                             //crash log text view
    @IBOutlet weak var mainTitleLabel: NSTextField!                     //main title label
    @IBOutlet weak var logTextViewOriginY: NSLayoutConstraint!          //crash log text view origin Y
    @IBOutlet weak var startBtn: SYFlatButton!                              //start button

    @IBOutlet weak var progressView: NSProgressIndicator!               //bottom analyze progress view
    @IBOutlet weak var loadingView: NSProgressIndicator!                //bottom loading view
    @IBOutlet weak var progressLabel: NSTextField!                      //bottom analyze progress label

    @IBOutlet weak var symbolTableTipLabel: NSTextField!                //input symbol table path tip label
    @IBOutlet weak var symbolTablePathView: NSTextField!                //input symbol table path view

    @IBOutlet weak var inputProcessView: NSView!                        //input necessary info view
    @IBOutlet weak var inputBackgroundView: NSView!                     //input necessary info view background

    @IBOutlet weak var inputProcessField: NSTextField!                  //input process info
    @IBOutlet weak var inputProcessCacheBtn: NSButton!                  //process cache
    @IBOutlet weak var inputStartAddressField: NSTextField!             //input the base address of process
    @IBOutlet weak var inputUUIDField: NSTextField!                     //input the UUID of process
    @IBOutlet weak var inputUUIDCacheBtn: NSButton!                     //UUID cache

    @IBOutlet weak var inputProgressTopTipLabel: NSTextField!
    @IBOutlet weak var inputProgressNameLabel: NSTextField!
    @IBOutlet weak var inputProgressBaseAddrLabel: NSTextField!
    @IBOutlet weak var inputProgressConfirmBtn: NSButton!

    @IBOutlet weak var languageChangeBtn: NSPopUpButton!                //select language
    @IBOutlet weak var logTextPlaceholder: NSTextField!
    
    var curLogModel: WBBMLogModel!                                      //scan crash log return a model
    var curSymbolTable: String!                                         //symbol table path
    var anaTimer: Timer!                                                //progress timer
    var selected = false                                                //start button selected

    lazy var inputCacheView: NSScrollView = {
        let tableview = NSTableView.init(frame: NSMakeRect(0, 0, 144.0, 70.0))
        tableview.wantsLayer = true
        tableview.delegate = self
        tableview.dataSource = self
        let column = NSTableColumn.init(identifier: NSUserInterfaceItemIdentifier(rawValue: "RowViewIden"))
        column.width = inputProcessField.frame.size.width
        column.title = TextDictionary.valueForKey(key: "historyText")
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

        initAllSubviews()//init all subviews
        initNotification()//add notification
        configThemeColor()// configure theme colors
        self.symbolTableTipLabel.isHidden = true
        self.showSymbolTableView(show: true)
        DispatchQueue.main.async {
            self.symbolTablePathView.becomeFirstResponder()
        }
        self.setBackgroudColor(color:.init(red: CGFloat(247)/CGFloat(255), green: CGFloat(247)/CGFloat(255), blue: CGFloat(247)/CGFloat(255), alpha: 1.0))
        self.logTextView.showTextViewBoarder()
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    //init all subviews
    func initAllSubviews() -> Void {
        loadingView.isHidden = true
        logTextView.registerForDraggedTypes([.fileURL,.string])
        logTextView.delegate = self
        languageChangeBtn.removeAllItems()
        languageChangeBtn.addItems(withTitles: ["English","中文"])
        if TextDictionary.mode == .chinese{
            languageChangeBtn.selectItem(at: 1)
        }
        //showSymbolTableView(show: false)
        showInputProcess(show: false)
        mainTitleLabel.stringValue = TextDictionary.valueForKey(key: "mainTitle")
        startBtn.title = TextDictionary.valueForKey(key: "startButtonNormal")
        progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzeTip")
        inputProgressTopTipLabel.stringValue = TextDictionary.valueForKey(key: "inputProgressTopTipLabel")
        inputProgressNameLabel.stringValue = TextDictionary.valueForKey(key: "inputProgressNameLabel")
        inputProgressBaseAddrLabel.stringValue = TextDictionary.valueForKey(key: "inputProgressBaseAddrLabel")
        inputProgressConfirmBtn.title = TextDictionary.valueForKey(key: "inputProgressConfirmBtn")
        logTextPlaceholder.placeholderString = TextDictionary.valueForKey(key: "mainTitle")
    }

    /**
     *  show input process alert view
     *  @param show  show alert view
     */
    func showInputProcess(show: Bool) -> Void {
        if show {
            logTextView.isEditable = false
            //symbolTablePathView.isEditable = false
            startBtn.isEnabled = false
            inputProcessView.isHidden = false;
            inputProcessView.wantsLayer = true
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
            //symbolTablePathView.isEditable = true
            //startBtn.isEnabled = true
            inputProcessView.isHidden = true;
            inputProcessField.stringValue = ""
            inputStartAddressField.stringValue = ""
            inputUUIDField.stringValue = ""
        }
    }

    /**
     *  show symbol table path view
     *  @param show  show view
     */
    func showSymbolTableView(show: Bool) -> Void {
        if show {
            symbolTableTipLabel.isHidden = false
            symbolTablePathView.isHidden = false
            symbolTablePathView.stringValue = ""
            //logTextViewOriginY.constant = 60.0
            selected = false
            symbolTableTipLabel.stringValue = TextDictionary.valueForKey(key: "symbolPathTip")
            symbolTablePathView.placeholderString = TextDictionary.valueForKey(key: "symbolPathTip")
            progressLabel.stringValue = TextDictionary.valueForKey(key: "inputSymbolPath")
            //startBtn.title = TextDictionary.valueForKey(key: "startButtonNormal")
        }else{
            symbolTableTipLabel.isHidden = true
            symbolTablePathView.isHidden = true
            //logTextViewOriginY.constant = 20.0
        }
        self.symbolTableTipLabel.isHidden = true
        self.mainTitleLabel.isHidden = true
        

    }

    /**
     *  show tips
     *  @param tipString  tip string
     */
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

    /**
     *  add notification
     */
    func initNotification() -> Void {
        NotificationCenter.default.addObserver(self, selector: #selector(scanCurrentLog), name: .init(LogTextViewContentChanged), object: nil)
    }

    
    func configThemeColor() {
        self.view.wantsLayer = true
        self.view.layer?.backgroundColor = NSColor(red: CGFloat(64)/CGFloat(255), green: CGFloat(143)/CGFloat(255), blue: CGFloat(209)/CGFloat(255), alpha: 1).cgColor

        let adjustedTintColor = NSColor.white.usingColorSpace(.deviceRGB)
        let tintColorRedComponent = adjustedTintColor?.redComponent
        let tintColorGreenComponent = adjustedTintColor?.greenComponent
        let tintColorBlueComponent = adjustedTintColor?.blueComponent

        let tintColorMinComponentsVector = CIVector(x: tintColorRedComponent ?? 0, y: tintColorGreenComponent ?? 0, z: tintColorBlueComponent ?? 0, w: 0.0)
        let tintColorMaxComponentsVector = CIVector(x: tintColorRedComponent ?? 0, y: tintColorGreenComponent ?? 0, z: tintColorBlueComponent ?? 0, w: 1.0)

        let colorClampFilter = CIFilter(name: "CIColorClamp")!
        colorClampFilter.setDefaults()
        colorClampFilter.setValue(tintColorMinComponentsVector, forKey: "inputMinComponents")
        colorClampFilter.setValue(tintColorMaxComponentsVector, forKey: "inputMaxComponents")

        self.progressView.contentFilters = [colorClampFilter]
        self.loadingView.contentFilters = [colorClampFilter]

    }
    
    //MARK:-
    //MARK:Event
    @IBAction func startBtnClicked(_ sender: NSButton) {
        if selected {
            selected = false
            sender.title = TextDictionary.valueForKey(key: "startButtonNormal")
        }else{
            sender.title = TextDictionary.valueForKey(key: "startButtonSelected")
            selected = true
        }

        guard canStartAnalyzing() == true else {
            sender.title = TextDictionary.valueForKey(key: "startButtonNormal")
            selected = false
            self.progressLabel.textColor = NSColor.red
            return
        }

        guard curLogModel.processName.count > 0 else {
            return
        }

        self.progressLabel.textColor = NSColor.labelColor
        loadingView.isHidden = !selected
        if selected {
            loadingView.startAnimation(nil)
            startAnalyzing()//开始解析
        }else{//停止解析
            loadingView.stopAnimation(nil)
            self.progressView.doubleValue = 0
            self.progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzingInterrupt")
            if anaTimer != nil {
                anaTimer.invalidate()
                anaTimer = nil
            }
            WBBladesCrashManager.stopAnalyze(logModel: curLogModel)
        }
    }

    @IBAction func inputProcessConfirmClicked(_ sender: Any) {
        if inputProcessField.stringValue.count == 0 {
            showTips(tipString: TextDictionary.valueForKey(key: "buglyMainTip"))
            return
        }
        curLogModel.processName = inputProcessField.stringValue
        WBBladesCrashManager.checkBuglyProcessName(logModel: curLogModel)
        var processCaches: Array<String> = UserDefaults.standard.object(forKey: kInputProcessCacheKey) as? Array<String> ?? []
        if !processCaches.contains(curLogModel.processName) {
            processCaches.insert(curLogModel.processName, at: 0)
        }
        UserDefaults.standard.setValue(processCaches, forKey: kInputProcessCacheKey)
        UserDefaults.standard.synchronize()

        if inputStartAddressField.stringValue.count == 0 {
            showTips(tipString: TextDictionary.valueForKey(key: "buglyProcessNameTip"))
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
            startBtn.title = TextDictionary.valueForKey(key: "startButtonSelected")
            selected = true
            self.startAnalyzing()
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

    @IBAction func goBack(_ sender: Any) {
        self.goBack()
    }

    @IBAction func languageChangeClicked(_ sender: NSPopUpButton) {
        let itemIndex = sender.indexOfSelectedItem
        if itemIndex == 0{
            TextDictionary.mode = .english
        }else{
            TextDictionary.mode = .chinese
        }

        //create new vc
        creatNewViewController()

        //close last window
        let lastWindow = self.view.window
        lastWindow?.close()
    }

    func creatNewViewController(){
        let vcWindow = NSStoryboard.main?.instantiateController(withIdentifier: "WindowController") as? NSWindowController
        vcWindow?.window?.center()
        vcWindow?.window?.orderFront(nil)
        vcWindow?.showWindow(nil)
    }

    //MARK:-
    //MARK:Analyze
    @objc
    func scanCurrentLog(notification: Notification?) -> Bool {
        if anaTimer != nil {
            anaTimer.invalidate()
            anaTimer = nil
        }

        guard let logModel: WBBMLogModel = WBBladesCrashManager.scanLog(logString: self.logTextView.string) else{
            self.curLogModel = nil
            self.progressLabel.textColor = NSColor.red
            self.progressLabel.stringValue = TextDictionary.valueForKey(key: "notSupportLog")
            return false
        }
        
        logTextPlaceholder.isHidden = true
        if notification != nil {
            if let url = notification?.object as? URL {
                logModel.originalLogPath = url
            }
        }
        self.logTextView.textColor = NSColor.labelColor
        self.curLogModel = logModel
        self.progressView.doubleValue = 0
        //self.logTextViewOriginY.constant = 20.0
        //self.showSymbolTableView(show: false)
        curSymbolTable = nil
        WBBladesCrashManager.checkSymbolPath(processName: logModel.processName, uuid: logModel.processUUID, {[weak self] symbolPath in
            self?.curSymbolTable = symbolPath
        })
        
        if logModel.logType == .BuglyType {
            self.showInputProcess(show: true)
        }else{
            self.progressLabel.textColor = NSColor.labelColor
            self.progressLabel.stringValue = "\(TextDictionary.valueForKey(key: "currentLogInfo")) \(logModel.processName)(\(logModel.version))."
        }
        return true
    }

    /**
     *  whether the crash log can be analyzed
     */
    func canStartAnalyzing() -> Bool {
        if curLogModel == nil{
            guard scanCurrentLog(notification:nil) != false else {
                self.progressLabel.stringValue = TextDictionary.valueForKey(key: "uncorrectLogType")
                return false
            }
        }

        guard curLogModel.processName.count > 0 else {
            self.progressLabel.stringValue = TextDictionary.valueForKey(key: "necessaryField")
            return false
        }

        if symbolTablePathView.isHidden == false{
            if symbolTablePathView.stringValue.count == 0 {
                curSymbolTable = nil
                self.symbolTableTipLabel.textColor = NSColor.red
                self.progressLabel.stringValue = TextDictionary.valueForKey(key: "inputSymbolPath")
                return false
            }else if(!FileManager.default.fileExists(atPath: symbolTablePathView.stringValue)){
                curSymbolTable = nil
                self.symbolTableTipLabel.textColor = NSColor.red
                self.progressLabel.stringValue = TextDictionary.valueForKey(key: "inputCorrectFile")
                return false
            }
        }else{
            curSymbolTable = nil
            return true
        }

        curSymbolTable = symbolTablePathView.stringValue
        return true
    }

    /**
     *  analyze crash log, judge the crash type
     */
    func startAnalyzing() -> Void {
        guard canStartAnalyzing() == true else {
            self.progressLabel.textColor = NSColor.red
            return
        }

        //self.symbolTableTipLabel.textColor = NSColor.labelColor
        self.progressLabel.textColor = NSColor.labelColor
        if curLogModel.logType == .BuglyType {
            WBBladesCrashManager.checkBuglyAnalzeReady(logModel: curLogModel, symbolPath:curSymbolTable, baseAddress: curLogModel.extendParams["buglyStartAddress"] as? String) { [weak self] ready in
                if(ready){
                    self?.analyzeLog()
                }
            }
        }else if(curSymbolTable == nil){
            self.showSymbolTableView(show: true)
        }else{
            analyzeLog()
        }
    }

    /**
     *  analyze crash log start
     */
    func analyzeLog() -> Void {
        createAnaTimer()
        WBBladesCrashManager.startAnalyze(logModel: curLogModel, symbolPath:curSymbolTable) { [weak self] succceed, symbolReady, outputPath in
            DispatchQueue.main.async {
                //symbol table is obtained.
                if symbolReady {
                    self?.createAnaTimer()
                    self?.progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzeRunning")
                }else{//analyze is finished
                    self?.loadingView.isHidden = true
                    self?.loadingView.stopAnimation(nil)
                    self?.startBtn.title = TextDictionary.valueForKey(key: "startButtonNormal")
                    self?.selected = false
                    self?.anaTimer?.invalidate()
                    self?.anaTimer = nil

                    //crash log analyze is failed.
                    if succceed == false || outputPath == nil {
                        DispatchQueue.global().async{
                            let outputRPath = WBBladesInterface.scanCrashSymbol(byCrashLogPath: self?.curLogModel.originalLogPath.absoluteString ?? "", executableAppPath: self?.curSymbolTable ?? "")
                            
                            DispatchQueue.main.async {
                                if outputRPath.count > 0 {
                                    NSWorkspace.shared.selectFile(outputRPath, inFileViewerRootedAtPath: "")
                                }else{
                                    self?.progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzeFailed")
                                    self?.progressView.doubleValue = 0
                                }
                            }
                        }
                        return
                    }

                    self?.progressView.doubleValue = 100
                    self?.progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzeSucceed")
                    let resultString = try? String.init(contentsOfFile: outputPath ?? "", encoding: .utf8)
                    self?.logTextView.string = resultString ?? ""
                    self?.logTextView.textColor = NSColor.init(red: 65.0/255.0, green: 105.0/255.0, blue: 225.0/255.0, alpha: 1.0)
                    NSWorkspace.shared.selectFile(outputPath, inFileViewerRootedAtPath: "")
                }
            }
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
        //progress control
        if self.progressView.doubleValue > 89 && count < 13 {
            self.progressView.doubleValue = 90
            count += 1
        }else if count >= 13 && self.progressView.doubleValue > 98 {
            self.progressView.doubleValue = 99
            let prgString = String.init(format: "%@ %0.f%%...",TextDictionary.valueForKey(key: "analyzingWillFinishing"), self.progressView.doubleValue)
            self.progressLabel.stringValue = prgString
        }else{
            self.progressView.doubleValue += 1.0
            let prgString = String.init(format: "%@ %0.f%%...",TextDictionary.valueForKey(key: "analyzingDidStarted"),self.progressView.doubleValue)
            self.progressLabel.stringValue = prgString
        }
    }

    //MARK:-
    //MARK:TextView
    func textDidChange(_ notification: Notification) {
        if logTextView.string == "" {
            curLogModel = nil
            progressLabel.stringValue = TextDictionary.valueForKey(key: "analyzeTip")
            logTextPlaceholder.isHidden = false
            return
        }
        logTextPlaceholder.isHidden = true
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

