//
//  ASFileListViewController.swift
//  AppSizeManager
//
//  Created by Shwnfee on 2022/3/8.
//  Copyright (C) 2005-present, 58.com.  All rights reserved.

import Cocoa

class ASFileListViewController: NSViewController,PXListViewDelegate {
    
    var _files : [ASShowFileListBaseModel] = []
    var files : [ASShowFileListBaseModel] {
        get {
            return self._files
        }
        set(newFiles){
            self._files = newFiles
            self.updateFlatFiles()
        }
    }
    
    var flatFiles : [ASShowFileListBaseModel] = []

    @IBOutlet weak var listView: PXListView!

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
        listView.cellSpacing = 2.0
        listView.allowsEmptySelection = true
        listView.allowsMultipleSelection = true
        listView.registerForDraggedTypes([.string])
        self.updateFlatFiles()
    }
    
    func updateFlatFiles() {
        self.flatFiles = self.flatWith(files: self.files, level: 0);
        if self.listView == nil{
            return
        }
        self.listView.reloadData()
    }
    
    func flatWith(files:[ASShowFileListBaseModel],level:UInt)->[ASShowFileListBaseModel]{
        var flatFiles:[ASShowFileListBaseModel] = []
        for file in files {
            file.foldLevel = level
            flatFiles.append(file)
            let subFiles = file.subFiles()
            if (!file.isFold && (subFiles.count>0)){
                let nextLevel = level + 1;
                let subFlats = self.flatWith(files: subFiles, level: nextLevel)
                flatFiles.append(contentsOf: subFlats)
            }
        }
        return flatFiles
    }
    
    func listView(_ aListView: PXListView!, cellForRow row: UInt) -> PXListViewCell! {
        let item:ASShowFileListBaseModel = self.flatFiles[Int(row)]
        guard let cell = item.cellFor(listView: aListView)  else {
            var errcell = aListView.dequeueCell(withReusableIdentifier: "test");
            if errcell == nil {
                errcell = (ASFileCell.cellLoaded(fromNibNamed: "ASFileCell", reusableIdentifier: "test") as! PXListViewCell)
            }
            return errcell
        }
        return cell
    }
    
    func listView(_ aListView: PXListView!, heightOfRow row: UInt) -> CGFloat {
        let item:ASShowFileListBaseModel = self.flatFiles[Int(row)]
        return item.cellHeight()
    }
 
    func numberOfRows(in aListView: PXListView!) -> UInt {
        return UInt(self.flatFiles.count)
    }
    
    func listView(_ aListView: PXListView!, rowClicked rowIndex: UInt) {
        if (rowIndex >= self.flatFiles.count) {
            return
        }
        let file:ASShowFileListBaseModel = self.flatFiles[Int(rowIndex)];
        file.isFold = !file.isFold
        self.updateFlatFiles()
    }
    
    func listView(_ aListView: PXListView!, rowDoubleClicked rowIndex: UInt) {
        print("")
    }
    
}
