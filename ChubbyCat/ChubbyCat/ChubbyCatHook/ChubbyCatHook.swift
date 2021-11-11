//
//  ChubbyCat.swift
//  ChubbyCat
//
//  Created by 邓竹立 on 2021/10/13.
//

/**
 ChubbyCat is used for studying,can't be used for business.
 */

import Foundation
import MachO

/**
 Get segment vm addr from load command index
 index: load command index
 header: image header
 */
fileprivate func getSegment(index:Int,header:UnsafePointer<mach_header>) -> (UInt64,Bool) {
    if index >= header.pointee.ncmds || index < 0{
        return (0,false)
    }
    //swift pointer!
    var cur =  uintptr_t(bitPattern: header) + UInt( MemoryLayout<mach_header_64>.stride)
    for i in 0 ..< header.pointee.ncmds {
        guard let curCmd = UnsafeMutablePointer<segment_command_64>(bitPattern: cur) else { return (0,false) }
        cur += UInt(UnsafeRawPointer.Stride(curCmd.pointee.cmdsize))
        if curCmd.pointee.cmd == LC_SEGMENT_64 {
            if i == index {
                return (curCmd.pointee.vmaddr,true)
            }
        }
    }
    return (0,false)
}

/**
 Read SLEB128 data
 loaction: The first char loaction
 */
fileprivate func SLEB128(location:inout UInt64) -> Int64 {
    guard var p = UnsafeMutablePointer<UInt8>(bitPattern: UInt(location)) else { return 0 }
    let start = p
    
    var result : Int64 = 0
    var bit: Int32 = 0
    var byte : UInt8

    repeat{
        byte = p.pointee
        p += 1
        result = Int64(((byte & 0x7f) << bit)) | result
        bit += 7
    }while(byte & 0x80 != 0)
    
    if ((byte & 0x40) != 0 ){
        result = (Int64(-1) << bit) | result
    }
    let size : UInt64 = UInt64(p - start) + 1
    location = location + size
    return result
}

/**
 Read ULEB128 data
 loaction: The first char loaction
 */
fileprivate func ULEB128(location:inout UInt64) -> UInt64 {
    
    guard var p = UnsafeMutablePointer<UInt8>(bitPattern: UInt(location)) else { return 0 }
    let start = p
    
    var result:UInt64 = 0
    var bit:Int32 = 0

    let slice : UInt64 = UInt64(p.pointee & 0x7f)
    if (bit >= 64 || (slice << bit) >> bit != slice){
        
        NSException.raise(NSExceptionName.init(rawValue: "ULEB128 Error"), format: "ULEB128 too big", arguments: withVaList([], {$0}))
    }else{
        result = result | (slice << bit)
        bit += 7
    }
    while ((p.pointee & 0x80) != 0){
        p += 1
        let slice : UInt64 = UInt64(p.pointee & 0x7f)
        if (bit >= 64 || (slice << bit) >> bit != slice){
            
            NSException.raise(NSExceptionName.init(rawValue: "ULEB128 Error"), format: "ULEB128 too big", arguments: withVaList([], {$0}))
        }else{
            result = result | (slice << bit)
            bit += 7
        }
    }
    let size : UInt64 = UInt64(p - start) + 1
    location = location + size
    return result
}

@objc class ChubbyCatHook : NSObject {
    
    /**
    I want to hook all images ,but it's difficult. In iOS 15 , image may not have LC_DYLD_INFO_ONLY.  If Deployment Target >= 15.0,fixup-chains will replace LC_DYLD_INFO_ONLY. When our code execute, all fixup-chains  data have been bound, we cant read ori data，but read from disk file.
    name: function name ,you should add _ before it
    replacement: function pointer
     */
    static func replaceC(name:String!,replacement:UInt64) -> Bool {
        
//        _dyld_register_func_for_add_image { header, index in
//            print("index = \(index)")
//        }
        
//        let count = _dyld_image_count()
        var ret = false
//        for i in 0 ..< count {
        
        //In iOS 15+,index = 0 may not be the exe image.
            ret = replaceC(name: name, replacement: replacement, index: 0)
        
//        }
        return ret
    }
    
    /**
    Replace C function in the image with image index.
    name: function name ,you should add _ before it
    replacement: function pointer
    index: image index
     */
    static func replaceC(name:String!,replacement:UInt64,index:UInt32) -> Bool {
        guard let symbolPtr = readBindList(index: index)[name] else { return false }
        let canHook = vm_protect(mach_task_self_, vm_address_t(symbolPtr), 8, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)
        if canHook == KERN_SUCCESS {
            let det = UnsafeMutableRawPointer(bitPattern: UInt(symbolPtr))
            let src = withUnsafePointer(to: replacement) { UnsafeRawPointer($0) }
            memcpy(det, src, 8);
        }
        return true
    }
    
    
    /**
    Read bind info (bind | weak-bind | lazy-bind)，and return map ,the map records symbol -> addr
    index: dyld image index, we can get image header and slide from dyld
    return: symbol -> addr
     */
    static func readBindList(index:UInt32) -> [String:UInt64]{
        var allBindInfoMap = [String:UInt64]()
        let header:UnsafePointer<mach_header> = _dyld_get_image_header(index)
        let slide = _dyld_get_image_vmaddr_slide(index)
        let imageName = String.init(cString: _dyld_get_image_name(index))
        print("image = \(imageName)")
        var dyCmd : UnsafePointer<dyld_info_command>?
        var leCmd : UnsafePointer<segment_command_64>?
        let headPtr = uintptr_t(bitPattern: header)
        var cur = headPtr + UInt(MemoryLayout<mach_header_64>.stride)
        
        //get loader info & __linkedit from the header
        for _ in 0 ..< header.pointee.ncmds {
            guard let curCmd = UnsafePointer<segment_command_64>(bitPattern: cur) else { return allBindInfoMap}
            cur += UInt(UnsafeRawPointer.Stride(curCmd.pointee.cmdsize))
            let segname = curCmd.pointee.segname
            if curCmd.pointee.cmd == LC_DYLD_INFO_ONLY {
                dyCmd = unsafeBitCast(curCmd, to: UnsafePointer<dyld_info_command>.self)
            }else if curCmd.pointee.cmd == LC_SEGMENT_64 && SEG_LINKEDIT.equalToCChars(tuple: segname) {
                leCmd = curCmd
            }else if curCmd.pointee.cmd == LC_DYLD_CHAINED_FIXUPS {
                //read fixup-chains
                let ldDataCmd = unsafeBitCast(curCmd, to: UnsafePointer<linkedit_data_command>.self)
                var ptr = UInt(ldDataCmd.pointee.dataoff) + uintptr_t(bitPattern: header)
                let fixupHeader = UnsafePointer<dyld_chained_fixups_header>(bitPattern: ptr)
                if let fixup = fixupHeader {
                    
                    //symbols_format: 0 => uncompressed
                    if fixup.pointee.symbols_format == 0 {
                        print("import count = \(fixup.pointee.imports_count)")
                        let symbolStarts = UInt(fixup.pointee.symbols_offset) + ptr
                        var length : UInt = 0
                        for _ in 0 ..< fixup.pointee.imports_count {
                            let location = symbolStarts + length
                            let symbol = UnsafeMutablePointer<CChar>(bitPattern: UInt(location))
                            if let name = symbol{
                                length += UInt(strlen(name)) + 1
                                print(String.init(cString: name))
                            }
                        }
                    }else if fixup.pointee.symbols_format == 1{
                        //TODO: zlib compressed
                    }
                    
                    // foreach page chains
                    ptr = ptr + UInt(fixup.pointee.starts_offset)
                    let starts = ptr
                    let chainImage = UnsafePointer<dyld_chained_starts_in_image>(bitPattern: ptr)

                    var offPtr = 4 + ptr
                    for _ in 0 ..< (chainImage?.pointee.seg_count ?? 0) {
                        let off = UnsafePointer<UInt32>(bitPattern: offPtr)?.pointee ?? 0
                        offPtr += 4
                        if off != 0 {
                            let segPtr = starts + UInt(off)
                            let seg = UnsafePointer<dyld_chained_starts_in_segment>(bitPattern: segPtr)
                            if let segment = seg {
                                for pageIndex in 0 ..< segment.pointee.page_count {
                                    let offsetInPage : UInt16 = segment.pointee.page_start + 16 * pageIndex;
                                    if offsetInPage == DYLD_CHAINED_PTR_START_NONE {
                                        continue
                                    }
                                    //32-bit chains which may need multiple starts per page
                                    if (offsetInPage & UInt16( DYLD_CHAINED_PTR_START_MULTI)) != 0 {
                                        //TODO: multiple starts
                                        print("multiple starts per page")
                                    }else{
                                        // one chain per page
                                        let chainStart = UInt64(headPtr) + segment.pointee.segment_offset + UInt64(offsetInPage) + UInt64(pageIndex * segment.pointee.page_size)
                                        let chainContentPtr = UnsafePointer<UInt>(bitPattern: UInt(chainStart))
                                        print("page:\(pageIndex) first pointer = \(String(format: "0x%llx", chainStart)) chainContent = \(String(format: "0x%llx", (chainContentPtr?.pointee ?? 0)))")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        guard let linkedit = leCmd else{ return allBindInfoMap}
        guard let dyldCmd = dyCmd else { return allBindInfoMap}
        
        //read bind info
        var dyldInfoPtr = linkedit.pointee.vmaddr + UInt64(dyldCmd.pointee.bind_off) - linkedit.pointee.fileoff + UInt64(slide)
        let bindMap = ChubbyCatHook.bindingInfoMap(start: dyldInfoPtr, size:UInt64(dyldCmd.pointee.bind_size) , lazy: false, index: index)
        
        //read lazy-bind info
        dyldInfoPtr = linkedit.pointee.vmaddr + UInt64(dyldCmd.pointee.lazy_bind_off) - linkedit.pointee.fileoff + UInt64(slide)
        let lazyBindMap = ChubbyCatHook.bindingInfoMap(start: dyldInfoPtr, size:UInt64(dyldCmd.pointee.lazy_bind_size) , lazy: false, index: index)
        
        //read weak-bind info
        dyldInfoPtr = linkedit.pointee.vmaddr + UInt64(dyldCmd.pointee.weak_bind_off) - linkedit.pointee.fileoff + UInt64(slide)
        let weakBindMap = ChubbyCatHook.bindingInfoMap(start: dyldInfoPtr, size:UInt64(dyldCmd.pointee.weak_bind_size) , lazy: false, index: index)
        
        //combine all bind info map
        allBindInfoMap = allBindInfoMap.merging(bindMap, uniquingKeysWith: { value0, vale1 in
            return value0
        })
        allBindInfoMap = allBindInfoMap.merging(lazyBindMap, uniquingKeysWith: { value0, vale1 in
            return value0
        })
        allBindInfoMap = allBindInfoMap.merging(weakBindMap, uniquingKeysWith: { value0, vale1 in
            return value0
        })
        return allBindInfoMap
    }
    
    /**
     Create bind info map from Mach-O
     start: start location
     size: data length
     lazy: is lazy-bind，lazy-bind is different from bind & weak-bind
     */
    static func bindingInfoMap(start:UInt64,size:UInt64,lazy:Bool,index:UInt32) -> [String:UInt64] {
        let header:UnsafePointer<mach_header> = _dyld_get_image_header(index)
        let slide:Int = _dyld_get_image_vmaddr_slide(index)

        var map = [String:UInt64]()
        var byte : UInt8
        var end : Bool = false
        var symbol : UnsafeMutablePointer<CChar>? = nil
        var addr : UInt64 = 0
        var location : UInt64 = start
        
        // read bytes one by one
        while !end && location < start + size {
            
            byte = UnsafeMutablePointer<UInt8>(bitPattern: UInt(location))?.pointee ?? 0
            
            location += 1
            //opcode is jsut like operation code in assembler language
            let opcode = byte & UInt8(BIND_OPCODE_MASK)
            let immediate = byte & UInt8(BIND_IMMEDIATE_MASK)
            
            //if opcode end with xxx_DO_BIND, it means that the addr and symbol have been got
            switch opcode {
            case UInt8(BIND_OPCODE_DONE):
                end = lazy
            case UInt8(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM):
                symbol = UnsafeMutablePointer<CChar>(bitPattern: UInt(location))
                if let name = symbol {
                    location = location + UInt64(strlen(name))
                }
            case UInt8(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB):
                let value = ULEB128(location: &location)
                addr = getSegment(index:Int(immediate), header: header).0 + value
            case UInt8(BIND_OPCODE_ADD_ADDR_ULEB):
                let value = ULEB128(location: &location)
                addr &+= value
            case UInt8(BIND_OPCODE_DO_BIND):
                if let name = symbol {
                    map.updateValue(addr &+ UInt64(slide), forKey: String.init(cString: name))
                }
                addr += 8
            case UInt8(BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB):
                if let name = symbol {
                    map.updateValue(addr &+ UInt64(slide), forKey: String.init(cString: name))
                }
                addr += 8 + ULEB128(location: &location)
            case UInt8(BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED):
                if let name = symbol {
                    map.updateValue(addr &+ UInt64(slide), forKey: String.init(cString: name))
                }
                let scale = immediate
                addr &+= UInt64(8 + scale * 8)
                
            case UInt8(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB):
                if let name = symbol {
                    map.updateValue(addr &+ UInt64(slide), forKey: String.init(cString: name))
                }
                let count = ULEB128(location: &location)
                let skip = ULEB128(location: &location)
                addr &+= (8 + skip) * count
            case UInt8(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB):
                //it does nothing, but keeps the location growing
                _ = ULEB128(location: &location)
            case UInt8(BIND_OPCODE_SET_ADDEND_SLEB):
                //it does nothing, but keeps the location growing
                _ = SLEB128(location: &location)

            default:do {}
            }
        }
        return map
    }
}

extension String {
    /**
     Compare tuple (char array in C) and String
     tuple: char array in C
     return: is equal or not
     */
    func equalToCChars(tuple:(CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar)) -> Bool {
        var tmp = tuple
        //transfer tuple to array
        let array = [CChar](UnsafeBufferPointer(start: &tmp.0, count: MemoryLayout.size(ofValue: tmp)))
        let min = min(16, count + 1);
        for i in 0 ..< min {
            guard let ch = cString(using: .utf8) else { return false }
            if array[i] != ch[i]{
                return false
            }
        }
        return true
    }
}

//-------------------------------------------------------------//
typealias MYNSLogType = @convention(thin) (_ format: String, _ args: CVarArg...)  -> Void

func MYNSLog(_ format: String, _ args: CVarArg...){
    print("Test success! Call MYNSLog !")
}

@objc class Test: NSObject {
    @objc func test() {
        let replacement = unsafeBitCast(MYNSLog as MYNSLogType, to: UInt64.self)
        let ret = ChubbyCatHook.replaceC(name: "_NSLog", replacement:replacement)
        print("hook result = \(ret)")
    }
}

