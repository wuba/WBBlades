//
//  NSObject+WBBladesScanManager_AutoHook.m
//  WBBlades
//
// Created by 竹林七闲 on 2022/9/1.
//
#import "CDTextClassDumpVisitor.h"
#import "WBBladesInterface.h"
#import "WBBladesScanManager+AutoHook.h"
#import "ChainFixUpsHelper.h"
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_map.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach-o/ldsyms.h>
#import <mach-o/getsect.h>
#import <objc/runtime.h>
#import <WBBlades/WBBladesCMD.h>
#import "WBBladesDefines.h"
#import "WBBladesTool.h"
#import "CDTypeParser.h"
#import "CDTypeController.h"
#import "CDTypeFormatter.h"
#import "CDOCInstanceVariable.h"
#import "CDOCProperty.h"
#import "CDClassDump.h"
#import "CDTypeName.h"
#import "CDType.h"
#import "CDMethodType.h"

@class WBOCClass, CDTextClassDumpVisitor;
static NSMutableDictionary<NSNumber *, WBOCClass *> *OCClassInfos;
static NSMutableString *allSturctDefines;
static CDTextClassDumpVisitor *dumpVisitor ;
static NSMutableDictionary *anonymousStructs;
static int anonymousCount = 0;
static NSString * MachOName ;
static NSDictionary *dynamicBindingInfos = nil;

@interface WBOCMethod : NSObject
@property(nonatomic, copy) NSString *methodName;
@property(nonatomic, copy) NSString *methodTypes;
@property(nonatomic, copy) NSString *className;
@property(nonatomic, copy) NSString *CHHookCode;
@property(nonatomic, assign) BOOL isMeta;
@property(nonatomic, assign) BOOL unKnowType;
@property(nonatomic, strong) NSString *methodDeclareCode;
@property(nonatomic, strong) NSString *methodFullPathName;
@end

@implementation WBOCMethod
- (void)methodParse {
    CDTypeController * typeController = [[CDTypeController alloc] initWithClassDump:nil];
    NSMutableString *CHHookCode = [[NSMutableString alloc] init];
     NSMutableString *methodDeclareCode = [[NSMutableString alloc] init];
     NSMutableString *superDeclareCode = [[NSMutableString alloc] init];
     NSMutableString *methodInterfaceCode = [[NSMutableString alloc] init];
    [typeController.methodTypeFormatter formatCaptainMethodName:self.methodName typeString:self.methodTypes parserComplete:^(NSString *returnType, NSArray<NSString *> *methodLabels, NSArray<NSString *> *methodLabelTypes) {
        if (self.isMeta) {
            [methodDeclareCode appendFormat:@"\nCHOptimizedClassMethod"];
            [CHHookCode appendFormat:@"    CHClassHook%ld(%@", methodLabelTypes.count, self.className];
            [methodInterfaceCode appendFormat:@"+"];
        }else {
            [methodDeclareCode appendFormat:@"\nCHOptimizedMethod"];
            [CHHookCode appendFormat:@"    CHHook%ld(%@", methodLabelTypes.count, self.className];
            [methodInterfaceCode appendFormat:@"-"];
        }
        if ([returnType isEqualToString:@"void"]) {
            [superDeclareCode appendFormat:@"    CHSuper%ld(%@",methodLabelTypes.count, self.className];
        }else {
            [superDeclareCode appendFormat:@"    %@ ret = CHSuper%ld(%@",returnType, methodLabelTypes.count, self.className];
        }
        [methodInterfaceCode appendFormat:@"(%@)", returnType];
        [methodDeclareCode appendFormat:@"%ld(self, %@, %@", methodLabelTypes.count, returnType, self.className];
        if ([returnType isEqualToString:@"struct *"] || [returnType isEqualToString:@"struct"]) {
            self.unKnowType = YES;
        }
        for (int i = 0; i<methodLabels.count; i++) {
            if (methodLabels.count == methodLabelTypes.count) { //方法多参数场景
                if ([(NSString *)methodLabelTypes[i] isEqualToString:@"struct *"] || [(NSString *)methodLabelTypes[i] isEqualToString:@"struct"] ) {
                    self.unKnowType = YES;
                    break;
                }
                [methodDeclareCode appendFormat:@", %@, %@, arg%@", methodLabels[i], methodLabelTypes[i], @(i + 1)];
                [superDeclareCode appendFormat:@", %@, arg%@",  methodLabels[i], @(i + 1)];
                [CHHookCode appendFormat:@", %@", methodLabels[i]];
                [methodInterfaceCode appendFormat:@"%@: (%@)arg%@ ", methodLabels[i], methodLabelTypes[i],@(i + 1)];
            }else if(1 == methodLabels.count) {//没有参数的情况
                [methodDeclareCode appendFormat:@", %@", methodLabels[i]];
                [superDeclareCode appendFormat:@", %@",  methodLabels[i]];
                [CHHookCode appendFormat:@", %@", methodLabels[i]];
                [methodInterfaceCode appendFormat:@"%@", methodLabels[i]];
            }
        }
        [methodDeclareCode appendString:@") {\n"];
        [CHHookCode appendString:@");\n"];
        [superDeclareCode appendString:@");"];
        if (![returnType isEqualToString:@"void"]) {
            [superDeclareCode appendString:@"\n    return ret;"];
        }
        [superDeclareCode appendString:@"\n }\n"];
    }];
    self.methodDeclareCode = [NSString stringWithFormat:@"%@%@", methodDeclareCode, superDeclareCode];
    self.CHHookCode = CHHookCode;
    [methodInterfaceCode appendString:@";\n"];
    self.methodFullPathName = [methodInterfaceCode copy];
}
@end



@interface WBOCClass : NSObject
@property(nonatomic, copy) NSString *superClassName;
@property(nonatomic, assign) unsigned long long superisa;
@property(nonatomic, copy) NSString *name;
@property(nonatomic, copy) NSString *superImport;
@property(nonatomic, strong) NSMutableArray<WBOCMethod *> *intanceMethods;
@property(nonatomic, strong) NSMutableArray<WBOCMethod *> *classMethods;
@property(nonatomic, strong)NSMutableArray <CDOCInstanceVariable *>*instanceVariables;
@property(nonatomic, strong)NSMutableArray <CDOCProperty *>*instanceProperties;
@property(nonatomic, strong)NSMutableSet <NSString *>*importClasses;;
@end

@implementation WBOCClass
- (NSMutableArray<WBOCMethod *> *)intanceMethods {
    if (!_intanceMethods) {
        _intanceMethods = [@[] mutableCopy];
    }
    return _intanceMethods;
}

- (NSMutableArray<WBOCMethod *> *)classMethods {
    if (!_classMethods) {
        _classMethods = [@[] mutableCopy];
    }
    return _classMethods;
}

- (NSMutableArray<CDOCInstanceVariable *> *)instanceVariables {
    if (!_instanceVariables) {
        _instanceVariables = [@[] mutableCopy];
    }
    return _instanceVariables;
}

- (NSMutableArray<CDOCProperty *> *)instanceProperties {
    if (!_instanceProperties) {
        _instanceProperties = [@[] mutableCopy];
    }
    return _instanceProperties;
}

- (NSMutableSet<NSString *> *)importClasses {
    if (!_importClasses) {
        _importClasses = [NSMutableSet new];
    }
    return _importClasses;
}

@end

@implementation WBBladesScanManager (AutoHook)

+ (void)endAutoHookProcess {
    OCClassInfos = nil;
    allSturctDefines  = nil;
    dumpVisitor = nil;
    anonymousStructs = nil;
    anonymousCount = 0;
    MachOName = nil;
    dynamicBindingInfos = nil;
}

+ (NSArray *)getAllOCClasses:(NSString *)filePath  {
    //清空全局变量
    OCClassInfos = nil;
    allSturctDefines  = nil;
    dumpVisitor = nil;
    anonymousStructs = nil;
    dynamicBindingInfos = nil;
    anonymousCount = 0;
    MachOName = [filePath lastPathComponent];//static library's name
    [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n%@%@", [WBBladesInterface shareInstance].autoHookInfos, @"分析文件---", MachOName];
    removeCopyFile(filePath);//remove file
    copyFile(filePath);//copy file
    [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n%@", [WBBladesInterface shareInstance].autoHookInfos, @"正在提取arm64架构"];
    thinFile(filePath);//arm64 file
    NSString *copyPath = [filePath stringByAppendingString:@"_copy"];

    NSData *fileData = [NSData dataWithContentsOfFile:copyPath];
    mach_header_64 mhHeader;
    [fileData getBytes:&mhHeader range:NSMakeRange(0, sizeof(mach_header_64))];
    if (mhHeader.filetype != MH_EXECUTE && mhHeader.filetype != MH_DYLIB) {
        [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n%@", [WBBladesInterface shareInstance].autoHookInfos, @"当前文件不是可执行文件"];
        removeCopyFile(filePath);//remove file
        return nil;
    }

    [[ChainFixUpsHelper shareInstance] fileLoaderWithFileData:fileData];
    section_64 classList = {0};

    segment_command_64 linkEdit = {0};

    unsigned long long currentLcLocation = sizeof(mach_header_64);
    for (int i = 0; i < mhHeader.ncmds; i++) {
        load_command *cmd = (load_command *)malloc(sizeof(load_command));
        [fileData getBytes:cmd range:NSMakeRange(currentLcLocation, sizeof(load_command))];

        if (cmd->cmd == LC_SEGMENT_64) {//LC_SEGMENT_64:(section header....)

            segment_command_64 segmentCommand;
            [fileData getBytes:&segmentCommand range:NSMakeRange(currentLcLocation, sizeof(segment_command_64))];
            NSString *segName = [NSString stringWithFormat:@"%s",segmentCommand.segname];

            //enumerate classlist、selref、classref、nlcls、cfstring section
            if ((segmentCommand.maxprot &( VM_PROT_WRITE | VM_PROT_READ)) == (VM_PROT_WRITE | VM_PROT_READ)) {
                //enumerate section header
                unsigned long long currentSecLocation = currentLcLocation + sizeof(segment_command_64);
                for (int j = 0; j < segmentCommand.nsects; j++) {

                    section_64 sectionHeader;
                    [fileData getBytes:&sectionHeader range:NSMakeRange(currentSecLocation, sizeof(section_64))];
                    NSString *secName = [[NSString alloc] initWithUTF8String:sectionHeader.sectname];

                    //note classlist
                    if ([secName isEqualToString:DATA_CLASSLIST_SECTION] ||
                        [secName isEqualToString:CONST_DATA_CLASSLIST_SECTION]) {
                        classList = sectionHeader;
                    }
                    currentSecLocation += sizeof(section_64);
                }
            } else if([segName isEqualToString:SEGMENT_LINKEDIT]){
                linkEdit = segmentCommand;
            }
        }
        currentLcLocation += cmd->cmdsize;
        free(cmd);

    }
    NSMutableArray *classes = [@[] mutableCopy];
    [self readClsRefList:classList classes:classes fileData:fileData];

    [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n%@", [WBBladesInterface shareInstance].autoHookInfos, @"Hook完成！"];
    [WBBladesInterface shareInstance].autoHookFinished = YES;
    removeCopyFile(filePath);//remove file
    return nil;
}
+ (void)readClsRefList:(section_64)classrefList  classes:(NSMutableArray *)OCClasses fileData:(NSData *)fileData {
    NSRange range = NSMakeRange(classrefList.offset, 0);
    OCClassInfos = [NSMutableDictionary new];
    NSString *documentPath = [NSSearchPathForDirectoriesInDomains(NSDesktopDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    NSString *fileDocument = [[NSString stringWithFormat:@"%@/%@", documentPath, @"WBBladers-RuntimeProject"] stringByAppendingPathComponent:MachOName];
    [[NSFileManager defaultManager] removeItemAtPath:fileDocument error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:fileDocument withIntermediateDirectories:YES attributes:nil error:nil];
    allSturctDefines = [@"" mutableCopy];
    NSMutableSet *allStructNames = [NSMutableSet set];
    NSMutableSet *partSystermStructNames = [self systermSturctNames];
    NSString *preAutoHookInfos = [WBBladesInterface shareInstance].autoHookInfos;
    for (int i = 0; i < classrefList.size / 8; i++) {
           @autoreleasepool {
//               WBOCClass *OCClass = [self getOCClassFromClassref:]
               unsigned long long classAddress;
               unsigned long long isaAddress;
               NSData *data = [WBBladesTool readBytes:range length:8 fromFile:fileData];
               [data getBytes:&classAddress range:NSMakeRange(0, 8)];
               isaAddress = classAddress;
               classAddress = [WBBladesTool getOffsetFromVmAddress:classAddress fileData:fileData];
               if(![[ChainFixUpsHelper shareInstance]validateSectionWithFileoffset:classAddress sectionName:@"__objc_data"]){
                   //如果该地址经过运算的取值在importSymbolPool范围内则为外部动态库的类
                   continue;
               }
               class64 targetClass = {0};
               NSRange targetClassRange = NSMakeRange(classAddress, 0);
               data = [WBBladesTool readBytes:targetClassRange length:sizeof(class64) fromFile:fileData];
               [data getBytes:&targetClass length:sizeof(class64)];

               //class info struct
               class64Info targetClassInfo = {0};
               unsigned long long targetClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.data fileData:fileData];
               if (OCClassInfos[@(isaAddress)]) {
                   continue;
               }
               WBOCClass *ocClass = [WBOCClass new];
               OCClassInfos[@(isaAddress)] = ocClass;
               ocClass.superisa = targetClass.superClass;
               if (ocClass.superisa & 0x8000000000000000) { //chain rebind 的标识
                   WBChainFixupImportSymbol *importSymbol = [ChainFixUpsHelper shareInstance].bindAdreesInfos[@(classAddress + 8)];
                   ocClass.superClassName = [importSymbol.importSymbolName componentsSeparatedByString:@"$_"].lastObject;
                   ocClass.superImport = [importSymbol.dylibName componentsSeparatedByString:@"/"].lastObject;
                   if ([ocClass.superImport isEqualToString:@"libobjc.A.dylib"]) {
                       ocClass.superImport = @"Foundation";
                   }
               }else if (0 == ocClass.superisa){ //iOS13以下， 系统类的判断方式
                   if (!dynamicBindingInfos) {
                       dynamicBindingInfos = [WBBladesTool dynamicBindingInfoFromFile:fileData];
                   }
                   //+8是因为isa的下一个是superclass，详见class64的数据结构
                   NSDictionary *dic = dynamicBindingInfos[@(classAddress + 8)];
                   //+8是因为isa的下一个是superclass，详见class64的数据结构
                   //如果动态库， bindingInfo的计算方式是从0开始， 但是如果是ipa里的可执行文件， bindingInfo的地址是从0x0000000100000000开始。但是Mach-O里的地址要从零计算
                   if (!dic) { //如果是App的Mach-O，添加偏移
                       dic = dynamicBindingInfos[@(0x0000000100000000 + classAddress + 8)];
                   }
                   ocClass.superClassName = [dic[@"symbolName"] componentsSeparatedByString:@"$_"].lastObject;
                   ocClass.superImport = [dic[@"dylibName"] componentsSeparatedByString:@"/"].lastObject;
                   if (!ocClass.superClassName) {
                       //待定，需要进一步研究iOS13-下bindinfo的数据结构
                       long  superClassAddress = [WBBladesTool getOffsetFromVmAddress:classAddress fileData:fileData];
                       NSRange metaClassRange = NSMakeRange(classAddress, 0);
                       data = [WBBladesTool readBytes:metaClassRange length:sizeof(long) fromFile:fileData];
                       [data getBytes:&superClassAddress length:sizeof(long)];
                       NSDictionary *dic = dynamicBindingInfos[@(superClassAddress)];
                       ocClass.superClassName = [dic[@"symbolName"] componentsSeparatedByString:@"$_"].lastObject;
                       ocClass.superImport = [dic[@"dylibName"] componentsSeparatedByString:@"/"].lastObject;
                   }
                   if ([ocClass.superImport isEqualToString:@"libobjc.A.dylib"]) {
                       ocClass.superImport = @"Foundation";
                   }
               }
               targetClassInfoOffset = (targetClassInfoOffset / 8) * 8;
               NSRange targetClassInfoRange = NSMakeRange(targetClassInfoOffset, 0);
               data = [WBBladesTool readBytes:targetClassInfoRange length:sizeof(class64Info) fromFile:fileData];
               [data getBytes:&targetClassInfo length:sizeof(class64Info)];
               unsigned long long classNameOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.name fileData:fileData];

               class64 metaClass = {0};
               unsigned long long metaClassOffset = [WBBladesTool getOffsetFromVmAddress:targetClass.isa fileData:fileData];
               NSRange metaClassRange = NSMakeRange(metaClassOffset, 0);
               data = [WBBladesTool readBytes:metaClassRange length:sizeof(class64) fromFile:fileData];
               [data getBytes:&metaClass length:sizeof(class64)];

               class64Info metaClassInfo = {0};
               unsigned long long metaClassInfoOffset = [WBBladesTool getOffsetFromVmAddress:metaClass.data fileData:fileData];
               metaClassInfoOffset = (metaClassInfoOffset / 8) * 8;
               NSRange metaClassInfoRange = NSMakeRange(metaClassInfoOffset, 0);
               data = [WBBladesTool readBytes:metaClassInfoRange length:sizeof(class64Info) fromFile:fileData];
               [data getBytes:&metaClassInfo length:sizeof(class64Info)];

               unsigned long long methodListOffset = [WBBladesTool getOffsetFromVmAddress:targetClassInfo.baseMethods fileData:fileData];
               unsigned long long classMethodListOffset = [WBBladesTool getOffsetFromVmAddress:metaClassInfo.baseMethods fileData:fileData];

               char *classname = (char *)[fileData bytes] + classNameOffset;
               NSString * className = @(classname);
               ocClass.name = className;
               //Mach-O过大， 会造成占用非常大的内存，这里只能缓存一部分内容
               [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n当前正在提取Class：%@", preAutoHookInfos, className];
               if (targetClassInfo.instanceVariables > 0) {
                   [self scanIvars:[WBBladesTool getOffsetFromVmAddress:targetClassInfo.instanceVariables fileData:fileData] class:ocClass fileData:fileData];
               }
               if (targetClassInfo.baseProperties > 0) {
                   [self scanProperty:[WBBladesTool getOffsetFromVmAddress:targetClassInfo.baseProperties fileData:fileData] class:ocClass fileData:fileData];
               }
               if (methodListOffset > 0) {
                   [self scanMethodListResult:methodListOffset class:ocClass  fileData:fileData isMeta:NO];
               }
               if (classMethodListOffset > 0) {
                   [self scanMethodListResult:classMethodListOffset class:ocClass  fileData:fileData isMeta:YES];
               }
            }
        }
    ChainFixUpsHelper *helper = [ChainFixUpsHelper shareInstance];
    NSArray *dylibNames = nil;
    if (helper.isChainFixups) {
        dylibNames = helper.dylibNames;
    }else {
        dylibNames = [WBBladesTool dylibNamesFromFile:fileData];
    }
    NSSet <NSString *> *allImportSets =  [self allImportsForDynamicNames:dylibNames];
    NSArray *allImports = [allImportSets allObjects];
    NSString *importCotent = [allImports componentsJoinedByString:@"\n"];
    preAutoHookInfos = [WBBladesInterface shareInstance].autoHookInfos;
    [OCClassInfos enumerateKeysAndObjectsUsingBlock:^(NSNumber * _Nonnull key, WBOCClass * _Nonnull obj, BOOL * _Nonnull stop) {
        [WBBladesInterface shareInstance].autoHookInfos = [NSString stringWithFormat:@"%@\n正在生成Hook文件内容：%@", preAutoHookInfos, obj.name];
        NSMutableString *hContents = [@"" mutableCopy];
        NSMutableString *mContents = [@"" mutableCopy];
        if (obj.superImport) {
            //如果父类是系统类， 则通过allImportSets引入， 就不单独引入了。 因为NSURLSession 会变成<dyld/dyld.h>
//            [hContents appendFormat:@"#import<%@/%@.h>\n", obj.superImport, obj.superImport];
            [hContents appendString:@"#ifndef WBB_DyanmicHeaders\n"];
            [hContents appendString:@"#define WBB_DyanmicHeaders\n"];
            [hContents appendString:@"#import \"WBBladerAllDyanmicHeaders.h\"\n"];
            [hContents appendString:@"#endif\n"];
        }else {
            WBOCClass *superClass = OCClassInfos[@(obj.superisa)];
            [hContents appendFormat:@"#import\"%@.h\"\n", superClass.name];
            obj.superClassName = superClass.name;
            obj.instanceVariables = [self subClassVariables:obj.instanceVariables diffSuperVariables: superClass.instanceVariables];
        }

        if (obj.importClasses.count > 0) {
            [hContents appendString:@"@class "];
            [obj.importClasses enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, BOOL * _Nonnull stop) {
                [hContents appendFormat:@"%@, ", obj];
            }];
            [hContents replaceCharactersInRange:NSMakeRange(hContents.length - 2, 2) withString:@";\n"];
        }

        [mContents appendFormat:@"#import \"%@\"\n#import \"%@.h\"\n", @"CaptainHook.h", obj.name];
        [hContents appendFormat:@"@interface %@: %@ {\n", obj.name, obj.superClassName];

        dumpVisitor = [CDTextClassDumpVisitor new];
        dumpVisitor.classDump = [CDClassDump new];
        dumpVisitor.resultString = hContents;
        [obj.instanceVariables enumerateObjectsUsingBlock:^(CDOCInstanceVariable * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            if (obj.type.members.count > 0 || obj.type.subtype.members.count > 0) {
                [hContents appendString:@"/*\n"];
                //
                //提取所有struct到统一的头文件中
                NSString *anmousStructName = @"";
                if ([obj.type.typeName.name isEqualToString:@"?"] || [obj.type.subtype.typeName.name isEqualToString:@"?"]) {
                    [self anonymousWithType:obj.type];
                }else {
                    CDType *type = [obj type]; // Parses it, if necessary;
                    NSString *typeName = type.typeName.name ?: type.subtype.typeName.name;
                    if (obj.parseError == nil && ![allStructNames containsObject:typeName] && ![partSystermStructNames containsObject:typeName]) {
                        NSString *formattedString = [[dumpVisitor.classDump.typeController ivarTypeFormatter] formatVariable:obj.name type:type];
                        NSString *structDefine = [self structDefineContent:formattedString structName:typeName isUnKownStructName:anmousStructName];
                        if(structDefine.length > 0) {
                            [allSturctDefines appendFormat:@"%@\n\n", structDefine];
                            if (typeName) {
                                [allStructNames addObject:typeName];
                            }
                        }
                  }
                }
                [dumpVisitor visitIvar:obj];
                [hContents appendString:@"*/\n"];
                //当接口中出现未识别出struct名称的变量时，直接注释
                if (![obj.type.typeName.name isEqualToString:@"?"] && obj.type.typeName.name.length > 0) {
                    [hContents appendFormat:@"    struct %@ %@;\n", obj.type.typeName.name, obj.name];
                }else {
                    NSString * anmousStructName = [self anonymousWithType:obj.type];
                    if (anmousStructName) {
                        [hContents appendFormat:@"    struct %@ %@;\n",anmousStructName, obj.name];
                    }else {
                        [hContents appendFormat:@"    //struct %@ %@;\n", obj.type.typeName.name, obj.name];
                    }
                }

            }else {
                [dumpVisitor visitIvar:obj];
            }

        }];
        [hContents appendFormat:@"\n}\n"];
        [obj.instanceProperties enumerateObjectsUsingBlock:^(CDOCProperty * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            if ([obj.type.typeString  hasPrefix:@"^{?="])  {
                [hContents appendString:@"/*\n"];
                [dumpVisitor visitProperty:obj parsedType:obj.type attributes:obj.attributes];
                [hContents appendString:@"*/\n"];
            }else {
                [dumpVisitor visitProperty:obj parsedType:obj.type attributes:obj.attributes];
            }
        }];

        NSMutableString *chConstructorContent = [@"" mutableCopy];
        if (obj.intanceMethods.count > 0 || obj.classMethods.count > 0) {
            [mContents appendFormat:@"\nCHDeclareClass(%@);\n",  obj.name];
            [chConstructorContent appendFormat:@"\nCHConstructor{\n    CHLoadLateClass(%@);\n", obj.name];
        }

        NSMutableSet *instanceMethodNames = [[NSMutableSet alloc] init]; //解决CaptionHook实例方法与类方法冲突的问题
        [obj.intanceMethods enumerateObjectsUsingBlock:^(WBOCMethod * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            [obj methodParse];
            if (!obj.unKnowType) {
                [instanceMethodNames addObject:obj.methodName];
                [hContents appendString:obj.methodFullPathName];
                [mContents appendString:obj.methodDeclareCode];
                [chConstructorContent appendString:obj.CHHookCode];
            }else {
                [hContents appendFormat:@"//%@", obj.methodFullPathName];
            }
        }];
        [obj.classMethods enumerateObjectsUsingBlock:^(WBOCMethod * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            if ([instanceMethodNames containsObject:obj.methodName]) {
                return;
            }
            [obj methodParse];
            if (!obj.unKnowType) {
                [hContents appendString:obj.methodFullPathName];
                [mContents appendString:obj.methodDeclareCode];
                [chConstructorContent appendString:obj.CHHookCode];
            }else {
                [hContents appendFormat:@"//%@", obj.methodFullPathName];
            }
        }];
        if (obj.intanceMethods.count > 0 || obj.classMethods.count > 0) {
            [chConstructorContent appendString:@"}\n"];
            [mContents appendString:chConstructorContent];
        }


        [hContents appendFormat:@"@end"];

        NSString *fileHPath = [NSString stringWithFormat:@"%@/%@.h", fileDocument, obj.name];
        NSString *fileMPath = [NSString stringWithFormat:@"%@/%@.m", fileDocument, obj.name];
        [hContents writeToFile:fileHPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [mContents writeToFile:fileMPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }];
    NSString *fileIMPortPath = [NSString stringWithFormat:@"%@/%@.h", fileDocument, @"WBBladerAllDyanmicHeaders"];
    if (allSturctDefines.length > 0) {
        importCotent = [NSString stringWithFormat:@"%@\n\n%@", importCotent, allSturctDefines];
    }
    [importCotent writeToFile:fileIMPortPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    NSString *captainHookPath = [[NSBundle mainBundle] pathForResource:@"CaptainHook" ofType:@"txt"];
    NSString *captainContent = [NSString stringWithContentsOfFile:captainHookPath encoding:NSUTF8StringEncoding error:nil];
    NSString *fileCPath = [NSString stringWithFormat:@"%@/%@.h", fileDocument, @"CaptainHook"];
    [captainContent writeToFile:fileCPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

+ (void)scanIvars:(unsigned long long)ivarListOffset  class:(WBOCClass *)ocClass   fileData:(NSData*)fileData {
    ivar64_list_t ivarList = {0};

    NSRange methodRange = NSMakeRange(ivarListOffset, 0);
    NSData* data = [WBBladesTool readBytes:methodRange length:sizeof(method64_list_t) fromFile:fileData];
    ivarListOffset += sizeof(ivar64_list_t);
    [data getBytes:&ivarList length:sizeof(method64_list_t)];
    for (int i = 0; i < ivarList.count; i++) {
        ivar64_t ivar_t = {0};
        NSRange ivarRange = NSMakeRange(ivarListOffset, 0);
        NSData* data = [WBBladesTool readBytes:ivarRange length:sizeof(ivar64_t) fromFile:fileData];
        [data getBytes:&ivar_t length:sizeof(ivar64_t)];
        if(ivar_t.name != 0) {
            char *ivarName = (char *)[fileData bytes] + (ivar_t.name & ChainFixUpsRawvalueMask);
            char *ivarTypes = (char *)[fileData bytes] + (ivar_t.type & ChainFixUpsRawvalueMask);
            CDOCInstanceVariable *instanceVariable = [[CDOCInstanceVariable alloc] initWithName:@(ivarName) typeString:@(ivarTypes) offset:ivar_t.offset];
            CDType *cdtype = instanceVariable.type;
            if(cdtype.typeName.name.length > 0 && (cdtype.isNamedObject)) {
                [ocClass.importClasses addObject:cdtype.typeName.name];
            }
            ivarListOffset += sizeof(ivar64_t);
            [ocClass.instanceVariables addObject:instanceVariable];
        }
    }
}

+ (void)scanProperty:(unsigned long long)propertyListOffset  class:(WBOCClass *)ocClass   fileData:(NSData*)fileData {
    property_list_t propertyList = {0};

    NSRange methodRange = NSMakeRange(propertyListOffset, 0);
    NSData* data = [WBBladesTool readBytes:methodRange length:sizeof(property_list_t) fromFile:fileData];
    propertyListOffset += sizeof(property_list_t);
    [data getBytes:&propertyList length:sizeof(property_list_t)];
    NSMutableSet *nameSets = [[NSMutableSet alloc] init];
    for (int i = 0; i < propertyList.count; i++) {
        property_t p_t = {0};
        NSRange propertyRange = NSMakeRange(propertyListOffset, 0);
        NSData* data = [WBBladesTool readBytes:propertyRange length:sizeof(property_t) fromFile:fileData];
        [data getBytes:&p_t length:sizeof(property_t)];
        NSString *name =  @((char *)[fileData bytes] + (p_t.name & ChainFixUpsRawvalueMask));
        NSString *attributes = @((char *)[fileData bytes] + (p_t.attributes & ChainFixUpsRawvalueMask));
        CDOCProperty *ocProperty = [[CDOCProperty alloc] initWithName:name attributes:attributes];
        if(ocProperty.type.typeName.name.length > 0 && (ocProperty.type.isNamedObject)) {
            [ocClass.importClasses addObject:ocProperty.type.typeName.name];
        }
        if(name && ![nameSets containsObject:name]) {
            [ocClass.instanceProperties addObject:ocProperty];
            [nameSets addObject:name];
        }

        propertyListOffset += sizeof(property_t);

    }
}

//CDOCProperty
+ (NSDictionary *)scanMethodListResult:(unsigned long long)methodListOffset
                            class:(WBOCClass *)ocClass
                             fileData:(NSData*)fileData
                                isMeta:(BOOL)isMeta {

    unsigned long long max = [fileData length];
    method64_list_t methodList;

    NSRange methodRange = NSMakeRange(methodListOffset, 0);
    NSData* data = [WBBladesTool readBytes:methodRange length:sizeof(method64_list_t) fromFile:fileData];
    [data getBytes:&methodList length:sizeof(method64_list_t)];
    NSMutableDictionary *crashSymbolRst = [NSMutableDictionary dictionary];
    if((methodList.entsize & 0x80000000) !=0){
        for (int j = 0; j<methodList.count; j++) {
            //获取方法名
            unsigned long long relative_method_start = methodListOffset + sizeof(method64_list_t) + sizeof(relative_method_t) * j;
            methodRange = NSMakeRange(relative_method_start , 0);
            data = [WBBladesTool readBytes:methodRange length:sizeof(relative_method_t) fromFile:fileData];

            relative_method_t relative_method;
            [data getBytes:&relative_method length:sizeof(relative_method_t)];
            unsigned long long name = relative_method_start + relative_method.nameOffset;
            unsigned long long type = relative_method_start + relative_method.typesOffset + 4;
            //方法名最大150字节
//            uint8_t * buffer = (uint8_t *)malloc(METHODNAME_MAX_LEN + 1); buffer[METHODNAME_MAX_LEN] = '\0';
                unsigned long long  classMethodNameAddress;
                [fileData getBytes:&classMethodNameAddress range:NSMakeRange(name, 8)];
//                [fileData getBytes:buffer range:NSMakeRange(classMethodNameAddress & ChainFixUpsRawvalueMask,METHODNAME_MAX_LEN)];
            const char *classmethodname = (char *)[fileData bytes] + (classMethodNameAddress & ChainFixUpsRawvalueMask);
            const char *types = (char *)[fileData bytes] + (type & ChainFixUpsRawvalueMask);
            NSString * methodName = @(classmethodname);
            //获取types
//            [fileData getBytes:buffer range:NSMakeRange(type & ChainFixUpsRawvalueMask,METHODNAME_MAX_LEN)];

            //type 和 name的取值方式不同，type直接取值即可，name需要取值两次，原因如下
            //name 在__DATA,__data中， 其值指向了__DATA, __objc_selrefs 其值指向了__Text,__objc_methname
            //type 在__DATA,__data中， 其值直接指向了__Text,__objc_methtype
            //type & ChainFixUpsRawvalueMask 进行地址修正
            WBOCMethod *method = [WBOCMethod new];
            method.methodName = methodName;
            method.methodTypes = @(types);
            method.className = ocClass.name;
            if (!isMeta) {
                if(![method.methodName hasPrefix:@".cxx"] && ![method.methodName hasPrefix:@"dealloc"] && ![method.methodName hasPrefix:@"init"]) {
                    [ocClass.intanceMethods addObject:method];
                    method.isMeta = NO;
                }
            }else {
                [ocClass.classMethods addObject:method];
                method.isMeta = YES;
            }

//            free(buffer);
        }
    }else{
        for (int j = 0; j<methodList.count; j++) {
            //获取方法名
            methodRange = NSMakeRange(methodListOffset + sizeof(method64_list_t) + sizeof(method64_t) * j, 0);
            data = [WBBladesTool readBytes:methodRange length:sizeof(method64_t) fromFile:fileData];

            method64_t method;
            [data getBytes:&method length:sizeof(method64_t)];
            unsigned long long methodNameOffset = [WBBladesTool getOffsetFromVmAddress:method.name fileData:fileData];//method.name;
            unsigned long long typesOffset = [WBBladesTool getOffsetFromVmAddress:method.types fileData:fileData];//method.name;
            WBOCMethod *ocMethod = [WBOCMethod new];
            ocMethod.className = ocClass.name;

//            method.methodTypes = types;
            //方法名最大150字节
//            uint8_t * buffer = (uint8_t *)malloc(METHODNAME_MAX_LEN + 1); buffer[METHODNAME_MAX_LEN] = '\0';
            if (methodNameOffset > 0 && methodNameOffset < max) {
                const char *classmethodname = (char *)[fileData bytes] + methodNameOffset;
                ocMethod.methodName = @(classmethodname);
            }
            if (typesOffset > 0 && typesOffset < max) {
                const char *types = (char *)[fileData bytes] + typesOffset;
                ocMethod.methodTypes = @(types);
            }

            if (!isMeta) {
                if(![ocMethod.methodName hasPrefix:@".cxx"] && ![ocMethod.methodName hasPrefix:@"dealloc"] && ![ocMethod.methodName isEqualToString:@"init"]) {
                    [ocClass.intanceMethods addObject:ocMethod];
                    ocMethod.isMeta = NO;
                }
            }else {
                [ocClass.classMethods addObject:ocMethod];
                ocMethod.isMeta = YES;
            }
        }
    }
    return crashSymbolRst.copy;
}

+ (WBOCClass *)getOCClassFromClassref:(section_64)claFssref {
    return  nil;
}

+ (NSMutableArray <CDOCInstanceVariable *> *) subClassVariables:(NSArray<CDOCInstanceVariable *> *)subVariables diffSuperVariables:(NSArray<CDOCInstanceVariable *> *)superVariables {
    NSMutableArray *diffs = [@[] mutableCopy];
    NSMutableSet *superVariableNames = [[NSMutableSet alloc] init];
    [superVariables enumerateObjectsUsingBlock:^(CDOCInstanceVariable *  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if (obj.name) {
            [superVariableNames addObject:obj.name];
        }
    }];
    [subVariables enumerateObjectsUsingBlock:^(CDOCInstanceVariable *  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *subName = obj.name;
        if (![superVariableNames containsObject:subName]) {
            [diffs addObject:obj];
        }
    }];
    return diffs;
}

//Macho中提取依赖系统动态库信息， 确认系统动态库的引用代码
+ (NSSet <NSString *> *)allImportsForDynamicNames:(NSArray<NSString *> *)dynamicNames {
    NSDictionary *nameMapImports = @{
        @"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": @"#import <CoreFoundation/CoreFoundation.h>",
        @"/System/Library/Frameworks/UIKit.framework/UIKit": @"#import <UIKit/UIKit.h>",
        @"/usr/lib/libobjc.A.dylib": @"#import <Foundation/Foundation.h>",
        @"/usr/lib/libSystem.B.dylib": @"#import <CoreFoundation/CoreFoundation.h>",
        @"/System/Library/Frameworks/Security.framework/Security": @"#import <Security/Security.h>",
        @"/System/Library/Frameworks/CFNetwork.framework/CFNetwork": @"#import <CFNetwork/CFNetwork.h>",
        @"/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics": @"#import <CoreGraphics/CoreGraphics.h>",
        @"/System/Library/Frameworks/CoreMedia.framework/CoreMedia": @"#import <CoreMedia/CoreMedia.h>",
        @"/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony": @"#import <CoreTelephony/CTCarrier.h>\n#import <CoreTelephony/CTTelephonyNetworkInfo.h>\n#import <CoreTelephony/CTCallCenter.h>\n#import <CoreTelephony/CTCall.h>",
        @"/System/Library/Frameworks/CoreVideo.framework/CoreVideo": @"#import <CoreVideo/CoreVideo.h>",
        @"/System/Library/Frameworks/Foundation.framework/Foundation": @"#import <Foundation/Foundation.h>",
        @"/System/Library/Frameworks/ImageIO.framework/ImageIO": @"#import <ImageIO/ImageIO.h>",
        @"/System/Library/Frameworks/MediaPlayer.framework/MediaPlayer": @"#import <MediaPlayer/MediaPlayer.h>",
        @"/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices": @"#import <MobileCoreServices/MobileCoreServices.h>",
        @"/System/Library/Frameworks/QuartzCore.framework/QuartzCore": @"#import <QuartzCore/QuartzCore.h>",
        @"/System/Library/Frameworks/StoreKit.framework/StoreKit": @"#import <StoreKit/StoreKit.h>",
        @"/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration": @"#import <SystemConfiguration/SystemConfiguration.h>",
        @"/System/Library/Frameworks/WebKit.framework/WebKit": @"#import <WebKit/WebKit.h>",
        @"/System/Library/Frameworks/AdSupport.framework/AdSupport": @"#import <AdSupport/AdSupport.h>",
        @"/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore": @"#import <JavaScriptCore/JavaScriptCore.h>",
        @"/System/Library/Frameworks/SafariServices.framework/SafariServices": @"#import <SafariServices/SafariServices.h>",
        @"/System/Library/Frameworks/CoreImage.framework/CoreImage": @"#import <CoreImage/CoreImage.h>",
        @"/System/Library/Frameworks/CoreText.framework/CoreText": @"#import <CoreText/CoreText.h>",
        @"/System/Library/Frameworks/CoreLocation.framework/CoreLocation": @"#import <CoreLocation/CoreLocation.h>",
        @"/System/Library/Frameworks/CoreMotion.framework/CoreMotion": @"#import <CoreMotion/CoreMotion.h>",
        @"/System/Library/Frameworks/Accelerate.framework/Accelerate": @"#import <Accelerate/Accelerate.h>",
        @"/System/Library/Frameworks/AppTrackingTransparency.framework/AppTrackingTransparency": @"#import <AppTrackingTransparency/AppTrackingTransparency.h>",
        @"/System/Library/Frameworks/GLKit.framework/GLKit": @"#import <GLKit/GLKit.h>"
    };
    NSMutableSet *imports = [[NSMutableSet alloc] init];
    [dynamicNames enumerateObjectsUsingBlock:^(NSString * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if (nameMapImports[obj]) {
            [imports addObject: nameMapImports[obj]];
        }
    }];
    return [imports copy];
}


+ (NSSet <NSString *> *)systermSturctNames {
    return [NSSet setWithObjects:@"_opaque_pthread_mutex_t", @"_opaque_pthread_rwlock_t", @"_opaque_pthread_mutexattr_t", @"CGSize", @"CGColor", @"CGRect", @"CGPoint", @"CMAcceleration", @"tm", nil];
}

+ (NSString *)structDefineContent:(NSString *)ivarTypeFormatter structName:(NSString *)structName isUnKownStructName:(NSString *)anmousStructName {
//    struct _opaque_pthread_mutex_t {                  typedef struct _opaque_pthread_mutex_t {
//        long long __sig;                 =>                long long __sig;
//        char __opaque[56];                                 char __opaque[56];
//    } _DB;                                             } _opaque_pthread_mutex_t;
    if (anmousStructName.length > 0) {
        structName = anmousStructName;
    }
    NSString *replaceLast = [[ivarTypeFormatter componentsSeparatedByString:@"}"] lastObject];
    NSString *replacePre = [[ivarTypeFormatter componentsSeparatedByString:@"{"] firstObject];
    if (replacePre.length >0 && replaceLast.length > 0) {
        ivarTypeFormatter = [ivarTypeFormatter stringByReplacingCharactersInRange:NSMakeRange(0, replacePre.length) withString:[NSString stringWithFormat:@"typedef struct %@ ", structName]];
        return  ivarTypeFormatter = [ivarTypeFormatter stringByReplacingCharactersInRange:NSMakeRange(ivarTypeFormatter.length - replaceLast.length,  replaceLast.length) withString:[NSString stringWithFormat:@" %@;", structName]];
    }
    return nil;
}

+ (NSString *)anonymousWithType:(CDType *)structType {
    //{?="mmmmm"B"ddddd"Q"cccccc"Q"eeeeeee"d"gggggg"d} => {"BQQdd": "anonymous_1"}
    if (!anonymousStructs) {
        anonymousStructs = [@{} mutableCopy];
    }

//    NSString *formattedString = [[dumpVisitor.classDump.typeController ivarTypeFormatter] formatVariable:obj.name type:type];
    NSString *structDesc = structType.typeString;
    if (![structDesc hasPrefix:@"^{?="] && ![structDesc hasPrefix:@"{?="] && ![structDesc hasSuffix:@"}"]) {
        return @"?";
    }

    NSArray *structCompents = [structDesc componentsSeparatedByString:@"\""];
    if (structCompents && (0 == structCompents.count % 2)) {
        NSMutableArray *structCompentsM = [structCompents mutableCopy];
        for (int i = 0;  i < structCompents.count; i++) {
            if( 0 == i%2) {
                [structCompentsM addObject:structCompents[i]];
            }
        }
        structCompents = structCompentsM;
    }

    BOOL isPointer = NO;
    NSString *structTypesDesc = [structCompents componentsJoinedByString:@""];
    if ([structDesc hasPrefix:@"^{?="]) {
        isPointer = YES;
        structTypesDesc = [structTypesDesc substringWithRange:NSMakeRange(4, structTypesDesc.length - 5)];
    }else {
        structTypesDesc = [structTypesDesc substringWithRange:NSMakeRange(3, structTypesDesc.length - 4)];
    }

    if (!anonymousStructs[structTypesDesc]) {
        NSString *structName =  [NSString stringWithFormat:@"Anonymous_%@", @(anonymousCount++)];
        NSString *formattedString = [[dumpVisitor.classDump.typeController ivarTypeFormatter] formatVariable:@"whatsName" type:structType];
        NSString *structDefine = [self structDefineContent:formattedString structName:structType.typeName.name isUnKownStructName:structName];
        if(structDefine.length > 0) {
            [allSturctDefines appendFormat:@"%@\n\n", structDefine];
            anonymousStructs[structTypesDesc] = structName;
        }
    }

    NSString *anonymousName = anonymousStructs[structTypesDesc];
    if (anonymousName.length > 0 && isPointer) {
        anonymousName = [NSString stringWithFormat:@"%@ %@", anonymousName, @"*"];
    }
    return anonymousName;
}

@end
