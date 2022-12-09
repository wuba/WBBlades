
#define NSSTRING(C_STR) [NSString stringWithCString: (char *)(C_STR) encoding: [NSString defaultCStringEncoding]]
#define CSTRING(NS_STR) [(NS_STR) cStringUsingEncoding: [NSString defaultCStringEncoding]]

struct class64
{
    unsigned long long isa;
    unsigned long long superClass;
    unsigned long long cache;
    unsigned long long vtable;
    unsigned long long data;

};

struct cfstring64
{
    unsigned long long ptr;
    unsigned long long unknown;
    unsigned long long stringAddress;
    unsigned long long size;
};

struct class64Info
{
    unsigned int flags;//objc-runtime-new.h line:379~460
    unsigned int instanceStart;
    unsigned int instanceSize;
    unsigned int reserved;
    unsigned long long  instanceVarLayout;
    unsigned long long  name;
    unsigned long long  baseMethods;
    unsigned long long  baseProtocols;
    unsigned long long  instanceVariables;
    unsigned long long  weakInstanceVariables;
    unsigned long long  baseProperties;
};

struct method64_list_t
{
  unsigned int entsize;
  unsigned int count;
    
//    bool usesRelativeOffsets() const {
//        return (entsize & 0x80000000) != 0;
//    }
};

struct method64_t
{
  unsigned long long name;
  unsigned long long types;
  unsigned long long imp;
};

struct relative_method_t {
    int32_t nameOffset;   // SEL*
    int32_t typesOffset;  // const char *
    int32_t impOffset;    // IMP
};


struct ivar64_list_t
{
  unsigned int entsize;
  unsigned int count;
};

struct property_list_t
{
  unsigned int entsize;
  unsigned int count;
};

struct ivar64_t
{
  unsigned long long offset;
  unsigned long long name;
  unsigned long long type;
  unsigned int alignment;
  unsigned int size;
};

struct property_t {
    unsigned long long name;
    unsigned long long attributes;
};

struct category64
{
    unsigned long long name;
    unsigned long long cls;
    unsigned long long instanceMethods;
    unsigned long long classMethods;
    unsigned long long instanceProperties;

};


//指令定义
#define RET  (0xd65f03c0)
#define B  (0x14000001)

//段定义
#define SEGMENT_TEXT @"__TEXT"
#define SEGMENT_RODATA @"__RODATA"
#define SEGMENT_DATA @"__DATA"
#define SEGMENT_DATA_CONST @"__DATA_CONST"
#define SEGMENT_LINKEDIT @"__LINKEDIT"

//符号表前缀定义
#define CLASS_SYMBOL_PRE @"_OBJC_CLASS_$_"
#define METACLASS_SYMBOL_PRE @"_OBJC_METACLASS_$_"

//中文字符串所处的节
#define CHINESE_STRING_SECTION  @"(__TEXT,__ustring)"

//异常调试相关节
#define TEXT_EH_FRAME @"__eh_frame"

//swift5相关字符串节
//sectname[16] 少了'\0',带入了后面的__TEXT
#define TEXT_SWIFT5_REFLSTR @"(__TEXT,__swift5_reflstr__TEXT)"
#define TEXT_SWIFT5_TYPEREF @"(__TEXT,__swift5_typeref__TEXT)"

//节定义
#define DATA_CLASSLIST_SECTION @"__objc_classlist__DATA"
#define CONST_DATA_CLASSLIST_SECTION @"__objc_classlist__DATA_CONST"
#define DATA_CLASSREF_SECTION @"__objc_classrefs__DATA"
#define CONST_DATA_CLASSREF_SECTION @"__objc_classrefs__DATA_CONST"
#define DATA_NCLSLIST_SECTION @"__objc_nlclslist__DATA"
#define CONST_DATA_NCLSLIST_SECTION @"__objc_nlclslist__DATA_CONST"
#define DATA_NCATLIST_SECTION @"__objc_nlcatlist__DATA"
#define CONST_DATA_NCATLIST_SECTION @"__objc_nlcatlist__DATA_CONST"
#define DATA_CSTRING @"__cfstring"
#define TEXT_CSTRING @"__cstring"
#define TEXT_TEXT_SECTION @"__text"
#define TEXT_SWIFT5_TYPES @"__swift5_types"
#define TEXT_CONST @"__const"
#define TEXT_SWIFT5_PROTOS @"__swift5_protos"
#define IMP_KEY @"imp"
#define SYMBOL_KEY @"symbol"
#define METADATACACHE_FLAG @"demangling cache variable for type metadata for "

#define SPECIAL_NUM 0x5614542
#define SPECIAL_SECTION_TYPE   0x3c

#define CLASSNAME_MAX_LEN 150
#define METHODNAME_MAX_LEN 150

#define BIND_OPCODE_MASK                    0xF0
#define BIND_IMMEDIATE_MASK                    0x0F

#define BIND_OPCODE_DONE                    0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM            0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB            0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM            0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM        0x40
#define BIND_OPCODE_SET_TYPE_IMM                0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB            0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                0x80
#define BIND_OPCODE_DO_BIND                    0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB            0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED            0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB        0xC0

typedef NS_ENUM(NSInteger, SwiftKind) {
    SwiftKindUnknown        = -1,    // UnKnown
    SwiftKindModule         = 0,     // Module
    SwiftKindAnonymous      = 2,     // Anonymous
    SwiftKindProtocol       = 3,     // Protocol
    SwiftKindOpaqueType     = 4,     // OpaqueType
    SwiftKindClass          = 16,    // Class
    SwiftKindStruct         = 17,    // Struct
    SwiftKindEnum           = 18     // Enum
};

typedef NS_ENUM(NSInteger, SwiftMethodKind) {
    SwiftMethodKindMethod             = 0,     // method
    SwiftMethodKindInit               = 1,     //init
    SwiftMethodKindGetter             = 2,     // get
    SwiftMethodKindSetter             = 3,     // set
    SwiftMethodKindModify             = 4,     // modify
    SwiftMethodKindRead               = 5,     // read
};

typedef NS_ENUM(NSInteger, SwiftMethodType) {
    SwiftMethodTypeKind                         = 0x0F,
    SwiftMethodTypeInstance                     = 0x10,
    SwiftMethodTypeDynamic                      = 0x20,
    SwiftMethodTypeExtraDiscriminatorShift      = 16,
    SwiftMethodTypeExtraDiscriminator           = 0xFFFF0000,
};
typedef NS_ENUM(NSInteger, FieldRecordFlag) {
    FieldRecordFlag_IsIndirectCase            = 0x1,
    FieldRecordFlag_IsVar                     = 0x2,
    FieldRecordFlag_IsArtificial              = 0x4,
};


//typedef NS_ENUM(uint8_t, SymbolicReferenceKind) {
//  /// A symbolic reference to a context descriptor, representing the
//  /// (unapplied generic) context.
//    SymbolicReferenceKind_Context,
//  /// A symbolic reference to an accessor function, which can be executed in
//  /// the process to get a pointer to the referenced entity.
//    SymbolicReferenceKind_AccessorFunctionReference,
//};

//typedef NS_ENUM(NSInteger, Directness) {
//    Directness_Direct,
//    Directness_Indirect
//};

typedef NS_ENUM(NSInteger, SwiftProtocolTableKind) {
    SwiftProtocolTableKindBaseProtocol                 = 0,
    SwiftProtocolTableKindMethod,
    SwiftProtocolTableKindInit,
    SwiftProtocolTableKindGetter,
    SwiftProtocolTableKindSetter,
    SwiftProtocolTableKindReadCoroutine,
    SwiftProtocolTableKindModifyCoroutine,
    SwiftProtocolTableKindAssociatedTypeAccessFunction,
    SwiftProtocolTableKindAssociatedConformanceAccessFunction
};

typedef NS_ENUM(NSInteger, SwiftProtocolTableType) {
    SwiftProtocolTableTypeKind                         = 0x0F,
    SwiftProtocolTableTypeInstance                     = 0x10,
    SwiftProtocolTableTypeExtraDiscriminatorShift      = 16,
    SwiftProtocolTableTypeExtraDiscriminator           = 0xFFFF0000,
};

/**
 从 https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html 了解到Swift的存储结构
 */

//__TEXT.__swift5_fieldmd
struct FieldRecord{
    uint32  Flags;
    uint32  MangledTypeName;
    uint32  FieldName;
};

struct FieldDescriptor{
    int          MangledTypeName;
    int          Superclass;
    uint16       Kind;
    uint16       FieldRecordSize;
    uint32       NumFields;
};

struct SwiftType {
    uint32_t Flag;
    uint32_t Parent;
};

/**

 ---------------------------------------------------------------------------------------------------------------------
 |  ExtraDiscriminator(16bit)  |... | instanceMethod(1bit) | instanceMethod(1bit) | Kind(4bit) |
 ---------------------------------------------------------------------------------------------------------------------
 */
struct SwiftMethod {
    uint32_t Flag;
    uint32_t Offset;
};

//OverrideTable结构如下，紧随VTable后4字节为OverrideTable数量，再其后为此结构数组
//struct SwiftOverrideMethod {
//    struct SwiftClassType *OverrideClass;
//    struct SwiftMethod *OverrideMethod;
//    struct SwiftMethod *Method;
//};
struct SwiftOverrideMethod {
    uint32_t OverrideClass;
    uint32_t OverrideMethod;
    uint32_t Method;
};

/**
 ---------------------------------------------------------------------------------------------------------------------
 |  TypeFlag(16bit)  |  version(8bit) | generic(1bit) | unique(1bit) | unknow (1bi) | Kind(5bit) |
 ---------------------------------------------------------------------------------------------------------------------
 */

struct SwiftBaseType {
    uint32_t Flag;
    uint32_t Parent;
    int32_t  Name;
    int32_t  AccessFunction;
    int32_t  FieldDescriptor;
};

/**
 由于flag的标记不同，结构也稍有变化，但是主要集中在以下三种类型
 1、SwiftClassType带有VTable的
 2、不带VTable的
 3、AddMetadataInitialization的
 */
struct SwiftClassType {
    uint32_t Flag;
    uint32_t Parent;
    int32_t  Name;
    int32_t  AccessFunction;
    int32_t  FieldDescriptor;
    int32_t  SuperclassType;
    uint32_t MetadataNegativeSizeInWords;
    uint32_t MetadataPositiveSizeInWords;
    uint32_t NumImmediateMembers;
    uint32_t NumFields;
    uint32_t FieldOffsetVectorOffset;
    uint32_t Offset;
    uint32_t NumMethods;
};

struct SwiftClassTypeNoMethods {
    uint32_t Flag;
    uint32_t Parent;
    int32_t  Name;
    int32_t  AccessFunction;
    int32_t  FieldDescriptor;
    int32_t  SuperclassType;
    uint32_t MetadataNegativeSizeInWords;
    uint32_t MetadataPositiveSizeInWords;
    uint32_t NumImmediateMembers;
    uint32_t NumFields;
    uint32_t FieldOffsetVectorOffset;
};

//struct SwiftClassSinMetadataInit {
//    uint32_t Flag;
//    uint32_t Parent;
//    int32_t  Name;
//    int32_t  AccessFunction;
//    int32_t  FieldDescriptor;
//    int32_t  SuperclassType;
//    uint32_t MetadataNegativeSizeInWords;
//    uint32_t MetadataPositiveSizeInWords;
//    uint32_t NumImmediateMembers;
//    uint32_t NumFields;
//    uint32_t FieldOffsetVectorOffset;
//    uint32_t Offset;
//    uint32_t SinMetadataInitCache;
//    uint32_t MetadataOrRelocationFunction;
//    uint32_t CompletionFunction;
//};


struct SwiftStructType {
    uint32_t Flag;
    uint32_t Parent;
    int32_t  Name;
    int32_t  AccessFunction;
    int32_t  FieldDescriptor;
    uint32   NumFields;
    uint32   FieldOffsetVectorOffset;
};

struct SwiftEnumType {
    uint32_t Flag;
    uint32_t Parent;
    int32_t  Name;
    int32_t  AccessFunction;
    int32_t  FieldDescriptor;
    uint32   NumPayloadCasesAndPayloadSizeOffset;
    uint32   NumEmptyCases;
};

struct SwiftProtocolType{
    uint32_t Flags;
    int32_t  Parent;
    int32_t  Name;
    uint32_t NumRequirementsInSignature;
    uint32_t NumRequirements;
    int32_t  AssociatedTypeNames;
};

