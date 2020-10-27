
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
    unsigned int flags;
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
};

struct method64_t
{
  unsigned long long name;
  unsigned long long types;
  unsigned long long imp;
};

struct ivar64_list_t
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

//符号表前缀定义
#define CLASS_SYMBOL_PRE @"_OBJC_CLASS_$_"
#define METACLASS_SYMBOL_PRE @"_OBJC_METACLASS_$_"

//中文字符串所处的节
#define CHINESE_STRING_SECTION  @"(__TEXT,__ustring)"

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
#define TEXT_TEXT_SECTION @"__text"
#define IMP_KEY @"imp"
#define SYMBOL_KEY @"symbol"

#define SPECIAL_NUM 0x5614542
#define SPECIAL_SECTION_TYPE   0x3c

#define CLASSNAME_MAX_LEN 50
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


/**
 从 https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html 了解到Swift的存储结构
 */

//__TEXT.__swift5_protos
struct ProtocolDescriptor{
    uint32  Flags;
    int     Parent;
    int     Name;
    uint32  NumRequirementsInSignature;
    uint32  NumRequirements;
    int     AssociatedTypeNames;
};

//__TEXT.__swift5_proto
struct ProtocolConformanceDescriptor{
    int     ProtocolDescriptor;
    int     NominalTypeDescriptor;
    int     ProtocolWitnessTable;
    uint32  ConformanceFlags;
};

//__TEXT.__swift5_types
struct EnumDescriptor{
    uint32  Flags;
    int     Parent;
    int     Name;
    int     AccessFunction;
    int     FieldDescriptor;
    uint32  NumPayloadCasesAndPayloadSizeOffset;
    uint32  NumEmptyCases;
};

struct StructDescriptor{
    uint32 Flags;
    int    Parent;
    int    Name;
    int    AccessFunction;
    int    FieldDescriptor;
    uint32 NumFields;
    uint32 FieldOffsetVectorOffset;
};

struct ClassDescriptor{
    uint32  Flags;
    int     Parent;
    int     Name;
    int     AccessFunction;
    int     FieldDescriptor;
    int     SuperclassType;
    uint32  MetadataNegativeSizeInWords;
    uint32  MetadataPositiveSizeInWords;
    uint32  NumImmediateMembers;
    uint32  NumFields;
};

//__TEXT.__swift5_fieldmd
struct FieldRecord{
    uint32  Flags;
    int     MangledTypeName;
    int     FieldName;
};

struct FieldDescriptor{
    int          MangledTypeName;
    int          Superclass;
    uint16       Kind;
    uint16       FieldRecordSize;
    uint32       NumFields;
    FieldRecord* FieldRecords;
};

//__TEXT.__swift5_assocty
struct AssociatedTypeRecord{
    int     Name;
    int     SubstitutedTypeName;
};

struct AssociatedTypeDescriptor{
    int                    ConformingTypeName;
    int                    ProtocolTypeName;
    uint32                 NumAssociatedTypes;
    uint32                 AssociatedTypeRecordSize;
    AssociatedTypeRecord*  AssociatedTypeRecords;
};

//__TEXT.__swift5_builtin
struct BuiltinTypeDescriptor{
    int                 TypeName;
    uint32              Size;
    uint32              AlignmentAndFlags;
    uint32              Stride;
    uint32              NumExtraInhabitants;
};

//__TEXT.__swift5_capture
struct CaptureTypeRecord{
    int     MangledTypeName;
};

struct MetadataSourceRecord{
    int     MangledTypeName;
    int     MangledMetadataSource;
};

struct CaptureDescriptor{
    uint32                NumCaptureTypes;
    uint32                NumMetadataSources;
    uint32                NumBindings;
    CaptureTypeRecord*    CaptureTypeRecords;
    MetadataSourceRecord* MetadataSourceRecords;
};

//__TEXT.__swift5_replace
struct Replacement{
    int     ReplacedFunctionKey;
    int     NewFunction;
    int     Replacement;
    uint32  Flags;
};

struct ReplacementScope{
    uint32  Flags;
    uint32  NumReplacements;
};

struct AutomaticReplacements{
    uint32  Flags;
    uint32  NumReplacements;
    int     Replacements;
};

//__TEXT.__swift5_replac2
struct Replacement2{
    int     Original;
    int     Replacement;
};

struct AutomaticReplacementsSome{
    uint32       Flags;
    uint32       NumReplacements;
    Replacement* Replacements;
};
