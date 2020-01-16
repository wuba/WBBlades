
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
#define DATA_CSTRING @"__cfstring"
#define TEXT_TEXT_SECTION @"__text"
#define IMP_KEY @"imp"
#define SYMBOL_KEY @"symbol"

#define SPECIAL_NUM 0x5614542
#define SPECIAL_SECTION_TYPE   0x3c

#define CLASSNAME_MAX_LEN 50
#define METHODNAME_MAX_LEN 150

