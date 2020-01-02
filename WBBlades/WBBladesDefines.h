
#define NSSTRING(C_STR) [NSString stringWithCString: (char *)(C_STR) encoding: [NSString defaultCStringEncoding]]
#define CSTRING(NS_STR) [(NS_STR) cStringUsingEncoding: [NSString defaultCStringEncoding]]

struct class64 {
    unsigned long long isa;
    unsigned long long superClass;
    unsigned long long cache;
    unsigned long long vtable;
    unsigned long long data;
    
};

struct cfstring64 {
    unsigned long long ptr;
    unsigned long long unknown;
    unsigned long long stringAddress;
    unsigned long long size;
    
};

struct class64Info {
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

#define RET  (0xd65f03c0)
#define B  (0x14000001)

#define SEGMENT_TEXT @"__TEXT"
#define SEGMENT_RODATA @"__RODATA"
#define SEGMENT_DATA @"__DATA"
#define SEGMENT_DATA_CONST @"__DATA_CONST"


#define CLASS_SYMBOL_PRE @"_OBJC_CLASS_$_"
#define METACLASS_SYMBOL_PRE @"_OBJC_METACLASS_$_"


#define CHINESE_STRING_SECTION  @"(__TEXT,__ustring)"

#define DATA_CLASSLIST_SECTION @"__objc_classlist__DATA"
#define CONST_DATA_CLASSLIST_SECTION @"__objc_classlist__DATA_CONST"
#define DATA_CLASSREF_SECTION @"__objc_classrefs__DATA"
#define CONST_DATA_CLASSREF_SECTION @"__objc_classrefs__DATA_CONST"
#define DATA_NCLSLIST_SECTION @"__objc_nlclslist__DATA"
#define CONST_DATA_NCLSLIST_SECTION @"__objc_nlclslist__DATA_CONST"
#define DATA_CSTRING @"__cfstring"


//if ([secName isEqualToString:@"__objc_classlist__DATA"] ||
//               [secName isEqualToString:@"__objc_classlist__DATA_CONST"]) {
//               classList = sectionHeader;
//           }
//           if ([secName isEqualToString:@"__objc_classrefs__DATA"] ||
//               [secName isEqualToString:@"__objc_classrefs__DATA_CONST"]) {
//               classrefList = sectionHeader;
//           }
//           if ([secName isEqualToString:@"__objc_nlclslist__DATA"] ||
//               [secName isEqualToString:@"__objc_nlclslist__DATA_CONST"]) {
//               nlclsList = sectionHeader;
//           }
//           if ([secName isEqualToString:@"__cfstring"]) {
