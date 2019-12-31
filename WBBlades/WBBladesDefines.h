
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
