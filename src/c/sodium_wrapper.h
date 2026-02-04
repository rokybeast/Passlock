// Try to include sodium.h from various locations
#if __has_include(<sodium.h>)
    #include <sodium.h>
#elif __has_include(<sodium/sodium.h>)
    #include <sodium/sodium.h>
#else
    #error "sodium.h not found"
#endif