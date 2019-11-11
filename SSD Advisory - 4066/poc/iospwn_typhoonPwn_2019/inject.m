/*
 *  inject.m
 *
 *  Created by Sam Bingner on 9/27/2018
 *  Copyright 2018 Sam Bingner. All Rights Reserved.
 *
 */

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

extern uint32_t KernelRead_4bytes(uint64_t rAddr);
extern uint64_t KernelRead_8bytes(uint64_t rAddr);
extern void KernelRead_anySize(uint64_t rAddr, char *outbuf, size_t outbuf_len);
extern void KernelWrite_4bytes(uint64_t wAddr, uint32_t wData);
extern void KernelWrite_8bytes(uint64_t wAddr, uint64_t wData);
extern void KernelWrite_anySize(uint64_t wAddr, char *inputbuf, size_t inputbuf_len);
extern uint64_t KernelAllocate(size_t);

extern uint64_t kernel_trustcache;
uint64_t current_my_trustcache = 0;

size_t kread(uint64_t where, void *p, size_t size)
{
    extern void KernelRead_anySize(uint64_t rAddr, char *outbuf, size_t outbuf_len);
    KernelRead_anySize(where, p, size);
    return size;
}

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0,                    /* no particular flags (default behavior) */
    kSecCSConsiderExpiration = 1 << 31,        /* consider expired certificates invalid */
};
typedef void *SecStaticCodeRef;

OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef  _Nullable *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;

enum cdHashType {
    cdHashTypeSHA1 = 1,
    cdHashTypeSHA256 = 2
};

static char *cdHashName[3] = {NULL, "SHA1", "SHA256"};

static enum cdHashType requiredHash = cdHashTypeSHA256;

#define TRUST_CDHASH_LEN (20)

struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct hash_entry_t {
    uint16_t num;
    uint16_t start;
} __attribute__((packed));

typedef uint8_t hash_t[TRUST_CDHASH_LEN];

NSString *cdhashFor(NSString *file) {
    NSString *cdhash = nil;
    SecStaticCodeRef staticCode;
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)file, kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
    const char *filename = file.UTF8String;
    if (result != errSecSuccess) {
        if (_SecCopyErrorMessageString != NULL) {
            CFStringRef error = _SecCopyErrorMessageString(result, NULL);
            printf("Unable to generate cdhash for %s: %s", filename, [(__bridge id)error UTF8String]);
            CFRelease(error);
        } else {
            printf("Unable to generate cdhash for %s: %d", filename, result);
        }
        return nil;
    }
    
    CFDictionaryRef cfinfo;
    result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &cfinfo);
    NSDictionary *info = CFBridgingRelease(cfinfo);
    CFRelease(staticCode);
    if (result != errSecSuccess) {
        printf("Unable to copy cdhash info for %s", filename);
        return nil;
    }
    NSArray *cdhashes = info[@"cdhashes"];
    NSArray *algos = info[@"digest-algorithms"];
    NSUInteger algoIndex = [algos indexOfObject:@(requiredHash)];
    
    if (cdhashes == nil) {
        printf("%s: no cdhashes", filename);
    } else if (algos == nil) {
        printf("%s: no algos", filename);
    } else if (algoIndex == NSNotFound) {
        printf("%s: does not have %s hash", cdHashName[requiredHash], filename);
    } else {
        cdhash = [cdhashes objectAtIndex:algoIndex];
        if (cdhash == nil) {
            printf("%s: missing %s cdhash entry", file.UTF8String, cdHashName[requiredHash]);
        }
    }
    return cdhash;
}

NSArray *filteredHashes(uint64_t kernel_trustcache, NSDictionary *hashes) {
#if !__has_feature(objc_arc)
    NSArray *result;
    @autoreleasepool {
#endif
        NSMutableDictionary *filtered = [hashes mutableCopy];
        
        struct trust_mem search;
        search.next = kernel_trustcache;
        while (search.next != 0) {
            uint64_t searchAddr = search.next;
            kread(searchAddr, &search, sizeof(struct trust_mem));
            //printf("Checking %d entries at 0x%llx", search.count, searchAddr);
            char *data = malloc(search.count * TRUST_CDHASH_LEN);
            kread(searchAddr + sizeof(struct trust_mem), data, search.count * TRUST_CDHASH_LEN);
            size_t data_size = search.count * TRUST_CDHASH_LEN;
            
            for (char *dataref = data; dataref <= data + data_size - TRUST_CDHASH_LEN; dataref += TRUST_CDHASH_LEN) {
                NSData *cdhash = [NSData dataWithBytesNoCopy:dataref length:TRUST_CDHASH_LEN freeWhenDone:NO];
                NSString *hashName = filtered[cdhash];
                if (hashName != nil) {
                    //printf("%s: already in dynamic trustcache, not reinjecting", [hashName UTF8String]);
                    [filtered removeObjectForKey:cdhash];
                    if ([filtered count] == 0) {
                        free(data);
                        return nil;
                    }
                }
            }
            free(data);
        }
        //printf("Actually injecting %lu keys", [[filtered allKeys] count]);
#if __has_feature(objc_arc)
        return [filtered allKeys];
#else
        result = [[filtered allKeys] retain];
    }
    return [result autorelease];
#endif
}

int injectTrustCache(NSArray <NSString*> *files){
    @autoreleasepool {
        
        NSMutableDictionary *hashes = [NSMutableDictionary new];
        int errors=0;
        for (NSString *file in files) {
            NSString *cdhash = cdhashFor(file);
            //NSLog(@"cdhash: %@", cdhash);
            if (cdhash == nil) {
                errors++;
                continue;
            }
            
            if (hashes[cdhash] == nil) {
                //printf("%s: OK\n", file.UTF8String);
                hashes[cdhash] = file;
            } else {
                //printf("%s: same as %s (ignoring)\n", file.UTF8String, [hashes[cdhash] UTF8String]);
            }
        }
        unsigned numHashes = (unsigned)[hashes count];
        
        if (numHashes < 1) {
            //printf("Found no hashes to inject\n");
            return errors;
        }
        
        NSArray *filtered = filteredHashes(KernelRead_8bytes(kernel_trustcache), hashes);
        //NSLog(@"%@", filtered);
        unsigned hashesToInject = (unsigned)[filtered count];
        //printf("%u new hashes to inject\n", hashesToInject);
        if (hashesToInject < 1) {
            return errors;
        }
        
        struct trust_mem mem;
        
        if(current_my_trustcache){
            KernelRead_anySize(current_my_trustcache, (char*)&mem, sizeof(mem));
        }
        else{
            mem.next = KernelRead_8bytes(kernel_trustcache);
            mem.count = 0;
            uuid_generate(mem.uuid);
        }
        
        char *buffer = malloc(hashesToInject * TRUST_CDHASH_LEN);
        if (buffer == NULL) {
            //printf("Unable to allocate memory for cdhashes: %s\n", strerror(errno));
            return -3;
        }
        char *curbuf = buffer;
        for (NSData *hash in filtered) {
            memcpy(curbuf, [hash bytes], TRUST_CDHASH_LEN);
            curbuf += TRUST_CDHASH_LEN;
        }
        
        if(!current_my_trustcache){
            size_t length = (32 + hashesToInject * TRUST_CDHASH_LEN + 0x3FFF) & ~0x3FFF;
            current_my_trustcache = KernelAllocate(length);
            //printf("current_my_trustcache: 0x%llx\n", current_my_trustcache);
            mem.count = hashesToInject;
            KernelWrite_anySize(current_my_trustcache + sizeof(mem), buffer, mem.count * TRUST_CDHASH_LEN);
            KernelWrite_8bytes(kernel_trustcache, current_my_trustcache);
        } else {
            KernelWrite_anySize(current_my_trustcache + sizeof(mem) + (mem.count * TRUST_CDHASH_LEN), buffer, hashesToInject * TRUST_CDHASH_LEN);
            mem.count += hashesToInject;
            //printf("mem.count: updated! %d\n", mem.count);
        }
        
        KernelWrite_anySize(current_my_trustcache, (char*)&mem, sizeof(mem));
    
        free(buffer);
        return (int)errors;
    }
}

/*int injectTrustCache2(NSString *file){
    @autoreleasepool {
        struct trust_mem mem;
        
        if(current_my_trustcache){
            KernelRead_anySize(current_my_trustcache, (char*)&mem, sizeof(mem));
        }
        else{
            mem.next = KernelRead_8bytes(kernel_trustcache);
            mem.count = 0;
            uuid_generate(mem.uuid);
        }
        
        NSMutableDictionary *hashes = [NSMutableDictionary new];
        int errors=0;
      
            NSString *cdhash = cdhashFor(file);
            //NSLog(@"cdhash: %@", cdhash);
       
        unsigned numHashes = (unsigned)[hashes count];
        
        if (numHashes < 1) {
            //printf("Found no hashes to inject\n");
            return errors;
        }
        
        NSArray *filtered = filteredHashes(KernelRead_8bytes(kernel_trustcache), hashes);
        //NSLog(@"%@", filtered);
        unsigned hashesToInject = (unsigned)[filtered count];
        //printf("%u new hashes to inject\n", hashesToInject);
        if (hashesToInject < 1) {
            return errors;
        }
        
        char *buffer = malloc(hashesToInject * TRUST_CDHASH_LEN);
        if (buffer == NULL) {
            //printf("Unable to allocate memory for cdhashes: %s\n", strerror(errno));
            return -3;
        }
        char *curbuf = buffer;
        for (NSData *hash in filtered) {
            memcpy(curbuf, [hash bytes], TRUST_CDHASH_LEN);
            curbuf += TRUST_CDHASH_LEN;
        }
        
        if(!current_my_trustcache){
            size_t length = (32 + hashesToInject * TRUST_CDHASH_LEN + 0x3FFF) & ~0x3FFF;
            current_my_trustcache = KernelAllocate(length);
            //printf("current_my_trustcache: 0x%llx\n", current_my_trustcache);
            mem.count = hashesToInject;
            KernelWrite_anySize(current_my_trustcache + sizeof(mem), buffer, mem.count * TRUST_CDHASH_LEN);
            KernelWrite_8bytes(kernel_trustcache, current_my_trustcache);
        } else {
            KernelWrite_anySize(current_my_trustcache + sizeof(mem) + (mem.count * TRUST_CDHASH_LEN), buffer, hashesToInject * TRUST_CDHASH_LEN);
            mem.count += hashesToInject;
            //printf("mem.count: updated! %d\n", mem.count);
        }
        
        KernelWrite_anySize(current_my_trustcache, (char*)&mem, sizeof(mem));
        
        free(buffer);
        return (int)errors;
    }
}*/

void check_file_type_and_trust(char *file_path){
    uint32_t HeaderMagic32 = 0xFEEDFACE; // MH_MAGIC
    uint32_t HeaderMagic32Swapped = 0xCEFAEDFE; // MH_CIGAM
    uint32_t HeaderMagic64 = 0xFEEDFACF; // MH_MAGIC_64
    uint32_t HeaderMagic64Swapped = 0xCFFAEDFE; // MH_CIGAM_64
    uint32_t UniversalMagic = 0xCAFEBABE; // FAT_MAGIC
    uint32_t UniversalMagicSwapped = 0xBEBAFECA; // FAT_CIGAM
    
    int fd = open(file_path, O_RDONLY);
    if(fd){
        uint32_t *file_head4bytes = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
        if((*file_head4bytes == HeaderMagic32) ||
           (*file_head4bytes == HeaderMagic32Swapped) ||
           (*file_head4bytes == HeaderMagic64) ||
           (*file_head4bytes == HeaderMagic64Swapped) ||
           (*file_head4bytes == UniversalMagic) ||
           (*file_head4bytes == UniversalMagicSwapped)
           ){
            // Confirmed it's a Mach-O execution file, add it to trust cache
            chmod(file_path, 0755);
            injectTrustCache(@[[NSString stringWithUTF8String:file_path]]);
        }
        munmap(file_head4bytes, PAGE_SIZE);
        close(fd);
    }
}

void trust_aFile(const char *file_path){
    if(!access(file_path, F_OK)){
        check_file_type_and_trust(file_path);
    }
}

void trust_execs_under_dir(const char *name, int i_deep)
{
    DIR *dir;
    struct dirent *entry;
    
    if (!(dir = opendir(name))){
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if(entry->d_name[0] == '.')
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            
            trust_execs_under_dir(path, i_deep+1);
        } else {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);

            check_file_type_and_trust(path);
        }
    }
    closedir(dir);
}

void trust_aDirectory(const char *dir_path){
    if(!access(dir_path, F_OK)){
        trust_execs_under_dir(dir_path, 0);
    }
}

__attribute__((constructor))
void ctor() {
    void *lib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (lib != NULL) {
        _SecCopyErrorMessageString = dlsym(lib, "SecCopyErrorMessageString");
        dlclose(lib);
    }
}
