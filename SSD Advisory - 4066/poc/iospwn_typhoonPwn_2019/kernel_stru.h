//
//  kernel_stru.h
//  UHAK_final
//
//  Created by aa on 6/1/19.
//  Copyright © 2019 aa. All rights reserved.
//

#include <stdint.h>
#include <mach/mach.h>

#ifndef kernel_stru_h
#define kernel_stru_h

struct semaphore{
    // Defined in the sync_sema.h
    char pad[0x38];
    uint64_t    owner;  // (task_t) task that owns semaphore
    uint64_t    port;  // (ipc_port_t) semaphore port
    
    /*
     How to locate owner:
     sync_sema.c
     kern_return_t semaphore_create(task_t task.
     s = (semaphore_t) zalloc (semaphore_zone);
     s->owner = task;
     */
};

#define KOFFSET(_STRU, _MEM)  _##_STRU##__##_MEM
#define KOFFSET_INIT(_STRU, _MEM)  extern vm_offset_t _##_STRU##__##_MEM

KOFFSET_INIT(task, bsd_info);
KOFFSET_INIT(task, itk_self);
KOFFSET_INIT(ipc_port, kobject);
KOFFSET_INIT(proc, p_ucred);

KOFFSET_INIT(proc, task); //自动生成
KOFFSET_INIT(task, itk_nself);
KOFFSET_INIT(task, itk_sself);




#endif /* kernel_stru_h */
