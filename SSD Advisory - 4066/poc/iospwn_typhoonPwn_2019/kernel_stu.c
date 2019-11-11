//
//  kernel_stu.c
//  UHAK_final
//
//  Created by aa on 6/3/19.
//  Copyright © 2019 aa. All rights reserved.
//

#include "kernel_stru.h"

#undef KOFFSET_INIT
#define KOFFSET_INIT(_STRU, _MEM, _OF)  vm_offset_t _##_STRU##__##_MEM = _OF

KOFFSET_INIT(task, bsd_info, 0x358);
// t_flags 0x390
/*
 task->bsd_info
 vm_unix.c
 kern_return_t pid_for_task(struct pid_for_task_args *args)
 t1 = port_name_to_task_inspect(t);
 p = get_bsdtask_info(t1);
 pid  = proc_pid(p);
 
 */

KOFFSET_INIT(proc, task, 0); //自动生成
KOFFSET_INIT(proc, p_ucred, 0xF8);
/*
 proc->p_ucred
 vm_unix.c
 
 sysctl_root
 -> mac_system_check_sysctlbyname
 -> kauth_cred_get
 
 */

KOFFSET_INIT(task, itk_self, 0xD8);
KOFFSET_INIT(task, itk_nself, 0);  //自动生成
KOFFSET_INIT(task, itk_sself, 0);  //自动生成

//KOFFSET_INIT(proc, p_textvp, 0x230);
KOFFSET_INIT(ipc_port, kobject, 0x68);

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <pthread/pthread.h>
#include <os/lock.h>
#include <IOSurface/IOSurfaceRef.h>
#include <sys/mman.h>
#include <mach/thread_act.h>
#include <mach/semaphore.h>
#include <mach/mach_traps.h>
#include <sys/sysctl.h>
#include <dirent.h>
#include <copyfile.h>

#define MAX_CHUNK_SIZE 0xFFF
