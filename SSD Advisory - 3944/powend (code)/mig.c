//
//  mig.c
//  powend
//
//  Created by simo on 30/08/2018.
//  Copyright © 2018 simo ghannam. All rights reserved.
//
#include "code.h"

// Taken from the internet, dont remember where exctly
void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else
            ascii[i % 16] = '.';
        
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0)
                printf("|  %s \n", ascii);
            else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j)
                    printf("   ");
                
                printf("|  %s \n", ascii);
            }
        }
    }
}

/* Routine io_ps_new_pspowersource */
kern_return_t io_ps_new_pspowersource
(
 mach_port_t server,
 int *psid,
 int *return_code
 )
{
    typedef struct {
        mach_msg_header_t Head;
    } Request __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        int psid;
        int return_code;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73020;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
    *psid = Out0P->psid;
    
    *return_code = Out0P->return_code;
    
    return KERN_SUCCESS;
}

/* Routine io_pm_assertion_copy_details */
kern_return_t io_pm_assertion_copy_details
(
 mach_port_t server,
 int assertion_id,
 int whichData,
 vm_offset_t props,
 mach_msg_type_number_t propsCnt,
 vm_offset_t *assertions,
 mach_msg_type_number_t *assertionsCnt,
 int *return_val
 )
{
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t props;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        int assertion_id;
        int whichData;
        mach_msg_type_number_t propsCnt;
    } Request __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t assertions;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t assertionsCnt;
        int return_val;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->msgh_body.msgh_descriptor_count = 1;
    
    InP->props.address = (void *)(props);
    InP->props.size = propsCnt;
    InP->props.deallocate =  FALSE;
    InP->props.copy = MACH_MSG_VIRTUAL_COPY;
    InP->props.type = MACH_MSG_OOL_DESCRIPTOR;
    
    InP->NDR = NDR_record;
    
    InP->assertion_id = assertion_id;
    
    InP->whichData = whichData;
    
    InP->propsCnt = propsCnt;
    
    InP->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73010;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
    
    *assertions = (vm_offset_t)(Out0P->assertions.address);
    *assertionsCnt = Out0P->assertionsCnt;
    
    *return_val = Out0P->return_val;
    
    return KERN_SUCCESS;
}

/* Routine io_ps_update_pspowersource */
kern_return_t io_ps_update_pspowersource
(
 mach_port_t server,
 int psid,
 vm_offset_t psdetails,
 mach_msg_type_number_t psdetailsCnt,
 int *return_code
 )
{
    
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t psdetails;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        int psid;
        mach_msg_type_number_t psdetailsCnt;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        int return_code;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    memset(&Mess,0,sizeof(Mess));
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->msgh_body.msgh_descriptor_count = 1;
    
    InP->psdetails.address = (void *)(psdetails);
    InP->psdetails.size = psdetailsCnt;
    InP->psdetails.deallocate = FALSE;
    InP->psdetails.copy = MACH_MSG_VIRTUAL_COPY;
    InP->psdetails.type = MACH_MSG_OOL_DESCRIPTOR;
    
    InP->NDR = NDR_record;
    
    InP->psid = psid;
    
    InP->psdetailsCnt = psdetailsCnt;
    
    InP->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73021;
    InP->Head.msgh_reserved = 0;
    
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
    
    *return_code = Out0P->return_code;
    
    return KERN_SUCCESS;
}
kern_return_t io_ps_copy_powersources_info
(
 mach_port_t server,
 int pstype,
 vm_offset_t *powersources,
 mach_msg_type_number_t *powersourcesCnt,
 int *return_code
 )
{
    
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        int pstype;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t powersources;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t powersourcesCnt;
        int return_code;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    memset(&Mess,0,sizeof(Mess));
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->NDR = NDR_record;
    InP->pstype = pstype;
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73023;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
#if 0
    DumpHex((void*)Out0P,sizeof(Reply));
    printf("deallocate = %d \n",Out0P->powersources.deallocate);
    printf("copy = %s\n",(Out0P->powersources.copy == 1)?"MACH_MSG_VIRTUAL_COPY":"MACH_MSG_PHYSICAL_COPY");
#endif
    *powersources = (vm_offset_t)(Out0P->powersources.address);
    *powersourcesCnt = Out0P->powersourcesCnt;
    
    *return_code = Out0P->return_code;
    
    return KERN_SUCCESS;
}

/* BUG:Routine io_pm_connection_copy_status */
kern_return_t io_pm_connection_copy_status
(
 mach_port_t server,
 int status_index,
 vm_offset_t *status_data,
 mach_msg_type_number_t *status_dataCnt,
 int *return_val
 )
{
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        int status_index;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t status_data;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t status_dataCnt;
        int return_val;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    /*
     *  * typedef struct {
     *   * mach_msg_header_t Head;
     *    * NDR_record_t NDR;
     *     * kern_return_t RetCode;
     *      * } mig_reply_error_t;
     *       */
    
    union {
        Request In;
        Reply Out;
    } Mess;
    
    memset(&Mess,0,sizeof(Mess));
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->NDR = NDR_record;
    
    InP->status_index = status_index;
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73019;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (msg_result != MACH_MSG_SUCCESS)
        return msg_result;
#if 0
    DumpHex((void*)Out0P,sizeof(Reply));
    //printf("deallocate = %d \n",Out0P->status_data.deallocate);
#endif
    *status_data = (vm_offset_t)(Out0P->status_data.address);
    *status_dataCnt = Out0P->status_dataCnt;
    
    *return_val = Out0P->return_val;
    
    return KERN_SUCCESS;
}

/* Routine io_ps_release_pspowersource */
kern_return_t io_ps_release_pspowersource
(
 mach_port_t server,
 int psid
 )
{
    
    
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        int psid;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    memset(&Mess,0,sizeof(Mess));
    Request *InP = &Mess.In;
    //Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->NDR = NDR_record;
    
    InP->psid = psid;
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73022;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
    
    return KERN_SUCCESS;
}

/* Routine io_pm_last_wake_time */
kern_return_t io_pm_last_wake_time
(
 mach_port_t server,
 vm_offset_t *wakeData,
 mach_msg_type_number_t *wakeDataCnt,
 vm_offset_t *deltaData,
 mach_msg_type_number_t *deltaDataCnt,
 int *return_val
 )
{
    
    typedef struct {
        mach_msg_header_t Head;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t wakeData;
        mach_msg_ool_descriptor_t deltaData;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t wakeDataCnt;
        mach_msg_type_number_t deltaDataCnt;
        int return_val;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    
    union {
        Request In;
        Reply Out;
    } Mess;
    memset(&Mess,0,sizeof(Mess));
    
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73006;
    InP->Head.msgh_reserved = 0;
    
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
    
    *wakeData = (vm_offset_t)(Out0P->wakeData.address);
    *wakeDataCnt = Out0P->wakeDataCnt;
    
    *deltaData = (vm_offset_t)(Out0P->deltaData.address);
    *deltaDataCnt = Out0P->deltaDataCnt;
    
    *return_val = Out0P->return_val;
    
    return KERN_SUCCESS;
}

/* Routine io_pm_hid_event_copy_history */
kern_return_t io_pm_hid_event_copy_history
(
 mach_port_t server,
 vm_offset_t *eventArray,
 mach_msg_type_number_t *eventArrayCnt,
 int *return_val
 )
{
    typedef struct {
        mach_msg_header_t Head;
    } Request __attribute__((unused));
    
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t eventArray;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t eventArrayCnt;
        int return_val;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    
    union {
        Request In;
        Reply Out;
    } Mess;
    memset(&Mess,0,sizeof(Mess));
    
    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;
    
    mach_msg_return_t msg_result;
    
    InP->Head.msgh_bits =
    MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    /* msgh_size passed as argument */
    InP->Head.msgh_request_port = server;
    InP->Head.msgh_reply_port = mig_get_reply_port();
    InP->Head.msgh_id = 73026;
    InP->Head.msgh_reserved = 0;
    
    msg_result = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    //printf("msg_result : 0x%x : %s \n",msg_result,mach_error_string(msg_result));
    if (msg_result != MACH_MSG_SUCCESS) {
        return msg_result;
    }
#if 0
    DumpHex((void*)Out0P,sizeof(Reply));
#endif
    *eventArray = (vm_offset_t)(Out0P->eventArray.address);
    *eventArrayCnt = Out0P->eventArrayCnt;
    
    *return_val = Out0P->return_val;
    
    return KERN_SUCCESS;
}

