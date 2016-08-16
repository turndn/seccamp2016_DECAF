#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "hookapi.h"

static plugin_interface_t myplug_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle URLDownloadToFileW_handle = DECAF_NULL_HANDLE;
static DECAF_Handle ReadFile_handle = DECAF_NULL_HANDLE;
char targetname[512];
uint32_t target_cr3;

/*
 * HRESULT URLDownloadToFile(
 *              LPUNKNOWN            pCaller,
 *              LPCTSTR              szURL,
 *              LPCTSTR              szFileName,
 *   _Reserved_ DWORD                dwReserved,
 *              LPBINDSTATUSCALLBACK lpfnCB
 * );
 */

typedef struct {
    uint32_t call_stack[5]; //paramters and return address
    DECAF_Handle hook_handle;
} URLDownloadToFileW_hook_context_t;

static void URLDownloadToFileW_ret(void *param)
{
    URLDownloadToFileW_hook_context_t *ctx = (URLDownloadToFileW_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    DECAF_printf("EIP = %08x, EAX = %d\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX]);
    free(ctx);
}

static void URLDownloadToFileW_call(void *opaque)
{
    DECAF_printf("URLDownloadFileW ");
    URLDownloadToFileW_hook_context_t *ctx = (URLDownloadToFileW_hook_context_t*)malloc(sizeof(URLDownloadToFileW_hook_context_t));

    if(!ctx) return;

    // get return addr and arguments
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 16, ctx->call_stack);

    // get url from argument
    int i;
    char url_buffer[256];
    int before_flag = 0;

    // read from (LPCTSTR szURL)
    DECAF_read_mem(NULL, ctx->call_stack[2], 255, url_buffer);
    url_buffer[255] = '\0';
    DECAF_printf("URL: ");

    // handle LPCTSTR ascii
    for (i = 0; i < 256; i++) {
        // Do not print \00 and \00\00 is EOF
        if (url_buffer[i] == '\0') {
            if (before_flag == 1)
                break;
            else
                before_flag = 1;

            continue;
        }
        before_flag = 0;
        DECAF_printf("%c", url_buffer[i]);
    }

    DECAF_printf("\n");
    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], URLDownloadToFileW_ret, ctx, sizeof(*ctx));
}

/*
 * BOOL ReadFile(
 *   HANDLE hFile,
 *   LPVOID lpBuffer,
 *   DWORD nNumberOfBytesToRead,
 *   LPDWORD lpNumberOfBytesRead,
 *   LPOVERLAPPED lpOverlapped
 * );
 */

typedef struct {
        uint32_t call_stack[5]; //paramters and return address
        DECAF_Handle hook_handle;
} ReadFile_hook_context_t;

uint32_t read_buf_addr;     // Read buffer address
uint32_t read_buffer_size;  // Read buffer size

static void ReadFile_ret(void *param)
{
    unsigned char read_buffer[256] = { 0 };
    int i;
    int before_flag = 0;

    // Stop when read large size
    if (read_buffer_size > 2048)
        return;

    // read from (LPVOID lpBuffer)
    DECAF_read_mem(NULL, read_buf_addr, 255, read_buffer);
    read_buffer[255] = '\0';

    DECAF_printf("Readbuf: ");

    // handle LPCTSTR ascii
    for (i = 0; i < 256; i++) {
        // Do not print \00 and \00\00 is EOF
        if (read_buffer[i] == '\0') {
            if (before_flag == 1)
                break;
            else
                before_flag = 1;

            continue;
        } else if (read_buffer[i] < 0x21 || read_buffer[i] > 0x7E) { // out of ascii
            before_flag = 0;
            DECAF_printf("\\x%02x", read_buffer[i]);
            continue;
        }
        before_flag = 0;
        DECAF_printf("%c", read_buffer[i]);
    }

    DECAF_printf("\n");
    ReadFile_hook_context_t *ctx = (ReadFile_hook_context_t *)param;
    hookapi_remove_hook(ctx->hook_handle);
    DECAF_printf("EIP = %08x, EAX = %d, EBP = %08x, ESP = %08x\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX], cpu_single_env->regs[R_EBP], cpu_single_env->regs[R_ESP]);
    free(ctx);
}

static void ReadFile_call(void *opaque)
{
    DECAF_printf("ReadFile ");
    ReadFile_hook_context_t *ctx = (ReadFile_hook_context_t*)malloc(sizeof(ReadFile_hook_context_t));

    if(!ctx) return;

    // get return addr and arguments
    DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 16, ctx->call_stack);

    DECAF_printf("Read buffer address: 0x%x\n", ctx->call_stack[2]);
    DECAF_printf("Return address: 0x%x\n", ctx->call_stack[0]);     // return addr
    read_buf_addr = ctx->call_stack[2];                             // set LPVOID lpBuffer addr
    read_buffer_size = ctx->call_stack[3];                          // set DWORD nNumberOfBytesToRead

    
    ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], ReadFile_ret, ctx, sizeof(*ctx));
}

static void myplug_block_begin_callback(DECAF_Callback_Params* params)
{
    if(params->bb.env->cr[3] == target_cr3)
    {
        target_ulong eip = params->bb.env->eip; 
        target_ulong eax = params->bb.env->regs[R_EAX]; 
    }
}

static void myplug_loadmainmodule_callback(VMI_Callback_Params* params)
{
    if(strcmp(params->cp.name,targetname) == 0)
    {
        DECAF_printf("Process %s you spcecified starts \n", params->cp.name);
        target_cr3 = params->cp.cr3;
        URLDownloadToFileW_handle = hookapi_hook_function_byname("Urlmon.dll", "URLDownloadToFileW", 1, target_cr3, URLDownloadToFileW_call, NULL, 0);
        ReadFile_handle = hookapi_hook_function_byname("Kernel32.dll", "ReadFile", 1, target_cr3, ReadFile_call, NULL, 0);
        blockbegin_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &myplug_block_begin_callback, NULL);
    }
}

void do_monitor_proc(Monitor* mon, const QDict* qdict)
{
    if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
            strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
    targetname[511] = '\0';
    DECAF_printf("Ready to track %s\n", targetname);
}

static int myplug_init(void)
{
    DECAF_printf("Init\n");
    processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &myplug_loadmainmodule_callback, NULL);
    if (processbegin_handle == DECAF_NULL_HANDLE)
            DECAF_printf("Could not register for the create or remove proc events\n");
    return 0;
}

static void myplug_cleanup(void)
{
    DECAF_printf("Cleanup\n");
    if (processbegin_handle != DECAF_NULL_HANDLE)
    {
        VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);  
        processbegin_handle = DECAF_NULL_HANDLE;
    }
    if (blockbegin_handle != DECAF_NULL_HANDLE)
    {
        DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
        blockbegin_handle = DECAF_NULL_HANDLE;
    }
}

static mon_cmd_t myplug_term_cmds[] = 
{
#include "plugin_cmds.h"
        {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
    myplug_interface.mon_cmds = myplug_term_cmds;
    myplug_interface.plugin_cleanup = &myplug_cleanup;
    myplug_init();
    return (&myplug_interface);
}
