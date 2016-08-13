#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include "hookapi.h"

static plugin_interface_t geteip_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle isdebuggerpresent_handle = DECAF_NULL_HANDLE;
char targetname[512];
uint32_t target_cr3;

typedef struct {
        uint32_t call_stack[5]; //paramters and return address
        DECAF_Handle hook_handle;
} IsDebuggerPresent_hook_context_t;

uint32_t read_buf_addr;

/*
 * BOOL IsDebuggerPresent(VOID);
 */

static void IsDebuggerPresent_ret(void *param)
{
	char read_buffer[256] = { 0 };
	DECAF_read_mem(NULL, read_buf_addr, 255, read_buffer);
	read_buffer[255] = '\0';
	DECAF_printf("Readbuf: ");
	int i;
	int before_flag = 0;
	for (i = 0; i < 256; i++) {
		if (read_buffer[i] == '\0') {
			if (before_flag == 1) break;
			else before_flag = 1;
			continue;
		}
		before_flag = 0;
		DECAF_printf("%c", read_buffer[i]);
	}
	DECAF_printf("\n");
        IsDebuggerPresent_hook_context_t *ctx = (IsDebuggerPresent_hook_context_t *)param;
        hookapi_remove_hook(ctx->hook_handle);
        DECAF_printf("EIP = %08x, EAX = %d, EBP = %08x, ESP = %08x\n", cpu_single_env->eip, cpu_single_env->regs[R_EAX], cpu_single_env->regs[R_EBP], cpu_single_env->regs[R_ESP]);
        free(ctx);
}

static void IsDebuggerPresent_call(void *opaque)
{
        DECAF_printf("ReadFile ");
        IsDebuggerPresent_hook_context_t *ctx = (IsDebuggerPresent_hook_context_t*)malloc(sizeof(IsDebuggerPresent_hook_context_t));
        if(!ctx) return;
        DECAF_read_mem(NULL, cpu_single_env->regs[R_ESP], 16, ctx->call_stack);
	DECAF_printf("Read buffer address: 0x%x\n", ctx->call_stack[2]);
	DECAF_printf("Return address: 0x%x\n", ctx->call_stack[0]);
	read_buf_addr = ctx->call_stack[2];
	
	ctx->hook_handle = hookapi_hook_return(ctx->call_stack[0], IsDebuggerPresent_ret, ctx, sizeof(*ctx));
}

static void geteip_block_begin_callback(DECAF_Callback_Params* params)
{
        if(params->bb.env->cr[3] == target_cr3)
        {
                target_ulong eip = params->bb.env->eip; 
                target_ulong eax = params->bb.env->regs[R_EAX]; 
                // DECAF_printf("EIP = 0x%08x, EAX = 0x%08x\n", eip, eax);
        }
}

static void geteip_loadmainmodule_callback(VMI_Callback_Params* params)
{
        if(strcmp(params->cp.name,targetname) == 0)
        {
                DECAF_printf("Process %s you spcecified starts \n", params->cp.name);
                target_cr3 = params->cp.cr3;
                isdebuggerpresent_handle = hookapi_hook_function_byname("Kernel32.dll", "ReadFile", 1, target_cr3, IsDebuggerPresent_call, NULL, 0);
                blockbegin_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &geteip_block_begin_callback, NULL);
        }
}

void do_monitor_proc(Monitor* mon, const QDict* qdict)
{
        if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
                strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
        targetname[511] = '\0';
        DECAF_printf("Ready to track %s\n", targetname);
}

static int geteip_init(void)
{
        DECAF_printf("Hello, World!\n");
        processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &geteip_loadmainmodule_callback, NULL);
        if (processbegin_handle == DECAF_NULL_HANDLE)
                DECAF_printf("Could not register for the create or remove proc events\n");  
        return 0;
}

static void geteip_cleanup(void)
{
        DECAF_printf("Bye, World\n");
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

static mon_cmd_t geteip_term_cmds[] = 
{
#include "plugin_cmds.h"
        {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
        geteip_interface.mon_cmds = geteip_term_cmds;
        geteip_interface.plugin_cleanup = &geteip_cleanup;
        geteip_init();
        return (&geteip_interface);
}
