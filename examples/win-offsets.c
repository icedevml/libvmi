/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Sergey Kovalev (valor@list.ru)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#define LIBVMI_EXTRA_JSON

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>
#include <signal.h>
#include <unistd.h>

vmi_instance_t vmi;
GHashTable* config;
vmi_event_t cr3_event;

int find_pid4_success = 0;

addr_t offset_kpcr_prcb;
addr_t offset_kprcb_currentthread;
addr_t offset_eprocess_uniqueprocessid;
addr_t offset_kthread_process;

int enable_debug = 0;

void dp(const char* format, ...)
{
    va_list argptr;
    va_start(argptr, format);

    if (enable_debug)
        vfprintf(stderr, format, argptr);

    va_end(argptr);
}

void clean_up(void)
{
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);
    if (config)
        g_hash_table_destroy(config);
}

void sigint_handler()
{
    clean_up();
    exit(1);
}

event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if (event->vcpu_id != 0) {
        /* LibVMI initialization procedure strongly
         * relies on reading CPU context for VCPU 0
         * so we only do care about this one. */
        return VMI_EVENT_RESPONSE_NONE;
    }

    addr_t gs_base;
    addr_t kthread;
    addr_t eprocess;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = event->reg_event.value
    };

    /*
     * Get current GS_BASE and translate its VA to PA using current CR3.
     * This may fail (most probably) if we are in user-mode DTB with KPTI hardening.
     */
    if (VMI_FAILURE == vmi_get_vcpureg(vmi, &gs_base, GS_BASE, 0)) {
        dp("Failed to read GS_BASE\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    /*
     * Inspect _KPCR to find _KTHREAD of currently running thread.
     */
    addr_t prcb = gs_base + offset_kpcr_prcb;
    addr_t cur_thread = prcb + offset_kprcb_currentthread;
    addr_t pid;

    ctx.addr = cur_thread;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &kthread)) {
        dp("Failed to get current KTHREAD from GS_BASE\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    /*
     * Find _EPROCESS of currently running thread.
     */
    addr_t pkprocess = kthread + offset_kthread_process;

    ctx.addr = pkprocess;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &eprocess)) {
        dp("Failed to get EPROCESS from KTHREAD\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    /*
     * Find PID of currently running process.
     */
    addr_t pid_ptr = eprocess + offset_eprocess_uniqueprocessid;

    ctx.addr = pid_ptr;
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &pid)) {
        dp("Failed to get PID from EPROCESS\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    /*
     * Check if we've caught System process. This would ensure that
     * current DTB for VCPU=0 contains all necessary kernel mappings.
     * These mappings may not be present or be incomplete in other processes
     * due to KPTI.
     */
    if (pid != 4) {
        dp("Current PID=%llx, skip until we reach PID=4\n", (unsigned long long)pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    dp("Stopped inside system process\n");
    find_pid4_success = 1;

    /*
     * Remove CR3 event and leave the VM paused inside System process,
     * to make it easy for LibVMI to detect all necessary offsets.
     */
    vmi_clear_event(vmi, event, NULL);
    vmi_pause_vm(vmi);

    return VMI_EVENT_RESPONSE_NONE;
}

void show_usage(char *arg0)
{
    printf("Usage: %s name|domid <domain name|domain id> -r <rekall profile> [-v]\n", arg0);
    printf("    [-v]   optional, enable verbose mode\n");
}

int main(int argc, char **argv)
{
    vmi_mode_t mode;
    int rc = 1;

    void *domain;
    uint64_t domid = VMI_INVALID_DOMID;
    uint64_t init_flags = 0;

    char *rekall_profile = NULL;
    char c;

    while ((c = getopt (argc, argv, "vr:")) != -1)
      switch (c) {
	case 'v':
          enable_debug = 1;
	  break;
        case 'r':
	  rekall_profile = optarg;
	  break;
	default:
	  printf("xxx\n");
	  show_usage(argv[0]);
	  return 1;
      }

    if (argc - optind != 2) {
        show_usage(argv[0]);
	return 1;
    }

    if (strcmp(argv[optind],"name")==0) {
        domain = (void*)argv[optind+1];
        init_flags |= VMI_INIT_DOMAINNAME;
    } else if (strcmp(argv[optind],"domid")==0) {
        domid = strtoull(argv[optind+1], NULL, 0);
        domain = (void*)&domid;
        init_flags |= VMI_INIT_DOMAINID;
    } else {
        printf("You have to specify either name or domid!\n");
	show_usage(argv[0]);
        return 1;
    }

    if (!rekall_profile) {
        printf("You have to specify path to rekall profile!\n");
	show_usage(argv[0]);
        return 1;
    }

    if (VMI_FAILURE == vmi_get_access_mode(vmi, domain, init_flags, NULL, &mode) )
        return 1;

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, domain, init_flags | VMI_INIT_EVENTS, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    signal(SIGINT, sigint_handler);

    config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!config) {
        printf("Failed to create GHashTable!\n");
        goto done;
    }

    g_hash_table_insert(config, g_strdup("os_type"), g_strdup("Windows"));
    g_hash_table_insert(config, g_strdup("rekall_profile"), g_strdup(rekall_profile));

    os_t os = vmi_init_os_partial(vmi, VMI_CONFIG_GHASHTABLE, config, NULL, false);
    if (VMI_OS_WINDOWS != os) {
        printf("Failed to init LibVMI library.\n");
        goto done;
    }

    g_hash_table_remove(config, "rekall_profile");

    json_object* profile = vmi_get_kernel_json(vmi);

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KPCR", "Prcb", &offset_kpcr_prcb)) {
        printf("Failed to find _KPCR->Prcb member offset\n");
        goto done;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KPRCB", "CurrentThread", &offset_kprcb_currentthread)) {
        printf("Failed to find _KPRCB->CurrentThread member offset\n");
        goto done;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "UniqueProcessId", &offset_eprocess_uniqueprocessid)) {
        printf("Failed to find _EPROCESS->UniqueProcessId member offset\n");
        goto done;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_KTHREAD", "Process", &offset_kthread_process)) {
        printf("Failed to find _KTHREAD->Process member offset\n");
        goto done;
    }

    memset(&cr3_event, 0, sizeof(vmi_event_t));
    cr3_event.version = VMI_EVENTS_VERSION;
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_cb;

    if (VMI_FAILURE == vmi_register_event(vmi, &cr3_event)) {
        printf("Failed to register CR3 write event\n");
        goto done;
    }

    while (!find_pid4_success) {
        if (VMI_FAILURE == vmi_events_listen(vmi, 500)) {
            printf("Failed to listen to VMI events\n");
            goto done;
        }
    }

    // the vm is already paused if we've got here
    os = vmi_init_os(vmi, VMI_CONFIG_GHASHTABLE, config, NULL);
    if (VMI_OS_WINDOWS != os) {
        printf("Failed to init LibVMI library.\n");
        goto done;
    }

    /* Get internal fields */
    addr_t ntoskrnl = 0;
    addr_t ntoskrnl_va = 0;
    addr_t tasks = 0;
    addr_t pdbase = 0;
    addr_t pid = 0;
    addr_t pname = 0;
    addr_t kdvb = 0;
    addr_t sysproc = 0;
    addr_t kpcr = 0;
    addr_t kdbg = 0;
    addr_t kpgd = 0;

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl", &ntoskrnl))
        printf("Failed to read field \"ntoskrnl\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_ntoskrnl_va", &ntoskrnl_va))
        printf("Failed to read field \"ntoskrnl_va\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks))
        printf("Failed to read field \"tasks\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pdbase", &pdbase))
        printf("Failed to read field \"pdbase\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid))
        printf("Failed to read field \"pid\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &pname))
        printf("Failed to read field \"pname\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdvb", &kdvb))
        printf("Failed to read field \"kdvb\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_sysproc", &sysproc))
        printf("Failed to read field \"sysproc\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kpcr", &kpcr))
        printf("Failed to read field \"kpcr\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "win_kdbg", &kdbg))
        printf("Failed to read field \"kdbg\"\n");

    if (VMI_FAILURE == vmi_get_offset(vmi, "kpgd", &kpgd))
        printf("Failed to read field \"kpgd\"\n");

    printf("win_ntoskrnl:0x%lx\n"
           "win_ntoskrnl_va:0x%lx\n"
           "win_tasks:0x%lx\n"
           "win_pdbase:0x%lx\n"
           "win_pid:0x%lx\n"
           "win_pname:0x%lx\n"
           "win_kdvb:0x%lx\n"
           "win_sysproc:0x%lx\n"
           "win_kpcr:0x%lx\n"
           "win_kdbg:0x%lx\n"
           "kpgd:0x%lx\n",
           ntoskrnl,
           ntoskrnl_va,
           tasks,
           pdbase,
           pid,
           pname,
           kdvb,
           sysproc,
           kpcr,
           kdbg,
           kpgd);

    if (!ntoskrnl || !ntoskrnl_va || !sysproc || !pdbase || !kpgd) {
        printf("Failed to get most essential fields\n");
        goto done;
    }

    rc = 0;

    /* cleanup any memory associated with the LibVMI instance */
done:
    clean_up();
    return rc;
}
