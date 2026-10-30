//
//  wz_kfd.m
//  TrollSpeedWZ
//
//  探测流程：
//   1. 按 16.2 / T8120 填 proc 相关偏移（SimpleKFD 的 _offsets_init 全是注释，必须自己填）
//   2. do_kopen 打 PUAF
//   3. 遍历 allproc，dump 进程名，找目标
//   4. 改目标 proc_ro->p_csflags 置 CS_GET_TASK_ALLOW
//   5. task_for_pid 拿 task port
//   6. 枚举首个 region，读 Mach-O magic 验证
//
//  所有结果写 /var/mobile/wz_probe.log，同时把一行短状态给悬浮窗显示。
//

#import "wz_kfd.h"

#import <dispatch/dispatch.h>
#import <mach/mach.h>
// iOS SDK 的 mach/mach_vm.h 是 #error 屏蔽的，只能用 vm_map.h 里的 vm_* 系列
#import <mach/vm_map.h>
#import <mach/vm_region.h>
#import <pthread.h>
#import <stdarg.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>

#include "krw.h"
#include "proc.h"
#include "offsets.h"

extern uint64_t _kfd;   // 定义在 krw.c

#define WZ_LOG_PRIMARY  "/var/mobile/wz_probe.log"

#define CS_GET_TASK_ALLOW 0x00000004

static char g_status[64] = "kfd:init";
static BOOL g_enabled = NO;
static BOOL g_started = NO;
static mach_port_t g_target_task = MACH_PORT_NULL;
static pid_t g_target_pid = 0;

#pragma mark - 日志

static void wz_log(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    NSLog(@"[WZ] %s", line);

    FILE *fp = fopen(WZ_LOG_PRIMARY, "a");
    if (!fp) {
        NSString *fallback = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wz_probe.log"];
        fp = fopen(fallback.fileSystemRepresentation, "a");
    }
    if (fp) {
        fprintf(fp, "%s\n", line);
        fclose(fp);
    }
}

static void wz_status(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_status, sizeof(g_status), fmt, ap);
    va_end(ap);
    wz_log("status -> %s", g_status);
}

#pragma mark - 16.2 偏移

// iOS 16.2 (xnu-8792.62.2) / iPhone 14 Pro Max (T8120)
// proc / proc_ro / ucred / task 的结构体布局在 16.0 - 16.6 之间没有变化，
// 这里取的是同代 16.1.2 的实测值。
static void wz_set_offsets_16_2(void)
{
    // struct proc
    off_p_list_le_prev   = 0x8;
    off_p_proc_ro        = 0x18;
    off_p_ppid           = 0x20;
    off_p_original_ppid  = 0x24;
    off_p_pgrpid         = 0x28;
    off_p_uid            = 0x2c;
    off_p_gid            = 0x30;
    off_p_ruid           = 0x34;
    off_p_rgid           = 0x38;
    off_p_svuid          = 0x3c;
    off_p_svgid          = 0x40;
    off_p_sessionid      = 0x44;
    off_p_puniqueid      = 0x48;
    off_p_pid            = 0x60;
    off_p_pfd            = 0xf8;
    off_p_textvp         = 0x350;
    off_p_name           = 0x381;

    // struct proc_ro
    off_p_ro_p_csflags   = 0x1c;
    off_p_ro_p_ucred     = 0x20;
    off_p_ro_pr_proc     = 0x0;
    off_p_ro_pr_task     = 0x8;
    off_p_ro_t_flags_ro  = 0x78;

    // struct ucred
    off_u_cr_label       = 0x78;
    off_u_cr_posix       = 0x18;
    off_cr_uid           = 0x0;
    off_cr_ruid          = 0x4;
    off_cr_svuid         = 0x8;
    off_cr_ngroups       = 0xc;
    off_cr_groups        = 0x10;
    off_cr_rgid          = 0x50;
    off_cr_svgid         = 0x54;
    off_cr_gmuid         = 0x58;
    off_cr_flags         = 0x5c;

    // struct task
    off_task_t_flags     = 0x3D0;
}

#pragma mark - 进程遍历

static uint64_t wz_find_proc_by_pid(pid_t pid)
{
    uint64_t proc = get_kernproc();
    for (int i = 0; i < 2048 && proc; i++) {
        if ((pid_t)kread32(proc + off_p_pid) == pid) return proc;
        proc = kread64(proc + off_p_list_le_prev);
    }
    return 0;
}

static uint64_t wz_find_proc_by_substr(const char *needle, pid_t *outPid)
{
    uint64_t proc = get_kernproc();
    for (int i = 0; i < 2048 && proc; i++) {
        char name[32] = {0};
        do_kread(proc + off_p_name, name, sizeof(name) - 1);
        if (name[0] && strstr(name, needle)) {
            if (outPid) *outPid = (pid_t)kread32(proc + off_p_pid);
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
    }
    return 0;
}

static void wz_dump_procs(void)
{
    wz_log("---- process list ----");
    uint64_t proc = get_kernproc();
    for (int i = 0; i < 2048 && proc; i++) {
        char name[32] = {0};
        do_kread(proc + off_p_name, name, sizeof(name) - 1);
        wz_log("pid=%-6d name=%s", kread32(proc + off_p_pid), name);
        proc = kread64(proc + off_p_list_le_prev);
    }
    wz_log("---- end ----");
}

#pragma mark - attach

static int wz_attach(pid_t pid)
{
    uint64_t proc = wz_find_proc_by_pid(pid);
    if (!proc) {
        wz_log("attach: proc not found for pid %d", pid);
        return -1;
    }

    uint64_t proc_ro = kread64(proc + off_p_proc_ro);
    if (!proc_ro) {
        wz_log("attach: proc_ro null");
        return -2;
    }

    uint32_t csflags = kread32(proc_ro + off_p_ro_p_csflags);
    wz_log("attach: pid=%d proc=0x%llx proc_ro=0x%llx csflags=0x%08x", pid, proc, proc_ro, csflags);

    if (!(csflags & CS_GET_TASK_ALLOW)) {
        kwrite32(proc_ro + off_p_ro_p_csflags, csflags | CS_GET_TASK_ALLOW);
        uint32_t after = kread32(proc_ro + off_p_ro_p_csflags);
        wz_log("attach: csflags patched -> 0x%08x (readback 0x%08x)", csflags | CS_GET_TASK_ALLOW, after);
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    wz_log("attach: task_for_pid(%d) -> kr=%d task=0x%x", pid, kr, task);

    if (kr != KERN_SUCCESS) return -3;

    g_target_task = task;
    g_target_pid = pid;
    return 0;
}

#pragma mark - 验证读取

static uint64_t wz_read_u64(mach_port_t task, uint64_t addr)
{
    uint64_t val = 0;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(task, (vm_address_t)addr, sizeof(val),
                                         (vm_address_t)&val, &out);
    if (kr != KERN_SUCCESS) return 0;
    return val;
}

static void wz_probe_target_image(void)
{
    if (g_target_task == MACH_PORT_NULL) return;

    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_port_t object_name = MACH_PORT_NULL;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;

    kern_return_t kr = vm_region_64(g_target_task, &addr, &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &count, &object_name);

    if (kr != KERN_SUCCESS) {
        wz_log("region: vm_region_64 failed kr=%d", kr);
        return;
    }

    wz_log("region: first addr=0x%llx size=0x%llx prot=%d",
           (unsigned long long)addr, (unsigned long long)size, info.protection);

    uint64_t magic = wz_read_u64(g_target_task, addr);
    wz_log("region: magic@0x%llx = 0x%016llx",
           (unsigned long long)addr, (unsigned long long)magic);

    uint32_t m32 = (uint32_t)(magic & 0xFFFFFFFF);
    if (m32 == 0xFEEDFACF || m32 == 0xFEEDFACE) {
        wz_status("kfd:ok p%d t1 m%08X", g_target_pid, m32);
        wz_log("region: MACH-O MAGIC OK");
    } else {
        wz_status("kfd:ok p%d t1 m%08X?", g_target_pid, m32);
        wz_log("region: magic mismatch");
    }
}

#pragma mark - 主流程

static void *wz_thread(void *arg)
{
    @autoreleasepool {
        wz_status("kfd:boot");
        wz_log("=== wz probe start, pid=%d uid=%d ===", getpid(), getuid());

        wz_set_offsets_16_2();
        wz_log("offsets set: p_pid=0x%x p_name=0x%x proc_ro=0x%x csflags=0x%x",
               off_p_pid, off_p_name, off_p_proc_ro, off_p_ro_p_csflags);

        // 1. 打 PUAF
        //    puaf_method: 1=smith, kread_method: 0=kqueue_workloop_ctl, kwrite_method: 0=dup
        //    puaf_pages 上限是 2048（kopen 里有 assert）
        uint64_t k = do_kopen(1024, 1, 0, 0, false, false);
        if (!k) {
            wz_status("kfd:FAIL");
            wz_log("do_kopen returned 0");
            g_enabled = YES;
            return NULL;
        }
        wz_log("do_kopen OK, kfd=0x%llx", k);
        wz_status("kfd:ok");

        // 2. 基本自检：读自己的 proc
        uint64_t self_proc = wz_find_proc_by_pid(getpid());
        wz_log("self proc = 0x%llx (kernproc=0x%llx)", self_proc, get_kernproc());
        if (!self_proc) {
            wz_status("kfd:ok procFAIL");
            g_enabled = YES;
            return NULL;
        }

        // 3. dump 进程表，方便确认目标进程名
        wz_dump_procs();

        // 4. 找目标
        pid_t tpid = 0;
        uint64_t tproc = wz_find_proc_by_substr("smoba", &tpid);
        if (!tproc) {
            wz_status("kfd:ok p0");
            wz_log("target 'smoba' not running");
            g_enabled = YES;
            return NULL;
        }
        wz_log("target found: pid=%d proc=0x%llx", tpid, tproc);
        wz_status("kfd:ok p%d", tpid);

        // 5. attach
        int rc = wz_attach(tpid);
        if (rc != 0) {
            wz_status("kfd:ok p%d t0(%d)", tpid, rc);
            g_enabled = YES;
            return NULL;
        }

        // 6. 验证读取
        wz_probe_target_image();

        g_enabled = YES;
        wz_log("=== wz probe done ===");
    }
    return NULL;
}

#pragma mark - 对外接口

BOOL WZProbeEnabled(void)
{
    return g_enabled;
}

NSString *WZProbeStatus(void)
{
    return [NSString stringWithUTF8String:g_status];
}

void WZProbeStart(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *args = [[NSProcessInfo processInfo] arguments];
        if (![args containsObject:@"-hud"]) {
            // 只有 HUD 进程才跑，主 App 不碰内核
            return;
        }
        if (g_started) return;
        g_started = YES;
        g_enabled = YES;   // 立刻切到调试显示，不用等探测跑完

        pthread_t th;
        pthread_create(&th, NULL, wz_thread, NULL);
        pthread_detach(th);
    });
}
