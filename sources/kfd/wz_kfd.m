//
//  wz_kfd.m
//  TrollSpeedWZ
//
//  探测流程：
//   0. 把"上一次跑到哪个阶段"读出来显示（panic 会重启，内存状态全丢，只有落盘能活）
//   1. 按 16.2 / T8120 填 proc 相关偏移
//   2. do_kopen 打 PUAF + 建 kread/kwrite 通道（perf 内部有多道校验，不对就返回 0）
//   3. 自检：读自己的 proc，核对 pid 和进程名，确认偏移没填错
//   4. 遍历 allproc，找目标进程
//   5. 校验 proc_ro 后改 p_csflags 置 CS_GET_TASK_ALLOW
//   6. task_for_pid 拿 task port
//   7. 枚举首个 region，读 Mach-O magic 验证
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
#import <stdio.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>

#include "krw.h"
#include "proc.h"
#include "offsets.h"

extern uint64_t _kfd;   // 定义在 krw.c

#define WZ_LOG_PRIMARY   "/var/mobile/wz_probe.log"
#define WZ_STAGE_FILE    "/var/mobile/wz_stage.txt"

#define CS_GET_TASK_ALLOW 0x00000004

#define WZ_PUAF_PAGES    2048
#define WZ_WALK_LIMIT    400

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

// 把当前阶段写进 NSUserDefaults + 一个纯文本文件，并立刻落盘。
// 内核 panic 会直接重启，内存里的状态全丢，只有落盘的东西能活下来；
// 下次启动先把上一个阶段显示出来，就能知道崩在哪一步。
static void wz_stage(const char *stage)
{
    wz_log("stage -> %s", stage);

    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:[NSString stringWithUTF8String:stage] forKey:@"WZLastStage"];
    [d synchronize];

    FILE *fp = fopen(WZ_STAGE_FILE, "w");
    if (fp) {
        fprintf(fp, "%s\n", stage);
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
    }
}

static NSString *wz_read_last_stage(void)
{
    NSString *s = [[NSUserDefaults standardUserDefaults] stringForKey:@"WZLastStage"];
    if (s.length) return s;

    FILE *fp = fopen(WZ_STAGE_FILE, "r");
    if (!fp) return nil;
    char buf[128] = {0};
    if (fgets(buf, sizeof(buf) - 1, fp)) {
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    }
    fclose(fp);
    return buf[0] ? [NSString stringWithUTF8String:buf] : nil;
}

#pragma mark - 16.2 偏移

// iOS 16.2 (xnu-8792.62.2) / iPhone 14 Pro Max (T8120)
// proc / proc_ro / ucred / task 的结构体布局在 16.0 - 16.3 之间没有变化，
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

#pragma mark - 指针 / 数值校验

// 内核指针基本校验：内核段地址高 16 位全 1。
// 链表遍历必须做这个检查——拿野地址去 kread 会让内核缺页，直接 panic 重启。
static inline BOOL wz_is_kptr(uint64_t p)
{
    return p > 0xffff000000000000ULL && p != 0xffffffffffffffffULL;
}

// pid 合法性：内核里合法的 pid 远小于这个上限，越界说明读到了别的东西
static inline BOOL wz_is_pid(uint32_t pid)
{
    return pid < 200000;
}

#pragma mark - 进程遍历

// 从起点沿 p_list.le_prev 走，最多 limit 个。
// 遇到回到起点、非法指针、或者 pid 明显不合理就停。
static uint64_t wz_walk_procs(int limit,
                              uint64_t (^match)(uint64_t proc, int idx))
{
    uint64_t start = get_kernproc();
    if (!wz_is_kptr(start)) return 0;

    uint64_t proc = start;
    for (int i = 0; i < limit; i++) {
        if (!wz_is_kptr(proc)) break;

        uint32_t pid = kread32(proc + off_p_pid);
        if (!wz_is_pid(pid)) {
            wz_log("walk: 第 %d 个节点 pid=%u 不合理，停止", i, pid);
            break;
        }

        uint64_t hit = match ? match(proc, i) : 0;
        if (hit) return hit;

        uint64_t next = kread64(proc + off_p_list_le_prev);
        if (next == start || !wz_is_kptr(next)) break;
        proc = next;
    }
    return 0;
}

static uint64_t wz_find_proc_by_pid(pid_t pid)
{
    return wz_walk_procs(WZ_WALK_LIMIT, ^uint64_t(uint64_t proc, int idx) {
        return ((pid_t)kread32(proc + off_p_pid) == pid) ? proc : 0;
    });
}

static uint64_t wz_find_proc_by_substr(const char *needle, pid_t *outPid)
{
    __block pid_t found = 0;
    uint64_t hit = wz_walk_procs(WZ_WALK_LIMIT, ^uint64_t(uint64_t proc, int idx) {
        char name[32] = {0};
        do_kread(proc + off_p_name, name, sizeof(name) - 1);
        if (name[0] && strstr(name, needle)) {
            found = (pid_t)kread32(proc + off_p_pid);
            return proc;
        }
        return 0;
    });
    if (hit && outPid) *outPid = found;
    return hit;
}

static void wz_dump_procs(int logEvery)
{
    wz_log("---- process list ----");
    __block int count = 0;
    wz_walk_procs(WZ_WALK_LIMIT, ^uint64_t(uint64_t proc, int idx) {
        if (logEvery <= 0 || idx < 30) {
            char name[32] = {0};
            do_kread(proc + off_p_name, name, sizeof(name) - 1);
            wz_log("pid=%-6d name=%s", kread32(proc + off_p_pid), name);
        }
        count++;
        return 0;
    });
    wz_log("---- end (%d entries) ----", count);
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
    if (!wz_is_kptr(proc_ro)) {
        wz_log("attach: proc_ro 非法 0x%llx（off_p_proc_ro 可能填错）", proc_ro);
        return -2;
    }

    // 强校验：proc_ro 的第一个字段 pr_proc 必须指回自己。
    // 这一条过不了就绝不往下写——往错的地址写 4 字节是直接 panic。
    uint64_t pr_proc = kread64(proc_ro + off_p_ro_pr_proc);
    if ((pr_proc & 0x0000000fffffffffULL) != (proc & 0x0000000fffffffffULL)) {
        wz_log("attach: pr_proc 校验失败 (pr_proc=0x%llx proc=0x%llx)，放弃写 csflags",
               pr_proc, proc);
        return -4;
    }

    uint32_t csflags = kread32(proc_ro + off_p_ro_p_csflags);
    wz_log("attach: pid=%d proc=0x%llx proc_ro=0x%llx csflags=0x%08x", pid, proc, proc_ro, csflags);

    // csflags 高位不该有垃圾，否则说明 0x1c 这个偏移不对
    if ((csflags & 0xFFFF0000u) != 0) {
        wz_log("attach: csflags 0x%08x 不像 csflags，放弃写入", csflags);
        return -5;
    }

    if (!(csflags & CS_GET_TASK_ALLOW)) {
        kwrite32(proc_ro + off_p_ro_p_csflags, csflags | CS_GET_TASK_ALLOW);
        uint32_t after = kread32(proc_ro + off_p_ro_p_csflags);
        wz_log("attach: csflags patched -> 0x%08x (readback 0x%08x)",
               csflags | CS_GET_TASK_ALLOW, after);
        if (after != (csflags | CS_GET_TASK_ALLOW)) {
            wz_log("attach: csflags 回读不一致");
            return -6;
        }
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
        wz_status("kfd:ok p%d m%08X", g_target_pid, m32);
        wz_log("region: MACH-O MAGIC OK");
    } else {
        wz_status("kfd:ok p%d m%08X?", g_target_pid, m32);
        wz_log("region: magic mismatch");
    }
}

#pragma mark - 主流程

static uint64_t wz_open_kfd(void)
{
    // SimpleKFD 的实测默认组合：2048 页 / smith / sem_open / sem_open，
    // 并且开启 build + device 校验——校验不过就直接返回 0，不会拿着错的偏移去写内核。
    wz_stage("2:kopen-strict");
    uint64_t k = do_kopen(WZ_PUAF_PAGES, 1, 1, 1, true, true);
    if (k) return k;

    wz_log("严格模式 kopen 失败，退回不带校验的模式再试一次");
    wz_stage("2:kopen-loose");
    k = do_kopen(WZ_PUAF_PAGES, 1, 1, 1, false, false);
    return k;
}

static void *wz_thread(void *arg)
{
    @autoreleasepool {
        wz_status("kfd:boot");
        wz_log("=== wz probe start, pid=%d uid=%d ===", getpid(), getuid());

        wz_stage("1:offsets");
        wz_set_offsets_16_2();
        wz_log("offsets set: p_pid=0x%x p_name=0x%x proc_ro=0x%x csflags=0x%x",
               off_p_pid, off_p_name, off_p_proc_ro, off_p_ro_p_csflags);

        // 1. 打 PUAF + 建读写通道
        uint64_t k = wz_open_kfd();
        if (!k) {
            wz_stage("2:kopen-FAIL");
            wz_status("kfd:FAIL open");
            wz_log("do_kopen returned 0");
            g_enabled = YES;
            return NULL;
        }
        wz_log("do_kopen OK, kfd=0x%llx slide=0x%llx", k, get_kslide());
        wz_status("kfd:ok s%llx", get_kslide());

        // 2. 自检：读自己的 proc，核对 pid 和进程名
        wz_stage("3:selfproc");
        uint64_t kernproc = get_kernproc();
        wz_log("kernproc=0x%llx slide=0x%llx", kernproc, get_kslide());
        if (!wz_is_kptr(kernproc)) {
            wz_stage("3:kernproc-bad");
            wz_status("kfd:ok kp?");
            g_enabled = YES;
            return NULL;
        }

        uint64_t self_proc = wz_find_proc_by_pid(getpid());
        if (!self_proc) {
            wz_stage("3:self-not-found");
            wz_status("kfd:ok self?");
            g_enabled = YES;
            return NULL;
        }

        char self_name[32] = {0};
        do_kread(self_proc + off_p_name, self_name, sizeof(self_name) - 1);
        wz_log("self proc=0x%llx pid=%d name='%s' progname='%s'",
               self_proc, kread32(self_proc + off_p_pid), self_name, getprogname());

        // p_name 偏移对不对，用进程名做交叉验证
        if (!self_name[0]) {
            wz_stage("3:name-empty");
            wz_status("kfd:ok name?");
            g_enabled = YES;
            return NULL;
        }
        wz_status("kfd:ok %s", self_name);

        // 3. dump 进程表，方便确认目标进程名
        wz_stage("4:scan");
        wz_dump_procs(0);

        // 4. 找目标
        pid_t tpid = 0;
        uint64_t tproc = wz_find_proc_by_substr("smoba", &tpid);
        if (!tproc) {
            wz_stage("4:no-target");
            wz_status("kfd:ok noT");
            wz_log("target 'smoba' not running");
            g_enabled = YES;
            return NULL;
        }
        wz_log("target found: pid=%d proc=0x%llx", tpid, tproc);
        wz_status("kfd:ok p%d", tpid);

        // 5. attach
        wz_stage("5:attach");
        int rc = wz_attach(tpid);
        if (rc != 0) {
            wz_stage("5:attach-fail");
            wz_status("kfd:ok p%d t%d", tpid, rc);
            g_enabled = YES;
            return NULL;
        }

        // 6. 验证读取
        wz_stage("6:read");
        wz_probe_target_image();

        wz_stage("7:done");
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

        // 先把上一次崩在哪一步显示出来，留 3 秒给人看清，再开始跑
        NSString *last = wz_read_last_stage();
        if (last.length) {
            snprintf(g_status, sizeof(g_status), "last:%s", last.UTF8String);
            wz_log("previous stage: %s", last.UTF8String);
        }

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            pthread_t th;
            pthread_create(&th, NULL, wz_thread, NULL);
            pthread_detach(th);
        });
    });
}
