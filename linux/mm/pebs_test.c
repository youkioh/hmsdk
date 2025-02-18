// htmm_pebs_module.c
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/sched/cputime.h>

#include "../kernel/events/internal.h"

#include <linux/pebs_test.h>

#define CPUS_PER_SOCKET 4
#define BUFFER_SIZE	32 /* 128: 1MB */
#define SAMPLE_PERIOD 1000

/* pebs events */
#define DRAM_LLC_LOAD_MISS  0x1d3
#define REMOTE_DRAM_LLC_LOAD_MISS   0x2d3
#define NVM_LLC_LOAD_MISS   0x80d1
#define ALL_STORES	    0x82d0
#define ALL_LOADS	    0x81d0
#define STLB_MISS_STORES    0x12d0
#define STLB_MISS_LOADS	    0x11d0
#define LLC_LOAD_MISS 0x20d1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sungsu Ahn");
MODULE_DESCRIPTION("PEBS Sampling Module");

static struct task_struct *access_sampling;
static struct perf_event ***mem_event;

static bool valid_va(unsigned long addr)
{
    if (!(addr >> (PGDIR_SHIFT + 9)) && addr != 0)
	return true;
    else
	return false;
}

struct test_event {
    struct perf_event_header header;
    __u64 ip;
    __u32 pid, tid;
    __u64 addr;
    __u64 phys_addr;
};

enum events {
    LLC_LOAD = 0,
    N_HTMMEVENTS
};

static __u64 get_pebs_event(enum events e)
{
    switch (e) {
    case LLC_LOAD:
        return LLC_LOAD_MISS;
	default:
	    return N_HTMMEVENTS;
    }
}


// static void perf_sample_callback(struct perf_event *event,
//                                struct perf_sample_data *data,
//                                struct pt_regs *regs)
// {
//     char *event_name;

//     switch (event->attr.config) {
//         case LLC_LOAD_MISS:
//             event_name = "LLC_LOAD_MISS";
//             break;
//         default:
//             event_name = "UNKNOWN";
//     }

//     pr_info("[PEBS] event: %s, ip=0x%lx, tgid=%d, tid=%d, addr=0x%llx, phys_addr=0x%llx\n",
//             event_name, regs->ip,
//             data->tid_entry.pid,
//             data->tid_entry.tid,
//             data->addr, data->phys_addr);
// }

// static struct perf_buffer *perf_buffer_alloc(int nr_pages)
// {
//     struct perf_buffer *rb;

//     rb = kzalloc(sizeof(*rb), GFP_KERNEL);
//     if (!rb)
//         return NULL;

//     rb->nr_pages = nr_pages;

//     refcount_set(&rb->refcount, 1);
//     INIT_LIST_HEAD(&rb->event_list);
//     spin_lock_init(&rb->event_lock);

//     // 사용자 페이지와 데이터 페이지 할당
//     rb->user_page = (void *)__get_free_pages(GFP_KERNEL, 0);
//     if (!rb->user_page)
//         goto error;

//     rb->data_pages = kcalloc(nr_pages, sizeof(void *), GFP_KERNEL);
//     if (!rb->data_pages) 
//         goto free_user_page;

//     for (int i = 0; i < nr_pages; i++) {
//         rb->data_pages[i] = (void *)__get_free_pages(GFP_KERNEL, 0);
//         if (!rb->data_pages[i])
//             goto free_data_pages;
//     }

//     return rb;

// free_data_pages:
//     for (int i = 0; i < nr_pages; i++) {
//         if (rb->data_pages[i])
//             free_pages((unsigned long)rb->data_pages[i], 0);
//     }
//     kfree(rb->data_pages);
// free_user_page:
//     free_pages((unsigned long)rb->user_page, 0);
// error:
//     kfree(rb);
//     return NULL;
// }

// static void ring_buffer_attach(struct perf_event *event, struct perf_buffer *rb)
// {
//     struct perf_buffer *old_rb = NULL;
//     unsigned long flags;

//     if (event->rb) {
//         old_rb = event->rb;
//         spin_lock_irqsave(&old_rb->event_lock, flags);
//         list_del_rcu(&event->rb_entry);
//         spin_unlock_irqrestore(&old_rb->event_lock, flags);
//     }

//     if (rb) {
//         spin_lock_irqsave(&rb->event_lock, flags);
//         list_add_rcu(&event->rb_entry, &rb->event_list);
//         spin_unlock_irqrestore(&rb->event_lock, flags);
//     }

//     rcu_assign_pointer(event->rb, rb);

//     if (old_rb) {
//         synchronize_rcu();  // RCU 동기화 추가
//         if (refcount_dec_and_test(&old_rb->refcount))
//             kfree(old_rb);
//     }
// }

// static int __perf_event_open(__u64 config, __u64 cpu, __u64 type, __u32 pid)
// {
//     struct perf_event_attr attr;
//     struct perf_event *event;
//     struct perf_buffer *rb;

//     printk(KERN_INFO "[__perf_event_open] Creating PEBS event for CPU %llu, event %llu\n", cpu, type);
//     memset(&attr, 0, sizeof(struct perf_event_attr));

//     attr.type = PERF_TYPE_RAW;
//     attr.size = sizeof(struct perf_event_attr);
//     attr.config = config;
// 	attr.sample_period = SAMPLE_PERIOD;
//     attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;
//     attr.disabled = 0;
//     attr.exclude_kernel = 1;
//     attr.exclude_hv = 1;
//     attr.exclude_callchain_kernel = 1;
//     attr.exclude_callchain_user = 1;
//     attr.precise_ip = 1;
//     attr.enable_on_exec = 1;

//     printk(KERN_INFO "[__perf_event_open] PEBS attributed done for CPU %llu, event %llu\n", cpu, type);

//     event = perf_event_create_kernel_counter(&attr, cpu, NULL, 
//                                            perf_sample_callback, NULL);
//     if (IS_ERR(event)) {
//         printk(KERN_ERR "[__perf_event_open] PEBS init failed for CPU%llu/Event%llu\n", cpu, type);
//         return PTR_ERR(event);
//     }

//     printk(KERN_INFO "[__perf_event_open] PEBS event created for CPU %llu, event %llu\n", cpu, type);

//     // Ring buffer allocation and attachment
//     rb = perf_buffer_alloc(8);  // 8 pages, no overwrite
//     printk(KERN_INFO "[__perf_event_open] PEBS ring buffer allocated for CPU %llu, event %llu\n", cpu, type);
//     if (!rb) {
//         perf_event_release_kernel(event);
//         return -ENOMEM;
//     }

//     ring_buffer_attach(event, rb);
//     printk(KERN_INFO "[__perf_event_open] PEBS ring buffer attached for CPU %llu, event %llu\n", cpu, type);
//     mem_event[cpu][type] = event;
    
//     return 0;
// }

static int __perf_event_open(__u64 config, __u64 cpu,
	__u64 type, __u32 pid)
{
    struct perf_event_attr attr;
    struct file *file;
    int event_fd, __pid;

    memset(&attr, 0, sizeof(struct perf_event_attr));

    attr.type = PERF_TYPE_RAW;
    attr.size = sizeof(struct perf_event_attr);
    attr.config = config;
	attr.sample_period = SAMPLE_PERIOD;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.exclude_callchain_kernel = 1;
    attr.exclude_callchain_user = 1;
    attr.precise_ip = 1;
    attr.enable_on_exec = 1;

    if (pid == 0)
	__pid = -1;
    else
	__pid = pid;
	
    event_fd = test__perf_event_open(&attr, __pid, cpu, -1, 0);
    //event_fd = htmm__perf_event_open(&attr, -1, cpu, -1, 0);
    if (event_fd <= 0) {
	printk("[error test__perf_event_open failure] event_fd: %d\n", event_fd);
	return -1;
    }

    file = fget(event_fd);
    if (!file) {
	printk("invalid file\n");
	return -1;
    }
    mem_event[cpu][type] = fget(event_fd)->private_data;
    return 0;
}

static int pebs_init(void)
{
    int cpu, event;

    printk(KERN_INFO "[pebs_init] start\n");

    mem_event = kzalloc(sizeof(struct perf_event **) * CPUS_PER_SOCKET, GFP_KERNEL);
    for (cpu = 0; cpu < CPUS_PER_SOCKET; cpu++) {
	mem_event[cpu] = kzalloc(sizeof(struct perf_event *) * N_HTMMEVENTS, GFP_KERNEL);
    }

    printk(KERN_INFO "[pebs_init] mem_event initialized \n");

    for (cpu = 0; cpu < CPUS_PER_SOCKET; cpu++) {        
    for (event = 0; event < N_HTMMEVENTS; event++) {
        if (get_pebs_event(event) == N_HTMMEVENTS) {
        mem_event[cpu][event] = NULL;
        continue;
        }
        
        printk(KERN_INFO "Creating PEBS event for CPU %d, event %d\n", cpu, event);
        if (__perf_event_open(get_pebs_event(event), cpu, event, -1)) return -1;
        if (test__perf_event_init(mem_event[cpu][event], BUFFER_SIZE)) return -1;
        printk(KERN_INFO "PEBS event created for event %d\n", event);
    }
    }
    return 0;
}

static void pebs_cleanup(void)
{
    int cpu, event;
    
    for (cpu = 0; cpu < CPUS_PER_SOCKET; cpu++) {
        for (event = 0; event < N_HTMMEVENTS; event++) {
            if (mem_event[cpu][event])
                perf_event_disable(mem_event[cpu][event]);
        }
        kfree(mem_event[cpu]);
    }
}

static int ksamplingd(void *data)
{
    printk(KERN_INFO "[ksamplingd] Sampling thread started\n");
    while (!kthread_should_stop()) {
        int cpu, event, cond = false;
        
        for (cpu = 0; cpu < CPUS_PER_SOCKET; cpu++) {
            for (event = 0; event < N_HTMMEVENTS; event++) {
                do {
                    struct perf_buffer *rb;
                    struct perf_event_mmap_page *up;
                    struct perf_event_header *ph;
                    struct test_event *te;
                    unsigned long pg_index, offset;
                    int page_shift;
                    __u64 head;

                    if (!mem_event[cpu][event]) {
                        printk(KERN_INFO "[ksamplingd] No event for CPU %d, event %d\n", cpu, event);
                        break;
                    }

                    __sync_synchronize();

                    rb = mem_event[cpu][event]->rb;
                    if (!rb) {
                        printk(KERN_INFO "[ksamplingd] Ring buffer is NULL for CPU %d, event %d\n", cpu, event);
                        return -1;
                    }

                    up = READ_ONCE(rb->user_page);
                    head = READ_ONCE(up->data_head);
                    if (head == up->data_tail) {
                        printk(KERN_INFO "[ksamplingd] No new data for CPU %d, event %d\n", cpu, event);
                        break;
                    }

                    head -= up->data_tail;
                    if (head > (BUFFER_SIZE * 50 / 100)) {
                        printk(KERN_INFO "[ksamplingd] Buffer more than 50%% full (size: %llu)\n", head);
                        cond = true;
                    } else if (head < (BUFFER_SIZE * 10 / 100)) {
                        cond = false;
                    }

                    smp_rmb();

                    page_shift = PAGE_SHIFT + page_order(rb);
                    offset = READ_ONCE(up->data_tail);
                    pg_index = (offset >> page_shift) & (rb->nr_pages - 1);
                    offset &= (1 << page_shift) - 1;

                    ph = (void*)(rb->data_pages[pg_index] + offset);
                    switch (ph->type) {
                    case PERF_RECORD_SAMPLE:
                        te = (struct test_event *)ph;
                        if (!valid_va(te->addr)) {
                            printk(KERN_INFO "[ksamplingd] Invalid virtual address detected\n");
                            break;
                        }

                        printk(KERN_INFO "[ksamplingd] PEBS sample: ip=0x%llx, tgid=%d, tid=%d, addr=0x%llx, phys_addr=0x%llx\n",
                            te->ip, te->pid, te->tid, te->addr, te->phys_addr);
                        break;
                    case PERF_RECORD_THROTTLE:
                    case PERF_RECORD_UNTHROTTLE:
                        printk(KERN_INFO "[ksamplingd] Throttle event detected\n");
                        break;
                    case PERF_RECORD_LOST_SAMPLES:
                        printk(KERN_INFO "[ksamplingd] Lost samples event detected\n");
                        break;
                    default:
                        printk(KERN_INFO "[ksamplingd] Unknown event type: %d\n", ph->type);
                        break;
                    }
                    smp_mb();
                    WRITE_ONCE(up->data_tail, up->data_tail + ph->size);
                } while (cond);
            }
        }
        msleep_interruptible(100);
    }
    printk(KERN_INFO "[ksamplingd] Sampling thread stopped\n");
    return 0;
}

int pebs_test_init(void)
{
    printk(KERN_INFO "HTMM PEBS module loading\n");
    int ret;
    if ((ret = pebs_init()) != 0)
        return ret;

    printk(KERN_INFO "PEBS initialized\n");

    access_sampling = kthread_run(ksamplingd, NULL, "pebs_sampling");
    if (IS_ERR(access_sampling)) {
        pebs_cleanup();
        return PTR_ERR(access_sampling);
    }
    
    printk(KERN_INFO "HTMM PEBS module loaded\n");
    return 0;
}

void pebs_test_exit(void)
{
    kthread_stop(access_sampling);
    pebs_cleanup();
    printk(KERN_INFO "HTMM PEBS module unloaded\n");
}

// module_init(pebs_test_init);
// module_exit(pebs_test_exit);
