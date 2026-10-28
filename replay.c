// replay.c — replay recorded pgbench <-> PostgreSQL traffic (record.sh traces) over
// Unix domain or TCP sockets and measure throughput/latency of the transport.
//
//   replay info   -d TRACEDIR
//   replay server -d TRACEDIR -a unix:/path/sock | tcp:[HOST:]PORT
//   replay client -d TRACEDIR -a unix:/path/sock | tcp:[HOST:]PORT [-c N] [-T SEC | -n LOOPS] [-V] [-R] [-o FILE]
//
// A trace (c2s.PID.bin + s2c.PID.bin) is split into rounds: a request is everything the
// client sent up to and including Sync ('S') or Query ('Q'), the response is everything the
// server sent up to and including ReadyForQuery ('Z'). Round 0 is the startup exchange.
// The client sends one round, waits for 'Z', and records the round-trip time (closed loop,
// like pgbench without pipelining). Rounds 1..n-1 are cycled until -T or -n is reached.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define HDR_MAGIC 0x52504c59u /* "RPLY": client -> fake server, selects the trace */

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "replay: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static uint32_t be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* ---------- traces ---------- */

typedef struct { size_t off, len; } span_t;
typedef struct { span_t *v; int n, cap; } spans_t;

static void spans_push(spans_t *s, size_t off, size_t len)
{
	if (s->n == s->cap) {
		s->cap = s->cap ? s->cap * 2 : 256;
		if (!(s->v = realloc(s->v, s->cap * sizeof *s->v)))
			die("out of memory");
	}
	s->v[s->n++] = (span_t){off, len};
}

typedef struct {
	char name[256];      /* PID part of c2s.PID.bin */
	uint8_t *c2s, *s2c;
	size_t c2s_len, s2c_len;
	spans_t req, resp;   /* round i: client sends req[i] (from c2s), server answers resp[i] (from s2c) */
	int n;               /* usable rounds, round 0 = startup */
	span_t term;         /* Terminate ('X') message, len 0 if absent */
	long c2s_msgs, s2c_msgs;
} trace_t;

static uint8_t *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		die("open %s: %s", path, strerror(errno));
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t *b = malloc(sz ? sz : 1);
	if (!b)
		die("out of memory");
	if (sz && fread(b, 1, sz, f) != (size_t)sz)
		die("read %s failed", path);
	fclose(f);
	*len = sz;
	return b;
}

/* Split a trace into rounds. Returns false for connections that are not a normal session. */
static bool parse_trace(trace_t *t)
{
	const uint8_t *d = t->c2s;
	size_t L = t->c2s_len, p, start;

	if (L < 8)
		return false;
	uint32_t len = be32(d), code = be32(d + 4);
	if (code == 80877102)                       /* CancelRequest connection */
		return false;
	if (code == 80877103 || code == 80877104)
		die("%s: SSL/GSS negotiation in the trace is not supported", t->name);
	if ((code >> 16) != 3 || len > L)
		die("%s: c2s does not start with a startup message", t->name);
	spans_push(&t->req, 0, len);

	p = start = len;
	while (p + 5 <= L) {
		char ty = d[p];
		uint32_t ml = be32(d + p + 1);
		if (ml < 4 || p + 1 + ml > L)
			break;
		if (ty == 'X') {
			t->term = (span_t){p, 1 + ml};
			break;
		}
		p += 1 + ml;
		t->c2s_msgs++;
		if (ty == 'S' || ty == 'Q') {
			spans_push(&t->req, start, p - start);
			start = p;
		}
	}
	if (start != p)
		fprintf(stderr, "replay: %s: %zu bytes of client messages without Sync at the end ignored\n",
			t->name, p - start);

	d = t->s2c;
	L = t->s2c_len;
	p = start = 0;
	while (p + 5 <= L) {
		char ty = d[p];
		uint32_t ml = be32(d + p + 1);
		if (ml < 4 || p + 1 + ml > L)
			break;
		if (ty == 'R' && t->resp.n == 0 && ml >= 8 && be32(d + p + 5) != 0)
			die("%s: server requested a password; set 'trust' in pg_hba.conf and record again", t->name);
		p += 1 + ml;
		t->s2c_msgs++;
		if (ty == 'Z') {
			spans_push(&t->resp, start, p - start);
			start = p;
		}
	}

	t->n = t->req.n < t->resp.n ? t->req.n : t->resp.n;
	if (t->req.n != t->resp.n)
		fprintf(stderr, "replay: %s: %d requests but %d responses, using %d rounds\n",
			t->name, t->req.n, t->resp.n, t->n);
	return true;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Load all c2s.*.bin / s2c.*.bin pairs, sorted by name, so client and server agree on indexes. */
static trace_t *load_traces(const char *dir, int min_rounds, int *ntr)
{
	DIR *dd = opendir(dir);
	if (!dd)
		die("open %s: %s", dir, strerror(errno));
	char **names = NULL;
	int nn = 0, cap = 0;
	struct dirent *e;
	while ((e = readdir(dd))) {
		size_t l = strlen(e->d_name);
		if (l > 8 && !strncmp(e->d_name, "c2s.", 4) && !strcmp(e->d_name + l - 4, ".bin")) {
			if (nn == cap && !(names = realloc(names, (cap = cap ? cap * 2 : 16) * sizeof *names)))
				die("out of memory");
			names[nn++] = strdup(e->d_name);
		}
	}
	closedir(dd);
	qsort(names, nn, sizeof *names, cmp_str);

	trace_t *tr = calloc(nn ? nn : 1, sizeof *tr);
	int k = 0;
	for (int i = 0; i < nn; i++) {
		trace_t *t = &tr[k];
		char path[4096];
		snprintf(t->name, sizeof t->name, "%.*s", (int)(strlen(names[i]) - 8), names[i] + 4);
		snprintf(path, sizeof path, "%s/c2s.%s.bin", dir, t->name);
		t->c2s = read_file(path, &t->c2s_len);
		snprintf(path, sizeof path, "%s/s2c.%s.bin", dir, t->name);
		t->s2c = read_file(path, &t->s2c_len);
		free(names[i]);
		if (!parse_trace(t) || t->n < min_rounds) {
			fprintf(stderr, "replay: skipping trace %s (%d rounds, need %d)\n", t->name, t->n, min_rounds);
			free(t->c2s); free(t->s2c); free(t->req.v); free(t->resp.v);
			memset(t, 0, sizeof *t);
			continue;
		}
		k++;
	}
	free(names);
	if (!k)
		die("no usable traces in %s (min rounds %d)", dir, min_rounds);
	*ntr = k;
	return tr;
}

/* ---------- sockets ---------- */

typedef struct {
	struct sockaddr_storage ss;
	socklen_t len;
	int family;
} addr_t;

static addr_t parse_addr(const char *spec, bool passive)
{
	addr_t a;
	memset(&a, 0, sizeof a);
	if (!strncmp(spec, "unix:", 5)) {
		struct sockaddr_un *u = (struct sockaddr_un *)&a.ss;
		if (strlen(spec + 5) >= sizeof u->sun_path)
			die("socket path too long: %s", spec + 5);
		u->sun_family = AF_UNIX;
		strcpy(u->sun_path, spec + 5);
		a.len = sizeof *u;
		a.family = AF_UNIX;
		return a;
	}
	if (!strncmp(spec, "tcp:", 4)) {
		char host[256] = "127.0.0.1";
		const char *s = spec + 4, *c = strrchr(s, ':'), *port = s;
		if (c) {
			snprintf(host, sizeof host, "%.*s", (int)(c - s), s);
			port = c + 1;
		}
		struct addrinfo hints = {0}, *res;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if (passive)
			hints.ai_flags = AI_PASSIVE;
		int rc = getaddrinfo(host, port, &hints, &res);
		if (rc)
			die("%s: %s", spec, gai_strerror(rc));
		memcpy(&a.ss, res->ai_addr, res->ai_addrlen);
		a.len = res->ai_addrlen;
		a.family = res->ai_family;
		freeaddrinfo(res);
		return a;
	}
	die("address must be unix:PATH or tcp:[HOST:]PORT, got '%s'", spec);
	return a;
}

static void set_nodelay(int fd, int family)
{
	int one = 1;
	if (family != AF_UNIX)          /* libpq and the postmaster do the same */
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static int write_all(int fd, const uint8_t *b, size_t n)
{
	while (n) {
		ssize_t k = send(fd, b, n, MSG_NOSIGNAL);
		if (k < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		b += k;
		n -= k;
	}
	return 0;
}

/* Receive buffer: messages are parsed in place, b[pos..fill) is unconsumed data. */
typedef struct {
	uint8_t *b;
	size_t cap, pos, fill;
} rbuf_t;

/* Make sure n unconsumed bytes are buffered. Returns -1 on EOF or error. */
static int rb_need(rbuf_t *r, int fd, size_t n)
{
	if (r->fill - r->pos >= n)
		return 0;
	if (r->pos) {
		memmove(r->b, r->b + r->pos, r->fill - r->pos);
		r->fill -= r->pos;
		r->pos = 0;
	}
	if (n > r->cap || !r->b) {
		r->cap = n < 65536 ? 65536 : n * 2;
		if (!(r->b = realloc(r->b, r->cap)))
			die("out of memory");
	}
	while (r->fill < n) {
		ssize_t k = recv(fd, r->b + r->fill, r->cap - r->fill, 0);
		if (k == 0)
			return -1;
		if (k < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		r->fill += k;
	}
	return 0;
}

/* ---------- info ---------- */

static int cmd_info(const char *dir)
{
	int ntr;
	trace_t *tr = load_traces(dir, 1, &ntr);
	printf("%-10s %8s %10s %10s %10s %10s %12s %12s\n",
	       "trace", "rounds", "c2s_msgs", "s2c_msgs", "c2s_bytes", "s2c_bytes", "avg_req_B", "avg_resp_B");
	for (int i = 0; i < ntr; i++) {
		trace_t *t = &tr[i];
		size_t rq = 0, rs = 0;
		for (int k = 1; k < t->n; k++) {
			rq += t->req.v[k].len;
			rs += t->resp.v[k].len;
		}
		int m = t->n > 1 ? t->n - 1 : 1;
		printf("%-10s %8d %10ld %10ld %10zu %10zu %12.1f %12.1f\n", t->name, t->n, t->c2s_msgs,
		       t->s2c_msgs, t->c2s_len, t->s2c_len, (double)rq / m, (double)rs / m);
	}
	return 0;
}

/* ---------- fake server ---------- */

/* One process per connection, like the postmaster. Answers each Sync/Query with the next recorded response. */
static void serve(int fd, trace_t *tr, int ntr)
{
	rbuf_t r = {0};

	if (rb_need(&r, fd, 12))
		return;
	uint32_t magic = be32(r.b), idx = be32(r.b + 4), n = be32(r.b + 8);
	r.pos = 12;
	if (magic != HDR_MAGIC || idx >= (uint32_t)ntr || n != (uint32_t)tr[idx].n) {
		fprintf(stderr, "replay server: bad connection header (client and server loaded different traces?)\n");
		return;
	}
	trace_t *t = &tr[idx];

	if (rb_need(&r, fd, 4))
		return;
	uint32_t len = be32(r.b + r.pos);
	if (len < 8 || rb_need(&r, fd, len))
		return;
	r.pos += len;
	if (write_all(fd, t->s2c + t->resp.v[0].off, t->resp.v[0].len))
		return;

	int k = 1;
	for (;;) {
		if (rb_need(&r, fd, 5))
			return;
		char ty = r.b[r.pos];
		uint32_t ml = be32(r.b + r.pos + 1);
		if (ml < 4 || rb_need(&r, fd, 1 + ml))
			return;
		r.pos += 1 + ml;
		if (ty == 'X')
			return;
		if (ty == 'S' || ty == 'Q') {
			span_t s = t->resp.v[k];
			if (write_all(fd, t->s2c + s.off, s.len))
				return;
			if (++k == t->n)
				k = 1;
		}
	}
}

static int cmd_server(const char *dir, const char *spec, int min_rounds)
{
	int ntr;
	trace_t *tr = load_traces(dir, min_rounds, &ntr);
	addr_t a = parse_addr(spec, true);

	int lfd = socket(a.family, SOCK_STREAM, 0);
	if (lfd < 0)
		die("socket: %s", strerror(errno));
	if (a.family == AF_UNIX) {
		unlink(((struct sockaddr_un *)&a.ss)->sun_path);
	} else {
		int one = 1;
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	}
	if (bind(lfd, (struct sockaddr *)&a.ss, a.len))
		die("bind %s: %s", spec, strerror(errno));
	if (a.family == AF_UNIX)
		chmod(((struct sockaddr_un *)&a.ss)->sun_path, 0777);
	if (listen(lfd, 1024))
		die("listen: %s", strerror(errno));
	signal(SIGCHLD, SIG_IGN);       /* auto-reap connection processes */
	fprintf(stderr, "replay server: %d traces loaded, listening on %s\n", ntr, spec);

	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			die("accept: %s", strerror(errno));
		}
		pid_t pid = fork();
		if (pid == 0) {
			close(lfd);
			set_nodelay(fd, a.family);
			serve(fd, tr, ntr);
			_exit(0);
		}
		if (pid < 0)
			fprintf(stderr, "replay server: fork: %s\n", strerror(errno));
		close(fd);
	}
}

/* ---------- client ---------- */

typedef struct {
	int id, idx;
	trace_t *t;
	uint64_t *lat;
	size_t nlat, cap;
	uint64_t rounds, loops, bytes_out, bytes_in, errors, mismatches;
	uint64_t t0, t1;
	const char *fail;
} client_t;

static addr_t g_addr;
static double g_dur;
static long g_loops;
static bool g_verify, g_real;
static pthread_barrier_t g_bar;

/* Read server messages up to ReadyForQuery. If exp is set, compare with the recorded response. */
static int read_response(int fd, rbuf_t *r, client_t *c, const uint8_t *exp, size_t explen, bool *mismatch)
{
	size_t v = 0;
	for (;;) {
		if (rb_need(r, fd, 5))
			return -1;
		uint8_t ty = r->b[r->pos];
		uint32_t ml = be32(r->b + r->pos + 1);
		if (ml < 4 || rb_need(r, fd, 1 + ml))
			return -1;
		const uint8_t *m = r->b + r->pos;
		r->pos += 1 + ml;
		c->bytes_in += 1 + ml;
		if (exp && !*mismatch && (v + 1 + ml > explen || memcmp(m, exp + v, 1 + ml)))
			*mismatch = true;
		v += 1 + ml;
		if (ty == 'E')
			c->errors++;
		if (ty == 'Z') {
			if (exp && v != explen)
				*mismatch = true;
			return 0;
		}
	}
}

static void lat_push(client_t *c, uint64_t ns)
{
	if (c->nlat == c->cap) {
		c->cap = c->cap ? c->cap * 2 : 1 << 16;
		if (!(c->lat = realloc(c->lat, c->cap * sizeof *c->lat)))
			die("out of memory");
	}
	c->lat[c->nlat++] = ns;
}

static void *client_main(void *arg)
{
	client_t *c = arg;
	trace_t *t = c->t;
	rbuf_t r = {0};
	bool mm = false;
	int fd = socket(g_addr.family, SOCK_STREAM, 0);

	if (fd < 0 || connect(fd, (struct sockaddr *)&g_addr.ss, g_addr.len)) {
		c->fail = strerror(errno);
	} else {
		set_nodelay(fd, g_addr.family);
		uint8_t h[12];
		put32(h, HDR_MAGIC);
		put32(h + 4, c->idx);
		put32(h + 8, t->n);
		if ((!g_real && write_all(fd, h, sizeof h)) ||
		    write_all(fd, t->c2s + t->req.v[0].off, t->req.v[0].len) ||
		    read_response(fd, &r, c, NULL, 0, &mm))
			c->fail = "startup failed (connection closed)";
	}
	pthread_barrier_wait(&g_bar);   /* all clients connected: start measuring together */
	if (c->fail)
		goto out;

	c->t0 = now_ns();
	uint64_t deadline = g_dur > 0 ? c->t0 + (uint64_t)(g_dur * 1e9) : UINT64_MAX;
	int k = 1;
	for (;;) {
		span_t q = t->req.v[k], s = t->resp.v[k];
		uint64_t a = now_ns();
		mm = false;
		if (write_all(fd, t->c2s + q.off, q.len) ||
		    read_response(fd, &r, c, g_verify && !g_real ? t->s2c + s.off : NULL, s.len, &mm)) {
			c->fail = "connection closed during replay";
			break;
		}
		uint64_t b = now_ns();
		lat_push(c, b - a);
		c->rounds++;
		c->bytes_out += q.len;
		c->mismatches += mm;
		if (++k == t->n) {
			k = 1;
			if (g_loops && ++c->loops >= (uint64_t)g_loops)
				break;
		}
		if (b >= deadline)
			break;
	}
	c->t1 = now_ns();
	if (t->term.len)
		write_all(fd, t->c2s + t->term.off, t->term.len);
out:
	if (fd >= 0)
		close(fd);
	free(r.b);
	return NULL;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

static double pct(const uint64_t *v, size_t n, double p)
{
	size_t i = (size_t)(p / 100.0 * (n - 1) + 0.5);
	return v[i] / 1000.0;
}

static int cmd_client(const char *dir, const char *spec, int nclients, int min_rounds, const char *out)
{
	int ntr;
	trace_t *tr = load_traces(dir, min_rounds, &ntr);
	g_addr = parse_addr(spec, false);
	if (nclients <= 0)
		nclients = ntr;
	if (g_dur <= 0 && g_loops <= 0)
		g_loops = 1;
	if (g_real && (g_loops != 1 || g_dur > 0))
		fprintf(stderr, "replay: note: against real PostgreSQL only one pass (-n 1) replays cleanly "
				"(-M prepared re-sends Parse, which then fails)\n");

	client_t *cl = calloc(nclients, sizeof *cl);
	pthread_t *th = calloc(nclients, sizeof *th);
	pthread_barrier_init(&g_bar, NULL, nclients);
	for (int i = 0; i < nclients; i++) {
		cl[i].id = i;
		cl[i].idx = i % ntr;
		cl[i].t = &tr[i % ntr];
		if (pthread_create(&th[i], NULL, client_main, &cl[i]))
			die("pthread_create failed");
	}

	uint64_t rounds = 0, bout = 0, bin = 0, errs = 0, mism = 0, t0 = UINT64_MAX, t1 = 0;
	size_t nlat = 0;
	int failed = 0;
	for (int i = 0; i < nclients; i++) {
		pthread_join(th[i], NULL);
		client_t *c = &cl[i];
		if (c->fail) {
			fprintf(stderr, "replay: client %d (trace %s): %s\n", i, c->t->name, c->fail);
			failed++;
		}
		if (!c->rounds)
			continue;
		rounds += c->rounds;
		bout += c->bytes_out;
		bin += c->bytes_in;
		errs += c->errors;
		mism += c->mismatches;
		nlat += c->nlat;
		if (c->t0 < t0) t0 = c->t0;
		if (c->t1 > t1) t1 = c->t1;
	}
	if (!rounds)
		die("no rounds completed");

	uint64_t *all = malloc(nlat * sizeof *all);
	size_t p = 0;
	for (int i = 0; i < nclients; i++) {
		memcpy(all + p, cl[i].lat, cl[i].nlat * sizeof *all);
		p += cl[i].nlat;
	}
	if (out) {
		FILE *f = fopen(out, "w");
		if (!f)
			die("open %s: %s", out, strerror(errno));
		fprintf(f, "latency_ns\n");
		for (size_t i = 0; i < nlat; i++)
			fprintf(f, "%lu\n", all[i]);
		fclose(f);
	}
	qsort(all, nlat, sizeof *all, cmp_u64);
	double sum = 0;
	for (size_t i = 0; i < nlat; i++)
		sum += all[i];

	double el = (t1 - t0) / 1e9;
	printf("target:     %s%s\n", spec, g_real ? " (real PostgreSQL)" : "");
	printf("traces:     %d from %s, clients: %d%s\n", ntr, dir, nclients,
	       failed ? " (some failed, see above)" : "");
	printf("rounds:     %lu in %.3f s = %.0f rounds/s\n", rounds, el, rounds / el);
	printf("data:       client->server %.2f MB/s, server->client %.2f MB/s\n", bout / el / 1e6, bin / el / 1e6);
	printf("latency us: avg %.2f  p50 %.2f  p90 %.2f  p99 %.2f  p99.9 %.2f  max %.2f\n",
	       sum / nlat / 1000.0, pct(all, nlat, 50), pct(all, nlat, 90), pct(all, nlat, 99),
	       pct(all, nlat, 99.9), all[nlat - 1] / 1000.0);
	if (errs || g_real)
		printf("ErrorResponse messages: %lu\n", errs);
	if (g_verify && !g_real)
		printf("verify:     %lu mismatching responses\n", mism);
	return failed ? 1 : 0;
}

/* ---------- main ---------- */

static void usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  replay info   -d TRACEDIR\n"
		"  replay server -d TRACEDIR -a ADDR [-m MINROUNDS]\n"
		"  replay client -d TRACEDIR -a ADDR [-c CLIENTS] [-T SECONDS | -n LOOPS] [-V] [-R] [-o FILE] [-m MINROUNDS]\n"
		"\n"
		"  ADDR       unix:/path/to/socket or tcp:[HOST:]PORT\n"
		"  -c N       client connections (default: one per trace; trace = client %% traces)\n"
		"  -T SEC     run for SEC seconds, cycling the trace\n"
		"  -n LOOPS   replay each trace LOOPS times (default 1 if no -T)\n"
		"  -V         verify responses byte-for-byte against the recording (fake server only)\n"
		"  -R         target is a real PostgreSQL server (no replay header)\n"
		"  -o FILE    write every round-trip latency (ns) to FILE\n"
		"  -m N       skip traces with fewer than N rounds, e.g. pgbench's setup connection (default 20);\n"
		"             client and server must use the same value\n");
	exit(2);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		usage();
	const char *cmd = argv[1], *dir = NULL, *addr = NULL, *out = NULL;
	int nclients = 0, min_rounds = 20, o;

	optind = 2;
	while ((o = getopt(argc, argv, "d:a:c:T:n:m:o:VR")) != -1) {
		switch (o) {
		case 'd': dir = optarg; break;
		case 'a': addr = optarg; break;
		case 'c': nclients = atoi(optarg); break;
		case 'T': g_dur = atof(optarg); break;
		case 'n': g_loops = atol(optarg); break;
		case 'm': min_rounds = atoi(optarg); break;
		case 'o': out = optarg; break;
		case 'V': g_verify = true; break;
		case 'R': g_real = true; break;
		default: usage();
		}
	}
	if (!dir)
		usage();
	if (!strcmp(cmd, "info"))
		return cmd_info(dir);
	if (!addr)
		usage();
	if (!strcmp(cmd, "server"))
		return cmd_server(dir, addr, min_rounds);
	if (!strcmp(cmd, "client"))
		return cmd_client(dir, addr, nclients, min_rounds, out);
	usage();
}
