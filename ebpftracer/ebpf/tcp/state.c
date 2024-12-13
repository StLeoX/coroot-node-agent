// TCP state monitoring, both client-side and server-side

#define MAX_CONNECTIONS 1000000

struct tcp_event {
    __u64 fd;
    __u64 timestamp;
    __u64 duration;
    __u32 type;
    __u32 pid;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u16 sport;
    __u16 dport;
    __u16 aport;
    // IP address parser supports "IPv4 in IPv6".
    __u8 saddr[16];
    __u8 daddr[16];
    __u8 aaddr[16];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_listen_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_connect_events SEC(".maps");

struct trace_event_raw_inet_sock_set_state__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u64 unused2;
#endif
    void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
#if __KERNEL_FROM >= 506
    __u16 protocol;
#else
    __u8 protocol;
#endif
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

struct connection_id {
    __u64 fd;
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(struct connection_id));
    __uint(max_entries, MAX_CONNECTIONS);
} connection_id_by_socket SEC(".maps");

struct connection {
    __u64 timestamp;
    __u64 bytes_sent;
    __u64 bytes_received;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct connection));
    __uint(max_entries, MAX_CONNECTIONS);
} active_connections SEC(".maps");


SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx)
{
    struct trace_event_raw_inet_sock_set_state__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    if (args.protocol != IPPROTO_TCP) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    // This transfer stands for new connection.
    if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_SYN_SENT) {
        __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);

        if (!fdp) {
            return 0;
        }
        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = *fdp;

        struct connection conn = {};
        conn.timestamp = bpf_ktime_get_ns();

        bpf_map_delete_elem(&fd_by_pid_tgid, &id);
        bpf_map_update_elem(&connection_id_by_socket, &args.skaddr, &cid, BPF_ANY);
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
        return 0;
    }

    __u64 fd = 0;
    __u32 type = 0;
    __u64 timestamp = 0;
    __u64 duration = 0;
    // client-side or server-side tcp_event
    void *tcp_events_p = &tcp_connect_events;

    struct tcp_event e = {};

    if (args.oldstate == BPF_TCP_SYN_SENT) {
        struct connection_id *cid = bpf_map_lookup_elem(&connection_id_by_socket, &args.skaddr);
        if (!cid) {
            return 0;
        }
        // 从缓存表中拿到活跃连接
        struct connection *conn = bpf_map_lookup_elem(&active_connections, cid);
        if (!conn) {
            return 0;
        }
        if (args.newstate == BPF_TCP_ESTABLISHED) {
            timestamp = conn->timestamp;
            type = EVENT_TYPE_CONNECTION_OPEN;
        } else if (args.newstate == BPF_TCP_CLOSE) {
            // 建连过程异常，需要清除活跃连接
            bpf_map_delete_elem(&active_connections, cid);
            type = EVENT_TYPE_CONNECTION_ERROR;
        }
        duration = bpf_ktime_get_ns() - conn->timestamp;
        pid = cid->pid;
        fd = cid->fd;
    }

    if (args.oldstate == BPF_TCP_ESTABLISHED && (args.newstate == BPF_TCP_FIN_WAIT1 || args.newstate == BPF_TCP_CLOSE_WAIT)) {
        // 清除活跃连接的套接字
        bpf_map_delete_elem(&connection_id_by_socket, &args.skaddr);
    }

    if (args.oldstate == BPF_TCP_CLOSE && args.newstate == BPF_TCP_LISTEN) {
        type = EVENT_TYPE_LISTEN_OPEN;
        tcp_events_p = &tcp_listen_events;
    }

    if (args.oldstate == BPF_TCP_LISTEN && args.newstate == BPF_TCP_CLOSE) {
        type = EVENT_TYPE_LISTEN_CLOSE;
        tcp_events_p = &tcp_listen_events;
    }

    if (type == EVENT_TYPE_UNKNOWN) {
        return 0;
    }

    // 构建 tcp_event
    e.type = type;
    e.duration = duration;
    e.timestamp = timestamp;
    e.pid = pid;
    e.sport = args.sport;
    e.dport = args.dport;
    e.fd = fd;
    __builtin_memcpy(&e.saddr, &args.saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &args.daddr_v6, sizeof(e.saddr));

    struct ipPort src = {};
    __builtin_memcpy(&src.ip, &args.saddr_v6, sizeof(args.saddr_v6));
    src.port = args.sport;

    struct ipPort *actualDst = bpf_map_lookup_elem(&actual_destinations, &src);
    if (actualDst) {
        e.aport = actualDst->port;
        __builtin_memcpy(&e.aaddr, &actualDst->ip, sizeof(e.aaddr));
    }

    bpf_perf_event_output(ctx, tcp_events_p, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

struct trace_event_raw_args_with_fd__stub {
    __u64 unused;
    __u64 unused2;
    __u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);
    if (!fdp) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = *fdp;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn && ctx->ret == 0) { // non-TCP connection
        struct connection conn = {};
        conn.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&active_connections, &cid, &conn, BPF_ANY);
    }
    bpf_map_delete_elem(&fd_by_pid_tgid, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(void *ctx) {
    struct trace_event_raw_args_with_fd__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        return 0;
    }
    __u64 id = bpf_get_current_pid_tgid();
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = args.fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn) {
        struct tcp_event e = {};
        e.type = EVENT_TYPE_CONNECTION_CLOSE;
        e.pid = cid.pid;
        e.fd = cid.fd;
        e.bytes_sent = conn->bytes_sent;
        e.bytes_received = conn->bytes_received;
        e.timestamp = conn->timestamp;
        bpf_perf_event_output(ctx, &tcp_connect_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
        bpf_map_delete_elem(&active_connections, &cid);
    }
    return 0;
}
