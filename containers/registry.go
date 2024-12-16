package containers

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netns"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const MinTrafficStatsUpdateInterval = 5 * time.Second

var (
	selfNetNs                = netns.None()
	hostNetNsId              = netns.None().UniqueId()
	agentPid                 = uint32(os.Getpid())
	containerIdRegexp        = regexp.MustCompile(`[a-z0-9]{64}`)
	cronjobPodName           = regexp.MustCompile(`([a-z0-9-]+)-([0-9]{8})-[bcdfghjklmnpqrstvwxz2456789]{5}`)
	cronjobPodScheduleWindow = 7 * 24 * time.Hour
)

type ProcessInfo struct {
	Pid         uint32
	ContainerId ContainerID
	StartedAt   time.Time
}

type Registry struct {
	reg prometheus.Registerer

	tracer *ebpftracer.Tracer
	events chan ebpftracer.Event

	containersById       map[ContainerID]*Container // 内部编号 ContainerID
	containersByCgroupId map[string]*Container      // 通过 host 上的 cgroupID 查找相应的容器
	containersByPid      map[uint32]*Container      // 通过 host 上的进程查找相应的容器，比如 k8s pod
	ip2fqdn              map[netaddr.IP]string      // 维护 DNS 局部缓存
	ip2fqdnLock          sync.RWMutex

	processInfoCh chan<- ProcessInfo

	trafficStatsLastUpdated time.Time
	trafficStatsLock        sync.Mutex
	trafficStatsUpdateCh    chan *TrafficStatsUpdate

	sseBatcher *tracing.SSEventBatcher
}

func NewRegistry(reg prometheus.Registerer, processInfoCh chan<- ProcessInfo) (*Registry, error) {
	ns, err := proc.GetSelfNetNs()
	if err != nil {
		return nil, err
	}
	selfNetNs = ns
	hostNetNs, err := proc.GetHostNetNs()
	if err != nil {
		return nil, err
	}
	defer hostNetNs.Close()
	hostNetNsId = hostNetNs.UniqueId()

	err = proc.ExecuteInNetNs(hostNetNs, selfNetNs, func() error {
		if err := TaskstatsInit(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := cgroup.Init(); err != nil {
		return nil, err
	}
	if err := DockerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := ContainerdInit(); err != nil {
		klog.Warningln(err)
	}
	if err := CrioInit(); err != nil {
		klog.Warningln(err)
	}
	if err := JournaldInit(); err != nil {
		klog.Warningln(err)
	}

	// New chClient
	chClient, err := common.NewChClient()
	if err != nil {
		return nil, err
	}

	r := &Registry{
		reg:                  reg,
		events:               make(chan ebpftracer.Event, 10000), // 参数化 eBPF 消息队列长度。chan 满后是阻塞而不是溢出。
		containersById:       map[ContainerID]*Container{},
		containersByCgroupId: map[string]*Container{},
		containersByPid:      map[uint32]*Container{},
		ip2fqdn:              map[netaddr.IP]string{},

		processInfoCh: processInfoCh,

		tracer: ebpftracer.NewTracer(hostNetNs, selfNetNs, *flags.DisableL7Tracing),

		trafficStatsUpdateCh: make(chan *TrafficStatsUpdate),

		sseBatcher: tracing.NewSSEventBatcher(tracing.SSEBatchLimit, tracing.SSEBatchTimeout, chClient),
	}
	if err = reg.Register(r); err != nil {
		return nil, err
	}

	// 启动 eBPF 事件消费者。
	go r.handleEvents(r.events)
	// 启动 eBPF 事件生产者。
	if err = r.tracer.Run(r.events); err != nil {
		close(r.events)
		return nil, err
	}

	return r, nil
}

func (r *Registry) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.Ip2Fqdn
}

func (r *Registry) Collect(ch chan<- prometheus.Metric) {
	r.ip2fqdnLock.RLock()
	defer r.ip2fqdnLock.RUnlock()
	for ip, fqdn := range r.ip2fqdn {
		ch <- gauge(metrics.Ip2Fqdn, 1, ip.String(), fqdn)
	}
}

func (r *Registry) Close() {
	r.tracer.Close()
	close(r.events)
	r.sseBatcher.Close()
}

func (r *Registry) handleEvents(ch <-chan ebpftracer.Event) {
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()
	for {
		select {
		// 处理 agent 定时 GC 事件。
		case now := <-gcTicker.C:
			for pid, c := range r.containersByPid {
				cg, err := proc.ReadCgroup(pid)
				if err != nil {
					delete(r.containersByPid, pid)
					if c != nil {
						c.onProcessExit(pid, false)
					}
					continue
				}
				if c != nil && cg.Id != c.cgroup.Id {
					delete(r.containersByPid, pid)
					c.onProcessExit(pid, false)
				}
			}
			activeIPs := map[netaddr.IP]struct{}{}
			for id, c := range r.containersById {
				for dst := range c.lastConnectionAttempts {
					activeIPs[dst.IP()] = struct{}{}
				}
				if !c.Dead(now) {
					continue
				}
				klog.Infoln("deleting dead container:", id)
				for cg, cc := range r.containersByCgroupId {
					if cc == c {
						delete(r.containersByCgroupId, cg)
					}
				}
				for pid, cc := range r.containersByPid {
					if cc == c {
						delete(r.containersByPid, pid)
					}
				}
				if ok := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Unregister(c); !ok {
					klog.Warningln("failed to unregister container:", id)
				}
				delete(r.containersById, id)
				c.Close()
			}
			r.ip2fqdnLock.Lock()
			for ip := range r.ip2fqdn {
				if _, ok := activeIPs[ip]; !ok {
					delete(r.ip2fqdn, ip)
				}
			}
			r.ip2fqdnLock.Unlock()
		// 处理 StatsUpdate 事件。
		case u := <-r.trafficStatsUpdateCh:
			if u == nil {
				continue
			}
			if c := r.containersByPid[u.Pid]; c != nil {
				c.updateTrafficStats(u)
			}
		// 处理 eBPF 事件。
		case e, more := <-ch:
			if !more {
				return
			}
			switch e.Type {
			case ebpftracer.EventTypeProcessStart:
				c, seen := r.containersByPid[e.Pid]
				switch { // possible pids wraparound + missed `process-exit` event
				case c == nil && seen: // ignored
					delete(r.containersByPid, e.Pid)
				case c != nil: // revalidating by cgroup
					cg, err := proc.ReadCgroup(e.Pid)
					if err != nil || cg.Id != c.cgroup.Id {
						delete(r.containersByPid, e.Pid)
						c.onProcessExit(e.Pid, false)
					}
				}
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					p := c.onProcessStart(e.Pid)
					if r.processInfoCh != nil && p != nil {
						r.processInfoCh <- ProcessInfo{Pid: p.Pid, ContainerId: c.id, StartedAt: p.StartedAt}
					}
				}
			case ebpftracer.EventTypeProcessExit:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onProcessExit(e.Pid, e.Reason == ebpftracer.EventReasonOOMKill)
				}
				delete(r.containersByPid, e.Pid)

			case ebpftracer.EventTypeFileOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onFileOpen(e.Pid, e.Fd, e.Mnt, e.Log)
				}

			case ebpftracer.EventTypeListenOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onListenOpen(e.Pid, e.SrcAddr, false)
				} else {
					if !c.addrBelongsToWorld(e.DstAddr) {
						klog.Infoln("TCP listen open from unknown container", e)
					}
				}
			case ebpftracer.EventTypeListenClose:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onListenClose(e.Pid, e.SrcAddr)
				}

			case ebpftracer.EventTypeConnectionOpen:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					// 针对 ConnectionOpen 事件，e.Timestamp 目前保留的是建立连接的时间。
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.ActualDstAddr, e.Timestamp, false, e.Duration)
					c.attachTlsUprobes(r.tracer, e.Pid)
				} else {
					if !c.addrBelongsToWorld(e.DstAddr) {
						klog.Infoln("TCP connection from unknown container", e)
					}
				}
			case ebpftracer.EventTypeConnectionError:
				if c := r.getOrCreateContainer(e.Pid); c != nil {
					c.onConnectionOpen(e.Pid, e.Fd, e.SrcAddr, e.DstAddr, e.ActualDstAddr, 0, true, e.Duration)
				} else {
					if !c.addrBelongsToWorld(e.DstAddr) {
						klog.Infoln("TCP connection error from unknown container", e)
					}
				}
			case ebpftracer.EventTypeConnectionClose:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.onConnectionClose(e)
				}
			case ebpftracer.EventTypeTCPRetransmit:
				for _, c := range r.containersById {
					if c.onRetransmission(e.SrcAddr, e.DstAddr) {
						break
					}
				}
			case ebpftracer.EventTypeL7Request:
				if e.L7Request == nil {
					continue
				}
				if c := r.containersByPid[e.Pid]; c != nil {
					// 针对 L7Request 事件，e.Timestamp 是建立连接的时间，e.KernelTimestamp 是boot以来的时间。
					ip2fqdn := c.onL7Request(e.Pid, e.Fd, e.Timestamp, e.L7Request, &e)
					// 针对 onDNSRequest ，会更新 r.ip2fqdn 缓存。
					r.ip2fqdnLock.Lock()
					for ip, fqdn := range ip2fqdn {
						r.ip2fqdn[ip] = fqdn
					}
					r.ip2fqdnLock.Unlock()
				}
			case ebpftracer.EventTypeL7Response:
				if c := r.containersByPid[e.Pid]; c != nil {
					// 针对 L7Response 事件，e.Timestamp 是建立连接的时间，e.KernelTimestamp 是boot以来的时间。
					sseStartTime := getRealTime(e.KernelTimestamp)
					// c.id 基本无用。无法用 IPPort 标识事件，因为 connectionsByPidFd 中的 PidFd 是 client-side 的，而 e.Pid 是 server-side 的。
					r.sseBatcher.Add(sseStartTime, e.Duration, string(c.id), e.TgidReqSs, e.TgidRespSs)
				}
			case ebpftracer.EventTypePythonThreadLock:
				if c := r.containersByPid[e.Pid]; c != nil {
					c.pythonThreadLockWaitTime += e.Duration
				}
			}
		}
	}
}

func (r *Registry) getOrCreateContainer(pid uint32) *Container {
	if c, seen := r.containersByPid[pid]; c != nil {
		return c
	} else if seen { // ignored
		return nil
	}
	cg, err := proc.ReadCgroup(pid)
	if err != nil {
		if !common.IsNotExist(err) {
			klog.Warningln("failed to read proc cgroup:", err)
		}
		return nil
	}
	if c := r.containersByCgroupId[cg.Id]; c != nil {
		r.containersByPid[pid] = c
		return c
	}
	if cg.ContainerType == cgroup.ContainerTypeSandbox {
		cmdline := proc.GetCmdline(pid)
		parts := bytes.Split(cmdline, []byte{0})
		if len(parts) > 0 {
			cmd := parts[0]
			lastArg := parts[len(parts)-1]
			if (bytes.HasSuffix(cmd, []byte("runsc-sandbox")) || bytes.HasSuffix(cmd, []byte("runsc"))) && containerIdRegexp.Match(lastArg) {
				cg.ContainerId = string(lastArg)
			}
		}
	}
	md, err := getContainerMetadata(cg)
	if err != nil {
		klog.Warningf("failed to get container metadata for pid %d -> %s: %s", pid, cg.Id, err)
		return nil
	}
	id := calcId(cg, md)
	klog.Infof("calculated container id %d -> %s -> %s", pid, cg.Id, id)
	if id == "" {
		if cg.Id == "/init.scope" && pid != 1 {
			klog.InfoS("ignoring without persisting", "cg", cg.Id, "pid", pid)
		} else {
			klog.InfoS("ignoring", "cg", cg.Id, "pid", pid)
			r.containersByPid[pid] = nil
		}
		return nil
	}
	if c := r.containersById[id]; c != nil {
		klog.Warningln("id conflict:", id)
		if cg.CreatedAt().After(c.cgroup.CreatedAt()) {
			c.cgroup = cg
			c.metadata = md
			c.runLogParser("")
		}
		r.containersByPid[pid] = c
		r.containersByCgroupId[cg.Id] = c
		return c
	}
	c, err := NewContainer(id, cg, md, pid, r)
	if err != nil {
		klog.Warningf("failed to create container pid=%d cg=%s id=%s: %s", pid, cg.Id, id, err)
		return nil
	}

	klog.InfoS("detected a new container", "pid", pid, "cg", cg.Id, "id", id)
	if err := prometheus.WrapRegistererWith(prometheus.Labels{"container_id": string(id)}, r.reg).Register(c); err != nil {
		klog.Warningln("failed to register container:", err)
		return nil
	}
	r.containersByPid[pid] = c
	r.containersByCgroupId[cg.Id] = c
	r.containersById[id] = c
	return c
}

func (r *Registry) updateTrafficStatsIfNecessary() {
	r.trafficStatsLock.Lock()
	defer r.trafficStatsLock.Unlock()

	if time.Now().Sub(r.trafficStatsLastUpdated) < MinTrafficStatsUpdateInterval {
		return
	}
	iter := r.tracer.ActiveConnectionsIterator()
	cid := ebpftracer.ConnectionId{}
	stats := ebpftracer.Connection{}
	for iter.Next(&cid, &stats) {
		r.trafficStatsUpdateCh <- &TrafficStatsUpdate{
			Pid:           cid.PID,
			FD:            cid.FD,
			BytesSent:     stats.BytesSent,
			BytesReceived: stats.BytesReceived,
		}
	}
	if err := iter.Err(); err != nil {
		klog.Warningln(err)
	}
	r.trafficStatsUpdateCh <- nil
	r.trafficStatsLastUpdated = time.Now()
}

func (r *Registry) getFQDN(ip netaddr.IP) string {
	r.ip2fqdnLock.RLock()
	defer r.ip2fqdnLock.RUnlock()
	return r.ip2fqdn[ip]
}

func calcId(cg *cgroup.Cgroup, md *ContainerMetadata) ContainerID {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		if strings.HasPrefix(cg.ContainerId, "/system.slice/crio-conmon-") {
			return ""
		}
		return ContainerID(cg.ContainerId)
	case cgroup.ContainerTypeTalosRuntime:
		return ContainerID(cg.ContainerId)
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return ""
	}
	if cg.ContainerId == "" {
		return ""
	}
	if md.labels["io.kubernetes.pod.name"] != "" {
		pod := md.labels["io.kubernetes.pod.name"]
		namespace := md.labels["io.kubernetes.pod.namespace"]
		name := md.labels["io.kubernetes.container.name"]
		if cg.ContainerType == cgroup.ContainerTypeSandbox {
			name = "sandbox"
		}
		if name == "" || name == "POD" { // skip pause containers
			return ""
		}
		if g := cronjobPodName.FindStringSubmatch(pod); len(g) == 3 {
			now := time.Now()
			tsMiniutes, _ := strconv.ParseUint(g[2], 10, 64)
			scheduledAt := time.Unix(int64(tsMiniutes)*60, 0)
			if scheduledAt.After(now.Add(-cronjobPodScheduleWindow)) && scheduledAt.Before(now.Add(cronjobPodScheduleWindow)) {
				return ContainerID(fmt.Sprintf("/k8s-cronjob/%s/%s/%s", namespace, g[1], name))
			}
		}
		return ContainerID(fmt.Sprintf("/k8s/%s/%s/%s", namespace, pod, name))
	}
	if taskNameParts := strings.SplitN(md.labels["com.docker.swarm.task.name"], ".", 3); len(taskNameParts) == 3 {
		namespace := md.labels["com.docker.stack.namespace"]
		service := md.labels["com.docker.swarm.service.name"]
		if namespace != "" {
			service = strings.TrimPrefix(service, namespace+"_")
		}
		if namespace == "" {
			namespace = "_"
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", namespace, service, taskNameParts[1]))
	}
	if md.env != nil {
		allocId := md.env["NOMAD_ALLOC_ID"]
		group := md.env["NOMAD_GROUP_NAME"]
		job := md.env["NOMAD_JOB_NAME"]
		namespace := md.env["NOMAD_NAMESPACE"]
		task := md.env["NOMAD_TASK_NAME"]
		if allocId != "" && group != "" && job != "" && namespace != "" && task != "" {
			return ContainerID(fmt.Sprintf("/nomad/%s/%s/%s/%s/%s", namespace, job, group, allocId, task))
		}
	}
	if md.name == "" { // should be "pure" dockerd container here
		klog.Warningln("empty dockerd container name for:", cg.ContainerId)
		return ""
	}
	return ContainerID("/docker/" + md.name)
}

func getContainerMetadata(cg *cgroup.Cgroup) (*ContainerMetadata, error) {
	switch cg.ContainerType {
	case cgroup.ContainerTypeSystemdService:
		md := &ContainerMetadata{}
		md.systemdTriggeredBy = SystemdTriggeredBy(cg.ContainerId)
		return md, nil
	case cgroup.ContainerTypeDocker, cgroup.ContainerTypeContainerd, cgroup.ContainerTypeSandbox, cgroup.ContainerTypeCrio:
	default:
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerId == "" {
		return &ContainerMetadata{}, nil
	}
	if cg.ContainerType == cgroup.ContainerTypeCrio {
		return CrioInspect(cg.ContainerId)
	}
	var dockerdErr error
	if dockerdClient != nil {
		md, err := DockerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		dockerdErr = err
	}
	var containerdErr error
	if containerdClient != nil {
		md, err := ContainerdInspect(cg.ContainerId)
		if err == nil {
			return md, nil
		}
		containerdErr = err
	}
	return nil, fmt.Errorf("failed to interact with dockerd (%s) or with containerd (%s)", dockerdErr, containerdErr)
}

type TrafficStatsUpdate struct {
	Pid           uint32
	FD            uint64
	BytesSent     uint64
	BytesReceived uint64
}
