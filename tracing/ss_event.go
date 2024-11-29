// Uploads server-side events (response related events)

package tracing

import (
	"context"
	"github.com/coroot/coroot-node-agent/common"
	"k8s.io/klog/v2"
	"strconv"
	"sync"
	"time"

	"github.com/ClickHouse/ch-go"
	chproto "github.com/ClickHouse/ch-go/proto"
)

const (
	SSEBatchLimit   = 100 // l7_event_ss processing batch size
	SSEBatchTimeout = 5 * time.Second
)

type SSEventBatcher struct {
	limit  int
	client *ch.Client

	addLock sync.Mutex
	done    chan struct{}

	Timestamp   *chproto.ColDateTime64
	Duration    *chproto.ColUInt64
	ContainerID *chproto.ColStr
	TgidRead    *chproto.ColStr
	TgidWrite   *chproto.ColStr
	StatementID *chproto.ColUInt32
}

func NewSSEventBatcher(limit int, timeout time.Duration, client *ch.Client) *SSEventBatcher {
	b := &SSEventBatcher{
		limit:  limit,
		client: client,

		done: make(chan struct{}),

		Timestamp:   new(chproto.ColDateTime64).WithPrecision(chproto.PrecisionNano),
		Duration:    new(chproto.ColUInt64),
		ContainerID: new(chproto.ColStr),
		TgidRead:    new(chproto.ColStr),
		TgidWrite:   new(chproto.ColStr),
		StatementID: new(chproto.ColUInt32),
	}

	go func() {
		ticker := time.NewTicker(timeout)
		defer ticker.Stop()
		for {
			select {
			case <-b.done:
				return
			case <-ticker.C:
				b.addLock.Lock()
				b.save()
				b.addLock.Unlock()
			}
		}
	}()

	return b
}

func (b *SSEventBatcher) Add(startTime time.Time, duration time.Duration, containerID string, TgidReqSs, TgidRespSs uint64) {
	b.addLock.Lock()
	defer b.addLock.Unlock()

	b.Timestamp.Append(startTime)
	b.Duration.Append(uint64(duration))
	b.TgidRead.Append(strconv.FormatUint(TgidReqSs, 10))
	b.TgidWrite.Append(strconv.FormatUint(TgidRespSs, 10))
	b.ContainerID.Append(containerID) // fixme Pid 以及 ContainerId 似乎来自 span client-side。
	b.StatementID.Append(0)           // todo 支持 x-request-id 之类的 RequestId。

	if b.Timestamp.Rows() < b.limit {
		return
	}
	b.save()
}

func (b *SSEventBatcher) Close() {
	b.done <- struct{}{}
	b.addLock.Lock()
	b.save()
	b.addLock.Unlock()
}

func (b *SSEventBatcher) save() {
	if b.Timestamp.Rows() == 0 {
		return
	}

	input := chproto.Input{
		{Name: "Timestamp", Data: b.Timestamp},
		{Name: "Duration", Data: b.Duration},
		{Name: "ContainerId", Data: b.ContainerID},
		{Name: "TgidRead", Data: b.TgidRead},
		{Name: "TgidWrite", Data: b.TgidWrite},
		{Name: "StatementId", Data: b.StatementID},
	}
	query := ch.Query{Body: input.Into("l7_events_ss"), Input: input}

	if b.client == nil || b.client.IsClosed() {
		var err error
		b.client, err = common.NewChClient()
		if err != nil {
			klog.Errorln(err)
			return
		}
	}

	// save and reset
	err := b.client.Do(context.Background(), query)
	if err != nil {
		klog.Errorln(err)
	}
	for _, i := range input {
		i.Data.(chproto.Resettable).Reset()
	}
}
