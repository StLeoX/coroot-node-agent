package event

import (
	"context"
	"io"

	eventv1 "github.com/StLeoX/coroot-extend-api/api/proto/coroot/event/v1"
	xcorootv1 "github.com/StLeoX/coroot-extend-api/api/proto/coroot/service/v1"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"
)

type Emitter struct {
	conn *grpc.ClientConn

	serverSpans chan *eventv1.ServerSpan
	// other events
}

func NewEmitter(conn *grpc.ClientConn) *Emitter {
	emitter := Emitter{
		conn:        conn,
		serverSpans: make(chan *eventv1.ServerSpan, 1000),
	}

	// start services
	go emitter.startServerSpanService(context.Background())

	return &emitter
}

func (e *Emitter) AddServerSpan(sse *eventv1.ServerSpan) {
	e.serverSpans <- sse
}

func (e *Emitter) startServerSpanService(ctx context.Context) {
	client := xcorootv1.NewServerSpanServiceClient(e.conn)
	// todo insert grpc.Header(common.AuthHeaders())
	stream, err := client.Upload(ctx)
	if err != nil {
		klog.Error(err)
		return
	}

	for {
		sse, closed := <-e.serverSpans
		// upstream closed
		if closed {
			break
		}
		err = stream.Send(&xcorootv1.ServerSpanServiceUploadRequest{Span: sse})
		if err != nil {
			klog.Error(err)
			return
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		if err != io.EOF {
			klog.Error(err)
		}
	}
}
