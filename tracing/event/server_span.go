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
	go func() {
		err := emitter.startServerSpanService(context.Background())
		if err != nil {
			klog.Error(err)
		}
	}()

	return &emitter
}

func (e *Emitter) AddServerSpan(sse *eventv1.ServerSpan) {
	e.serverSpans <- sse
}

func (e *Emitter) EndServerSpan() {
	close(e.serverSpans)
}

func (e *Emitter) startServerSpanService(ctx context.Context) error {
	client := xcorootv1.NewServerSpanServiceClient(e.conn)
	// todo insert grpc.Header(common.AuthHeaders())
	stream, err := client.Upload(ctx)
	if err != nil {
		return err
	}

	for sse := range e.serverSpans {
		err = stream.Send(&xcorootv1.ServerSpanServiceUploadRequest{Span: sse})
		// end of downstream
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	} // end of upstream

	_, err = stream.CloseAndRecv()
	return err
}
