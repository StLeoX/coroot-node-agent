package tracing

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/klog/v2"
)

const (
	MemcacheDBItemKeyName attribute.Key = "dt.memcached.item"
)

var (
	batcher             sdktrace.TracerProviderOption
	commonResourceAttrs []attribute.KeyValue
	agentVersion        string
	initialized         bool
)

func Init(machineId, hostname, version string) {
	endpointUrl := *flags.TracesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointUrl.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(common.AuthHeaders()),
		otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify}),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}

	batcher = sdktrace.WithBatcher(exporter)
	commonResourceAttrs = []attribute.KeyValue{semconv.HostName(hostname), semconv.HostID(machineId)}
	agentVersion = version
	initialized = true
}

type Tracer struct {
	otel trace.Tracer
}

func GetContainerTracer(containerId string) *Tracer {
	if !initialized {
		return &Tracer{otel: nil}
	}
	provider := sdktrace.NewTracerProvider(
		batcher,
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			append(
				commonResourceAttrs,
				semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
				semconv.ContainerID(containerId),
			)...,
		)),
	)
	return &Tracer{otel: provider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(agentVersion))}
}

// NewTrace creates a new Trace, actually it's a single span.
func (t *Tracer) NewTrace(source, destination common.HostPort, startTime time.Time, raw *ebpftracer.Event) *Trace {
	return &Trace{tracer: t,
		destination: destination,
		startTime:   startTime,
		commonAttrs: []attribute.KeyValue{
			semconv.NetHostName(source.Host()),
			semconv.NetHostPort(int(source.Port())),
			semconv.NetPeerName(destination.Host()),
			semconv.NetPeerPort(int(destination.Port())),
			attribute.String("tgid_req_cs", strconv.FormatUint(raw.TgidReqCs, 10)),
			attribute.String("tgid_resp_cs", strconv.FormatUint(raw.TgidRespCs, 10)),
		}}
}

// Trace manages Span's resource attributes. Others manage Span's span attributes.
type Trace struct {
	tracer      *Tracer
	destination common.HostPort
	startTime   time.Time
	commonAttrs []attribute.KeyValue
}

func (t *Trace) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	if t.tracer.otel == nil {
		klog.Warning("Tracer unavailable.")
		return
	}
	startTime := t.startTime
	endTime := startTime.Add(duration)
	_, span := t.tracer.otel.Start(context.Background(), name, trace.WithTimestamp(startTime), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End(trace.WithTimestamp(endTime))
}

func (t *Trace) HttpRequest(method, uri, path string, status l7.Status, duration time.Duration) {
	if t == nil || method == "" {
		return
	}
	t.createSpan(fmt.Sprintf("%s %s", method, path),
		duration,
		status >= 400,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", t.destination.String(), uri)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *Trace) Http2Request(method, path, scheme string, status l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if method == "" {
		method = "unknown"
	}
	if path == "" {
		path = "/unknown"
	}
	if scheme == "" {
		scheme = "unknown"
	}
	t.createSpan(fmt.Sprintf("%s %s", method, path),
		duration,
		status >= 400,
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		// todo 轻解析 SQL 知道 CRUD 操作类型。
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		// todo 轻解析 SQL 知道 CRUD 操作类型。
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMongoDB,
		// todo 轻解析 SQL 知道 CRUD 操作类型。
		semconv.DBStatement(query),
	)
}

func (t *Trace) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemMemcached,
		semconv.DBOperation(cmd),
	}
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	t.createSpan(cmd, duration, error, attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error,
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}
