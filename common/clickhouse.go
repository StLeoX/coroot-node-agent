package common

import (
	"context"
	"github.com/ClickHouse/ch-go"
	"github.com/coroot/coroot-node-agent/flags"
	"time"
)

func NewChClient() (*ch.Client, error) {
	chOpts := ch.Options{
		Address:          flags.GetString(flags.ClickhouseEndpoint),
		User:             flags.GetString(flags.ClickhouseUser),
		Password:         flags.GetString(flags.ClickhousePassword),
		Compression:      ch.CompressionLZ4,
		ReadTimeout:      30 * time.Second,
		DialTimeout:      10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
	return ch.Dial(context.Background(), chOpts)
}
