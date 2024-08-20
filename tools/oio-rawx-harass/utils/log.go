package utils

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

func Log(ctx context.Context) *log.Entry {
	return LogT(ctx, time.Now())
}

func LogT(ctx context.Context, t time.Time) *log.Entry {
	return log.WithContext(ctx).WithTime(t).WithField("t", t.Unix())
}
