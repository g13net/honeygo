package service

import (
	"context"
	"honeygo/internal/isolation"
	"io"
)

type Service interface {
	Start(ctx context.Context) error
	Stop() error
	Status() string
	Port() int
	Protocol() string
	SetLogger(w io.Writer)
	EnableIsolation(engine *isolation.Engine)
	IsIsolated() bool
	SetTTL(seconds int)
	GetTTL() int
}
