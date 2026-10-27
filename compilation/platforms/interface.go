package platforms

import (
	"context"

	"github.com/crytic/medusa/compilation/types"
)

// PlatformConfig describes the interface all compilation platform configs must implement.
type PlatformConfig interface {
	Compile() ([]types.Compilation, string, error)
	Platform() string
	GetTarget() string
	SetTarget(string)
}

// ContextPlatformConfig adds cancellation without changing the legacy platform interface.
type ContextPlatformConfig interface {
	PlatformConfig
	CompileContext(context.Context) ([]types.Compilation, string, error)
}
