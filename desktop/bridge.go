package main

import (
	"context"
	"fmt"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/model"
)

// Bridge connects the frontend UI to the Cerberus backend Daemon.
type Bridge struct {
	d   *app.Daemon
	ctx context.Context
}

// NewBridge creates a new Bridge instance.
func NewBridge(d *app.Daemon) *Bridge {
	return &Bridge{d: d}
}

// Status returns the current live sentinel status for the UI.
func (b *Bridge) Status() model.SystemStatus {
	return b.d.Status()
}

// APIBaseURL returns the HTTP URL of the local REST API.
func (b *Bridge) APIBaseURL() string {
	return fmt.Sprintf("http://%s", b.d.ServerAddr())
}
