package main

import (
	"context"
	"embed"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func xdgDataPath(app, file string) string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			base = filepath.Join(home, ".local", "share")
		} else {
			base = "."
		}
	}
	dir := filepath.Join(base, app)
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, file)
}

func main() {
	cfg := config.Load()
	if cfg.DBPath == "cerberus.db" {
		cfg.DBPath = xdgDataPath("cerberus", "cerberus.db")
	}
	d := app.New(cfg)
	b := &Bridge{d: d}
	err := wails.Run(&options.App{
		Title:  "Cerberus Sentinel",
		Width:  1280,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "io.github.gr0gu.cerberus",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				if b.ctx != nil {
					runtime.WindowShow(b.ctx)
				}
			},
		},
		OnStartup: func(ctx context.Context) {
			b.ctx = ctx
			if err := d.Start(context.Background()); err != nil {
				runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
					Type:    runtime.ErrorDialog,
					Title:   "Cerberus failed to start",
					Message: err.Error(),
				})
				runtime.Quit(ctx)
				return
			}
			go func() {
				for err := range d.Errors() {
					runtime.EventsEmit(ctx, "daemon:error", err.Error())
				}
			}()
		},
		OnShutdown: func(context.Context) {
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = d.Stop(sctx)
		},
		Bind: []interface{}{b},
	})
	if err != nil {
		log.Fatal(err)
	}
}
