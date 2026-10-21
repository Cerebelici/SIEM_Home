package main

import (
	"context"
	"embed"
	"log"
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

func main() {
	cfg := config.Load()
	if cfg.DBPath == "cerberus.db" {
		cfg.DBPath = config.OSDataDir("cerberus", "cerberus.db")
	}
	// Desktop runs in pure IPC mode without starting the HTTP server
	cfg.DisableHTTPServer = true

	d := app.New(cfg)
	b := NewBridge(d)

	err := wails.Run(&options.App{
		Title:  "Cerberus Sentinel",
		Width:  1280,
		Height: 820,
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
			b.SetContext(ctx)
			if err := d.Start(context.Background()); err != nil {
				runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
					Type:    runtime.ErrorDialog,
					Title:   "Cerberus Failed to Start",
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
