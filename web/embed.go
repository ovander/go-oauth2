package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed templates/*.html
var Templates embed.FS

//go:embed static/*
var staticFS embed.FS

// StaticFileServer returns an http.Handler for serving static files
func StaticFileServer() http.Handler {
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("failed to get static fs: " + err.Error())
	}
	return http.FileServer(http.FS(staticContent))
}
