package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Templates holds parsed HTML templates
var Templates *template.Template

func init() {
	var err error
	Templates, err = template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		panic("failed to parse templates: " + err.Error())
	}
}

// StaticFileServer returns an http.Handler for serving static files
func StaticFileServer() http.Handler {
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("failed to get static fs: " + err.Error())
	}
	return http.FileServer(http.FS(staticContent))
}
