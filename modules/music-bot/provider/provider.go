package provider

import "context"

// Track contains display metadata and an extractor-produced source URL, never a path.
type Track struct {
	ID           string
	Title        string
	SourceURL    string
	ThumbnailURL string
}

type Provider interface {
	Initialize(context.Context) error
	Resolve(context.Context, string) ([]Track, error)
}

type Limits struct {
	MaxResults       int
	MaxQueryBytes    int
	MaxOutputBytes   int64
	ToolTimeoutMS    int64
	ResolveTimeoutMS int64
}

const (
	FFmpeg  = "/opt/flexmodule/bin/ffmpeg"
	FFprobe = "/opt/flexmodule/bin/ffprobe"
	YTDLP   = "/opt/flexmodule/yt-dlp/yt-dlp"
	Deno    = "/opt/flexmodule/bin/deno"
)
