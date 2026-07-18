// Package cnssowa embeds the web UI into the compiled binary so the
// application is fully self-contained: a single EXE runs anywhere
// without needing an external web/ directory next to it.
package cnssowa

import "embed"

//go:embed all:web
var WebFS embed.FS
