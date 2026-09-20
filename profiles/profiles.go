package profiles

import "embed"

// FS embeds all default web profile files into the compiled binary
//
//go:embed *.txt
var FS embed.FS
