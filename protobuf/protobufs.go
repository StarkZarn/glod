package protobufs

import (
	"embed"
)

var (

	// FS - Embedded FS access to proto files
	//go:embed commonpb/* glodpb/* dnspb/*
	FS embed.FS
)
