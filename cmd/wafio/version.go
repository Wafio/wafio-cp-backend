package main

// Version is injected at build time via -ldflags "-X main.Version=vX.Y.Z".
// Defaults to "dev" for local builds.
var Version = "dev"
