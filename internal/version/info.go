package version

// Version is the build version string. Release builds override it with ldflags:
//
//	go build -ldflags "-X github.com/sufield/stave/internal/version.Version=0.0.3"
var Version = "dev"
