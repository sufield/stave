package version

// String is the build version. Release builds override it with ldflags:
//
//	go build -ldflags "-X github.com/sufield/stave/internal/version.String=0.0.3"
var String = "dev"
