package pack

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		return
	}
	os.Exit(m.Run())
}
