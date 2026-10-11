// Command gen writes the small synthetic image fixtures used by the image
// engine tests and the end-to-end demo: a `docker save`-style tarball and an
// OCI image layout directory, both describing a tiny Alpine-like root with
// an apk database, os-release, a lockfile and a whiteout. Run once and
// commit the output:
//
//	go run ./testdata/image/gen testdata/image
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/iamstoick/scnr/internal/engine/image/imagetest"
)

func main() {
	out := "testdata/image"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	tarPath := filepath.Join(out, "alpine-small.tar")
	b := imagetest.DockerArchive(imagetest.AlpineLayers(), "scnr-fixture/alpine-small:3.18")
	if err := os.WriteFile(tarPath, b, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", tarPath, len(b), "bytes")
	ociDir := filepath.Join(out, "oci-small")
	if err := imagetest.OCILayout(ociDir, imagetest.AlpineLayers()); err != nil {
		panic(err)
	}
	fmt.Println("wrote", ociDir)
}
