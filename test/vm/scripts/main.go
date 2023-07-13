package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sync/semaphore"
)

var (
	maxWorkers            = runtime.GOMAXPROCS(0)
	sem                   = semaphore.NewWeighted(int64(maxWorkers))
	ubuntuContainer2004   = "vm-ubuntu2004:latest"
	ubuntuContainer2204   = "vm-ubuntu2204:latest"
	ubuntuContainer2310   = "vm-ubuntu2310:latest"
	debianbusterContainer = "vm-debianbuster:latest"
)

func dockerRunCompileDriver(ctx context.Context, ver [2]string, headers string, dir string) {
	verNumeric, err := strconv.ParseInt(ver[1], 10, 32)
	compilerType := ver[0]
	if err != nil {
		panic(err)
	}
	fmt.Printf("Performing concurrent docker run for compiler %s and compiler version %d\n", compilerType, verNumeric)
	dockerImage := ubuntuContainer2004
	shArgs := []string{""}
	if compilerType == "clang" {
		if verNumeric >= 11 {
			dockerImage = ubuntuContainer2204
		}
		if verNumeric >= 15 {
			dockerImage = ubuntuContainer2310
		}
		shArgs = []string{"-c", fmt.Sprintf("docker run -v %s:/vm:z -v %s:/headers:z %s \"/bin/bash /vm/scripts/compile_drivers.sh /usr/bin/llc-%d /usr/bin/clang-%d /usr/bin/gcc-%d OFF ON\"", dir, headers, dockerImage, verNumeric, verNumeric, verNumeric)}
	} else if compilerType == "gcc" {
		dockerImage = debianbusterContainer
		if verNumeric >= 9 {
			dockerImage = ubuntuContainer2310
		}
		shArgs = []string{"-c", fmt.Sprintf("docker run -v %s:/vm:z -v %s:/headers:z %s \"/bin/bash /vm/scripts/compile_drivers.sh /usr/bin/llc-%d /usr/bin/clang-%d /usr/bin/gcc-%d ON OFF\"", dir, headers, dockerImage, verNumeric, verNumeric, verNumeric)}
	}
	fmt.Println("Using docker image:", dockerImage)
	fmt.Println("shArgs", shArgs)
	out, _ := exec.Command("sh", shArgs...).CombinedOutput()
	fmt.Println(string(out))
}

func semLaunchCompileDriver(compilerVersionsClang string, compilerVersionsGcc string, dirKernelHeadersSubDirs string, dir string) {

	clangs := []string{}
	gccs := []string{}
	if strings.Contains(compilerVersionsClang, ",") {
		clangs = strings.Split(compilerVersionsClang, ",")
	} else if _, err := strconv.Atoi(compilerVersionsClang); err == nil {
		clangs = append(gccs, compilerVersionsClang)
	}
	if strings.Contains(compilerVersionsGcc, ",") {
		gccs = strings.Split(compilerVersionsGcc, ",")
	} else if _, err := strconv.Atoi(compilerVersionsGcc); err == nil {
		gccs = append(gccs, compilerVersionsGcc)
	}

	searchArrayCompilerVersions := [][2]string{}

	for _, ver := range clangs {
		searchArrayCompilerVersions = append(searchArrayCompilerVersions, [2]string{"clang", ver})
	}
	for _, ver := range gccs {
		searchArrayCompilerVersions = append(searchArrayCompilerVersions, [2]string{"gcc", ver})
	}
	fmt.Println("Starting concurrent docker runs...")

	ctx := context.Background()

	for _, ver := range searchArrayCompilerVersions {

		if err := sem.Acquire(ctx, 1); err != nil {
			log.Printf("Failed to acquire semaphore: %v", err)
			panic(err)
		}

		go func(i [2]string) {
			defer sem.Release(1)
			dockerRunCompileDriver(ctx, i, dirKernelHeadersSubDirs, dir)
		}(ver)
	}

	if err := sem.Acquire(ctx, int64(maxWorkers)); err != nil {
		log.Printf("Failed to acquire semaphore: %v", err)
		panic(err)
	}
	fmt.Println("Done")

}

func main() {

	// This script is only relevant for `kmod` and `bpf`, not `modern_bpf`
	// This is not intended to become a Go module or interfere w/ system settings, hence run as ad-hoc script, see below:
	// GO111MODULE=off bash -c 'go get golang.org/x/sync/semaphore; go run scripts/main.go -compilerVersionsClang=7,12,14,16 -compilerVersionsGcc=8,9,11,13 -dirExtractedKernelHeaders=$(pwd)/build/headers_extracted/ -dir=$(pwd)'

	compilerVersionsClang := flag.String("compilerVersionsClang", "7,12,14,16", `comma separated list of compiler versions for /usr/bin/clang-<version>, fails gracefully if compiler does not exist`)
	compilerVersionsGcc := flag.String("compilerVersionsGcc", "8,9,11,13", `comma separated list of compiler versions for /usr/bin/gcc-<version>, fails gracefully if compiler does not exist`)
	dirExtractedKernelHeaders := flag.String("dirExtractedKernelHeaders", "build/headers_extracted/", `path to directory containing extracted kernel headers sub directories`)
	dir := flag.String("dir", "", `path to vm base directory`)
	flag.Parse()

	semLaunchCompileDriver(*compilerVersionsClang, *compilerVersionsGcc, *dirExtractedKernelHeaders, *dir)

}
