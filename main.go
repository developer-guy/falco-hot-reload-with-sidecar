package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mitchellh/go-ps"
)

var hashes map[string]string
var folder string

const (
	interval = 10
)

func init() {
	folder = os.Getenv("FALCO_ROOTDIR")
	hashes = getFileHashes(folder)
}

func main() {
	ticker := time.NewTicker(interval * time.Second)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-ticker.C:
				newHashes := getFileHashes(folder)
				if !sameHashes(hashes, newHashes) {
					if pid := findFalcoPID(); pid > 0 {
						if err := reloadProcess(pid); err != nil {
							continue
						}
						hashes = newHashes
					}
				}
			case <-sigs:
				ticker.Stop()
				done <- true
				return
			}
		}
	}()
	<-done
}

func sameHashes(previous, new map[string]string) bool {
	for i := range new {
		if previous[i] != new[i] {
			return false
		}
	}
	return true
}

func getFileHashes(folder string) map[string]string {
	var files []string
	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if !info.Mode().IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	h := make(map[string]string, len(files))
	md5hasher := md5.New()
	for _, i := range files {
		file, err := os.Open(i)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		_, err = io.Copy(md5hasher, file)
		if err != nil {
			log.Fatal(err)
		}
		sum := md5hasher.Sum(nil)
		h[i] = fmt.Sprintf("%x", sum)
	}
	return h
}

func findFalcoPID() int {
	processes, err := ps.Processes()

	if err != nil {
		return -1
	}
	for _, p := range processes {
		if p.Executable() == "falco" {
			log.Printf("executable %s found with pid %d\n", p.Executable(), p.Pid())
			return p.Pid()
		}
	}
	log.Printf("no executable for falco has been found\n")
	return -1
}

func reloadProcess(pid int) error {
	log.Printf("SIGHUP signal sending to PID %d\n", pid)

	err := syscall.Kill(pid, syscall.SIGHUP)
	if err != nil {
		log.Printf("could not send SIGHUP signal:%v\n", err)
		return err
	}

	log.Printf("SIGHUP signal send to PID %d\n", pid)
	return nil
}
