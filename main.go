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
					log.Printf("a config file has changed, falco will be reloaded\n")
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

func sameHashes(previous, current map[string]string) bool {
	for i := range current {
		if previous[i] != current[i] {
			return false
		}
	}
	return true
}

func getFileHashes(folder string) map[string]string {
    h := make(map[string]string)
	
    md5hasher := md5.New()
    
    err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if !info.Mode().IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
		    
            file, err := os.Open(path)
            
            if err != nil {
                log.Fatal(err)
            }
            
            defer file.Close()
            
            _, err = io.Copy(md5hasher, file)
      
            if err != nil {
                log.Fatal(err)
            }
            
            sum := md5hasher.Sum(nil)
            
            h[path] = fmt.Sprintf("%x", sum)
        }
         return nil
	})

	if err != nil {
		log.Fatal(err)
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
			log.Printf("found executable %s (pid: %d)\n", p.Executable(), p.Pid())
			return p.Pid()
		}
	}
	log.Printf("no executable for falco has been found\n")
	return -1
}

func reloadProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGHUP)
	if err != nil {
		log.Printf("could not send SIGHUP signal to falco: %v\n", err)
		return err
	}

	log.Printf("SIGHUP signal sent to falco (pid: %d)\n", pid)
	return nil
}
