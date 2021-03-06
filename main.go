package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
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
				if file, same := sameHashes(hashes, newHashes); !same {
					log.Printf("a config file %s has changed, falco will be reloaded\n", file)
					if pid := findFalcoPID(); pid > 0 {
						var valid bool
						for i := range newHashes {
							if err := validateRule(i); err != nil {
								log.Printf("wrong syntax for rule file %s\n", i)
								valid = false
								break
							}
							valid = true
						}
						if valid {
							if err := reloadProcess(pid); err != nil {
								log.Printf("failed to reload falco\n")
								continue
							}
						} else {
							log.Println("could not reload the Falco process, rule files are not valid")
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

func sameHashes(previous, current map[string]string) (string, bool) {
	for i := range current {
		if previous[i] != current[i] {
			return i, false
		}
	}
	return "", true
}

func getFileHashes(folder string) map[string]string {
	h := make(map[string]string)

	md5hasher := md5.New()

	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if !info.Mode().IsDir() && !(strings.Contains(info.Name()+filepath.Ext(path), "falco.yaml")) && !(strings.HasPrefix(path, folder+"/"+"..")) && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {

			file, err := os.Open(path)
			if err != nil {
				log.Printf("can't open file %s\n", path)
			}

			defer file.Close()

			_, err = io.Copy(md5hasher, file)

			if err != nil {
				log.Printf("error with file %s to get its hash\n", path)
			}

			sum := md5hasher.Sum(nil)

			h[path] = fmt.Sprintf("%x", sum)
		}
		return nil
	})

	if err != nil {
		log.Println("error to get hashes")
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

func validateRule(ruleFile string) error {
	cmd := exec.Command("/usr/bin/falco", "--validate", ruleFile)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
