package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

func main() {
	rootDir := os.Getenv("FALCO_ROOTDIR")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("could not create watcher:%v\n", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, channelIsStillOpened := <-watcher.Events:
				if !channelIsStillOpened {
					return
				}
				// k8s configmaps uses symlinks, we need this workaround.
				// original configmap file is removed
				if event.Op == fsnotify.Remove || event.Op == fsnotify.Write {
					// remove the watcher since the file is removed
					watcher.Remove(event.Name)
					// add a new watcher pointing to the new symlink/file
					watcher.Add(event.Name)

					log.Printf("event:%v\n", event)

					if err := reloadProcess(findPidOfFalcoProcess(), syscall.SIGHUP); err != nil {
						log.Printf("could not reload falco: %v\n", err)
						return
					}
				}
			case err, channelIsStillOpened := <-watcher.Errors:
				if !channelIsStillOpened {
					return
				}
				log.Fatalf("error:%v\n", err)
			}
		}
	}()

	// starting at the root of the project, walk each file/directory searching for
	// directories
	if err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		// since fsnotify can watch all the files in a directory, watchers only need
		// to be added to each nested directory
		if !info.Mode().IsDir() {
			log.Printf("starting to watch %s\n", path)
			return watcher.Add(path)
		}

		return nil
	},
	); err != nil {
		log.Fatalf("could not walk directory %s:%v\n", rootDir, err)
	}
	<-make(chan struct{})
}

func reloadProcess(pid int, signal syscall.Signal) error {
	log.Printf("SIGHUP signal sending to PID %d\n", pid)

	err := syscall.Kill(pid, signal)
	if err != nil {
		log.Printf("could not send SIGHUP signal:%v\n", err)
		return err
	}

	log.Printf("SIGHUP signal send to PID %d\n", pid)
	return nil
}
