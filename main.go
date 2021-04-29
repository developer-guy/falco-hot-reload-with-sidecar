package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"path/filepath"
	"github.com/fsnotify/fsnotify"
	ps "github.com/mitchellh/go-ps"
)

func main(){
    rootDir := os.Getenv("FALCO_ROOTDIR")

    watcher, err := fsnotify.NewWatcher()  
    if err != nil {
        log.Fatalf("could not create watcher:%v\n", err)
    }
    defer watcher.Close()

    go func() {
        for {
		select {
		case event, ok  := <-watcher.Events:
            if !ok {
              return
            }
			// k8s configmaps uses symlinks, we need this workaround.
            // original configmap file is removed
			if event.Op == fsnotify.Remove {
                // remove the watcher since the file is removed
				watcher.Remove(event.Name)
                // add a new watcher pointing to the new symlink/file
				watcher.Add(event.Name)
			    
                log.Printf("event:%v\n", event)
                
                falcoPID, err := findPidOfFalcoProcess()
                if err != nil {
                  log.Fatalf("could not found pid of falco process:%v\n", err)
                }

                reloadProcess(falcoPID, syscall.SIGHUP)
            }
			// also allow normal files to be modified and reloaded.
			if event.Op == fsnotify.Write {
                log.Printf("event:%v\n", event)
                falcoPID, err := findPidOfFalcoProcess()
                if err != nil {
                  log.Fatalf("could not found pid of falco process:%v\n", err)
                }

                reloadProcess(falcoPID, syscall.SIGHUP)
            }
		case err, ok := <-watcher.Errors:
            if !ok {
                return
            }
            
            log.Fatalf("error:%v\n", err)
		}
	}
}()
    
    // starting at the root of the project, walk each file/directory searching for
	// directories
	if err := filepath.Walk(rootDir,func(path string, info os.FileInfo, err error) error {
        // since fsnotify can watch all the files in a directory, watchers only need
	    // to be added to each nested directory
	    if !info.Mode().IsDir() {
          log.Printf("starting to watch %s\n", path)
		  return watcher.Add(path)
	    }

        return nil
      },
    ); err != nil {
	    log.Fatalf("could not walk directory %s:%v\n",rootDir, err)
    }
    <- make(chan struct{})
}

func reloadProcess(pid int, signal syscall.Signal){
                
     log.Printf("SIGHUP signal sending to PID %d\n",pid)
     
     err := syscall.Kill(pid, signal)
     if err != nil {
       log.Fatalf("could not send SIGHUP signal:%v\n", err)
     }
     
     log.Printf("SIGHUP signal send to PID %d\n", pid)
}

func findPidOfFalcoProcess() (int, error) {
    processes, err := ps.Processes()

    if err != nil {
        return -1, err
    }

    var pid int
    for _ , p := range processes {
            if p.Executable() == "falco" {
                log.Printf("executable %s found with pid %d\n", p.Executable(), p.Pid())
                pid = p.Pid() 
            }
    }

    return pid, nil
}

