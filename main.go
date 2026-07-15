package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed index.html
var indexHTML []byte

var (
	dir  = flag.String("dir", "./files", "folder to store files")
	port = flag.String("port", "47747", "port to listen on")
	pass = flag.String("pass", "", "password for basic auth (empty = auth disabled)")
	user = flag.String("user", "drop", "username for basic auth")
)

type FileInfo struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Mod  time.Time `json:"mod"`
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("cannot create %s: %v", *dir, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET /api/info", infoHandler)
	mux.HandleFunc("GET /api/files", filesHandler)
	mux.HandleFunc("POST /api/upload", uploadHandler)
	mux.HandleFunc("GET /files/{name}", downloadHandler)

	var handler http.Handler = mux
	if *pass != "" {
		handler = withAuth(mux)
	}

	log.Printf("serving %s on %s", *dir, serverAddr())
	log.Fatal(http.ListenAndServe(":"+*port, handler))
}

// lanIP returns this machine's IPv4 address on the local network.
func lanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	fallback := ""
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil {
			continue
		}
		if ip.IsPrivate() {
			return ip.String()
		}
		if fallback == "" {
			fallback = ip.String()
		}
	}
	return fallback
}

func serverAddr() string {
	host := lanIP()
	if host == "" {
		host = "localhost"
	}
	return "http://" + host + ":" + *port
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"addr": serverAddr()})
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(*dir)
	if err != nil {
		http.Error(w, "cannot read dir", http.StatusInternalServerError)
		return
	}

	files := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name: e.Name(),
			Size: info.Size(),
			Mod:  info.ModTime(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	src, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	defer src.Close()

	name := filepath.Base(hdr.Filename)
	if name == "" || name == "." || name == ".." || name == "/" {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return
	}

	dst, err := os.Create(filepath.Join(*dir, uniqueName(name)))
	if err != nil {
		http.Error(w, "cannot create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(dst.Name())
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// uniqueName returns name, or "name (N).ext" if a file with that name
// already exists in dir — uploads never overwrite existing files.
func uniqueName(name string) string {
	if _, err := os.Stat(filepath.Join(*dir, name)); os.IsNotExist(err) {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(filepath.Join(*dir, candidate)); os.IsNotExist(err) {
			return candidate
		}
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name != filepath.Base(name) || name == "." || name == ".." {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, filepath.Join(*dir, name))
}

func withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(*user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(*pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="netdrop"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
