package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Req struct {
	Act string `json:"act"`
	Pwd string `json:"pwd"`
	Q   string `json:"q,omitempty"`
}

type Res struct {
	Ok   bool        `json:"ok"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	if r.Method != "POST" {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "use POST"})
		return
	}
	
	var req Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "invalid json"})
		return
	}
	
	home, _ := os.UserHomeDir()
	vaultPath := filepath.Join(home, ".passlock.vault")
	
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		json.NewEncoder(w).Encode(Res{
			Ok:  false,
			Msg: "no vault found - create one with CLI first",
		})
		return
	}
	
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "cant read vault"})
		return
	}
	
	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "invalid vault format"})
		return
	}
	
	json.NewEncoder(w).Encode(Res{
		Ok:   true,
		Msg:  "vault found (decrypt via CLI for now)",
		Data: map[string]string{
			"salt":      parts[0],
			"encrypted": fmt.Sprintf("%d bytes", len(parts[1])),
			"note":      "use CLI for full functionality",
		},
	})
}

func banner() {
	fmt.Println("╔═══════════════════════════════════════╗")
	fmt.Println("║                                       ║")
	fmt.Println("║       PASSLOCK API SERVER             ║")
	fmt.Println("║       listening on :8080              ║")
	fmt.Println("║                                       ║")
	fmt.Println("╚═══════════════════════════════════════╝")
}

func main() {
	banner()
	
	http.HandleFunc("/api", handle)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	
	log.Println("→ server started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}