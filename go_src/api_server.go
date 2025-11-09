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
		Ok:  true,
		Msg: "vault found (decrypt via CLI for now)",
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := `
			<!DOCTYPE html>
			<html><head><meta charset="UTF-8"><title>PASSLOCK API</title><style>
			body{background:#0a0e27;color:#fff;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
			.box{border:2px solid #00d9ff;padding:40px;text-align:center;max-width:500px}
			h1{color:#00d9ff;margin:0 0 20px}
			.endpoint{background:#1a1e3a;padding:10px;margin:10px 0;border-left:3px solid #00d9ff}
			code{color:#0f0}
			</style></head><body>
			<div class="box">
			<h1>PASSLOCK API</h1>
			<p>Multi-language password manager</p>
			<div class="endpoint"><b>GET</b> <code>/health</code> - Health check</div>
			<div class="endpoint"><b>POST</b> <code>/api</code> - Vault operations</div>
			<p style="margin-top:30px;font-size:12px">Server running ✓</p>
			</div>
			</body></html>
		`
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/api", handle)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	log.Println("→ server started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
