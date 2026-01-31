package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Entry struct {
	ID  string `json:"id"`
	N   string `json:"n"`
	U   string `json:"u"`
	P   string `json:"p"`
	Url string `json:"url,omitempty"`
	Nt  string `json:"nt,omitempty"`
	T   uint64 `json:"t"`
}

type Vault struct {
	E []Entry `json:"e"`
	S string  `json:"s"`
}

var v *Vault
var ms_pwd string

func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "use POST"})
		return
	}

	body := make([]byte, 0)
	var req map[string]interface{}
	json.NewDecoder(r.Body).Decode(&req)

	home, _ := os.UserHomeDir()
	vt_path := filepath.Join(home, ".passlock.vault")
	tempP := filepath.Join(home, ".passlock.temp")

	act, _ := req["act"].(string)

	switch act {
	case "check":
		exists := false
		if _, err := os.Stat(vt_path); err == nil {
			exists = true
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "exists": exists})

	case "create":
		pwd, _ := req["pwd"].(string)
		confirm, _ := req["confirm"].(string)

		if pwd == "" || confirm == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "password and confirmation required"})
			return
		}

		if pwd != confirm {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "passwords don't match"})
			return
		}

		if len(pwd) < 4 {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "password too short (min 4 chars)"})
			return
		}

		if _, err := os.Stat(vt_path); err == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "vault already exists"})
			return
		}

		wd, err := os.Getwd()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to get working directory"})
			return
		}

		cmd := exec.Command("cargo", "run", "--release", "--", "create", pwd)
		cmd.Dir = wd
		err = cmd.Run()

		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":  false,
				"msg": "failed to create vault",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "vault created successfully"})

	case "unlock":
		pwd, _ := req["pwd"].(string)
		if pwd == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "password required"})
			return
		}

		if _, err := os.Stat(vt_path); os.IsNotExist(err) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "no vault - create with CLI"})
			return
		}

		wd, err := os.Getwd()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to get working directory"})
			return
		}

		cmd := exec.Command("cargo", "run", "--release", "--", "unlock", pwd)
		cmd.Dir = wd
		err = cmd.Run()

		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":  false,
				"msg": "wrong password",
			})
			return
		}

		tempD, err := os.ReadFile(tempP)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to read decrypted vault"})
			return
		}

		var tempV Vault
		if err := json.Unmarshal(tempD, &tempV); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to parse vault"})
			return
		}

		ms_pwd = pwd
		v = &tempV
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "unlocked"})

	case "list":
		if v == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "not unlocked"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": v.E})

	case "add":
		if v == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "not unlocked"})
			return
		}

		name, _ := req["name"].(string)
		user, _ := req["user"].(string)
		pass, _ := req["pass"].(string)
		url, _ := req["url"].(string)
		note, _ := req["note"].(string)

		if name == "" || user == "" || pass == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "name, user, pass required"})
			return
		}

		e := Entry{
			ID:  fmt.Sprintf("%d", time.Now().UnixNano()),
			N:   name,
			U:   user,
			P:   pass,
			Url: url,
			Nt:  note,
			T:   uint64(time.Now().Unix()),
		}

		v.E = append(v.E, e)

		tempD, _ := json.Marshal(v)
		os.WriteFile(tempP, tempD, 0600)

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "added"})

	case "delete":
		if v == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "not unlocked"})
			return
		}

		id, _ := req["id"].(string)
		newE := []Entry{}
		for _, e := range v.E {
			if e.ID != id {
				newE = append(newE, e)
			}
		}
		v.E = newE

		tempD, _ := json.Marshal(v)
		os.WriteFile(tempP, tempD, 0600)

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "deleted"})

	case "gen":
		l := 16
		if len, ok := req["len"].(float64); ok {
			l = int(len)
		}
		if l < 4 {
			l = 4
		}
		if l > 64 {
			l = 64
		}

		chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
		pwd := make([]byte, l)
		for i := range pwd {
			pwd[i] = chars[time.Now().UnixNano()%int64(len(chars))]
			time.Sleep(time.Nanosecond)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "data": string(pwd)})

	case "save":
		if v == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "not unlocked"})
			return
		}

		tempD, err := json.Marshal(v)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to serialize vault"})
			return
		}

		if err := os.WriteFile(tempP, tempD, 0600); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to write temp file"})
			return
		}

		wd, err := os.Getwd()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "failed to get working directory"})
			return
		}

		cmd := exec.Command("cargo", "run", "--release", "--", "sync", ms_pwd)
		cmd.Dir = wd
		output, err := cmd.CombinedOutput()

		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":  false,
				"msg": fmt.Sprintf("failed to save: %s", string(output)),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "saved to vault"})

	default:
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "unknown action"})
	}

	_ = body

}

func banner() {
	fmt.Println("╔═══════════════════════════════════════╗")
	fmt.Println("║       PASSLOCK WEB SERVER             ║")
	fmt.Println("║       http://localhost:8080           ║")
	fmt.Println("╚═══════════════════════════════════════╝")
}

func main() {
	banner()
	http.Handle("/", http.FileServer(http.Dir("./web")))
	http.HandleFunc("/api", handle)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	log.Println("→ server started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
