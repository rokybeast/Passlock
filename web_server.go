package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Req struct {
	Act  string `json:"act"`
	Pwd  string `json:"pwd"`
	Name string `json:"name,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
	Url  string `json:"url,omitempty"`
	Note string `json:"note,omitempty"`
	ID   string `json:"id,omitempty"`
	Q    string `json:"q,omitempty"`
	Len  int    `json:"len,omitempty"`
}

type Res struct {
	Ok   bool        `json:"ok"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

type Entry struct {
	ID   string `json:"id"`
	N    string `json:"n"`
	U    string `json:"u"`
	P    string `json:"p"`
	Url  string `json:"url,omitempty"`
	Note string `json:"note,omitempty"`
	T    int64  `json:"t"`
}

type Vault struct {
	E []Entry `json:"e"`
	S string  `json:"s"`
}

var vault *Vault
var masterPwd string

func handleAPI(w http.ResponseWriter, r *http.Request) {
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
	
	switch req.Act {
	case "unlock":
		handleUnlock(w, req)
	case "list":
		handleList(w, req)
	case "add":
		handleAdd(w, req)
	case "delete":
		handleDelete(w, req)
	case "search":
		handleSearch(w, req)
	case "generate":
		handleGenerate(w, req)
	default:
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "unknown action"})
	}
}

func handleUnlock(w http.ResponseWriter, req Req) {
	home, _ := os.UserHomeDir()
	vp := filepath.Join(home, ".passlock.vault")
	
	if _, err := os.Stat(vp); os.IsNotExist(err) {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "no vault found - create one with CLI first"})
		return
	}
	
	data, err := os.ReadFile(vp)
	if err != nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "cant read vault"})
		return
	}
	
	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "invalid vault format"})
		return
	}
	
	masterPwd = req.Pwd
	vault = &Vault{E: []Entry{}, S: parts[0]}
	
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "vault unlocked"})
}

func handleList(w http.ResponseWriter, req Req) {
	if vault == nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
		return
	}
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "success", Data: vault.E})
}

func handleAdd(w http.ResponseWriter, req Req) {
	if vault == nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
		return
	}
	
	e := Entry{
		ID:   fmt.Sprintf("%d", time.Now().UnixNano()),
		N:    req.Name,
		U:    req.User,
		P:    req.Pass,
		Url:  req.Url,
		Note: req.Note,
		T:    time.Now().Unix(),
	}
	
	vault.E = append(vault.E, e)
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "password added", Data: e})
}

func handleDelete(w http.ResponseWriter, req Req) {
	if vault == nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
		return
	}
	
	var newE []Entry
	found := false
	
	for _, e := range vault.E {
		if e.ID != req.ID {
			newE = append(newE, e)
		} else {
			found = true
		}
	}
	
	if !found {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "password not found"})
		return
	}
	
	vault.E = newE
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "password deleted"})
}

func handleSearch(w http.ResponseWriter, req Req) {
	if vault == nil {
		json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
		return
	}
	
	q := strings.ToLower(req.Q)
	var results []Entry
	
	for _, e := range vault.E {
		if strings.Contains(strings.ToLower(e.N), q) ||
			strings.Contains(strings.ToLower(e.U), q) ||
			strings.Contains(strings.ToLower(e.Url), q) {
			results = append(results, e)
		}
	}
	
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "success", Data: results})
}

func handleGenerate(w http.ResponseWriter, req Req) {
	l := req.Len
	if l == 0 {
		l = 16
	}
	
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	p := make([]byte, l)
	
	for i := range p {
		p[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		time.Sleep(time.Nanosecond)
	}
	
	json.NewEncoder(w).Encode(Res{Ok: true, Msg: "success", Data: string(p)})
}

func serveWeb(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>PASSLOCK</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#1e1e2e;color:#cdd6f4;font-family:'Segoe UI',sans-serif;min-height:100vh;padding:20px}.container{max-width:1200px;margin:0 auto}.hdr{text-align:center;padding:30px;border:2px solid #89b4fa;border-radius:12px;margin-bottom:30px;background:#181825}.hdr h1{color:#89b4fa;font-size:2.5em;margin-bottom:10px;font-weight:600}.hdr p{color:#6c7086}.login{max-width:400px;margin:50px auto;padding:40px;border:2px solid #89b4fa;border-radius:12px;background:#181825}.login h2{color:#89b4fa;margin-bottom:20px;text-align:center}input,textarea{width:100%;padding:12px;margin:10px 0;background:#313244;border:2px solid #45475a;border-radius:8px;color:#cdd6f4;font-size:14px}input:focus,textarea:focus{outline:none;border-color:#89b4fa}button{width:100%;padding:12px;margin:10px 0;background:#89b4fa;border:none;border-radius:8px;color:#1e1e2e;font-weight:600;cursor:pointer}button:hover{background:#a6c8ff}button.sec{background:#313244;color:#89b4fa}button.danger{background:#f38ba8}.ctrl{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}.ctrl button{width:auto;padding:12px 24px;flex:1;min-width:150px}.search{flex:2;min-width:200px}.entries{display:grid;gap:15px;margin-top:20px}.entry{background:#181825;border:2px solid #313244;border-radius:12px;padding:20px}.entry:hover{border-color:#89b4fa}.entry-hdr{display:flex;justify-content:space-between;margin-bottom:15px}.entry-name{color:#89b4fa;font-size:1.3em;font-weight:600}.entry-actions{display:flex;gap:10px}.entry-actions button{width:auto;padding:8px 16px;margin:0;font-size:13px}.field{margin:10px 0;display:flex;gap:10px}.lbl{color:#6c7086;min-width:90px}.val{color:#a6e3a1;flex:1;cursor:pointer}.val:hover{text-decoration:underline}.hidden{display:none}.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:1000}.modal-content{background:#1e1e2e;border:2px solid #89b4fa;border-radius:12px;padding:30px;max-width:500px;width:90%}.modal-hdr{color:#89b4fa;font-size:1.5em;margin-bottom:20px;text-align:center}.status{padding:12px;margin:10px 0;border-left:4px solid;border-radius:6px}.status.success{border-color:#a6e3a1;color:#a6e3a1;background:rgba(166,227,161,0.1)}.status.error{border-color:#f38ba8;color:#f38ba8;background:rgba(243,139,168,0.1)}.empty{text-align:center;padding:60px 20px;color:#6c7086}.empty h3{color:#89b4fa}</style></head><body><div class="container"><div class="hdr"><h1>🔐 PASSLOCK</h1><p>secure password manager</p></div><div id="loginScreen" class="login"><h2>unlock vault</h2><input type="password" id="pwd" placeholder="master password"><button onclick="unlock()">unlock</button><div id="loginMsg"></div></div><div id="app" class="hidden"><div class="ctrl"><input type="text" id="q" class="search" placeholder="search..." oninput="search()"><button onclick="showAdd()">add password</button><button onclick="showGen()" class="sec">generate</button><button onclick="logout()" class="danger">logout</button></div><div id="msg"></div><div id="entries"></div></div></div><div id="addModal" class="modal hidden" onclick="if(event.target===this)closeModal('addModal')"><div class="modal-content"><div class="modal-hdr">add password</div><input type="text" id="newN" placeholder="name"><input type="text" id="newU" placeholder="username"><input type="text" id="newP" placeholder="password"><input type="text" id="newUrl" placeholder="url (optional)"><textarea id="newNote" placeholder="notes (optional)" rows="3"></textarea><button onclick="add()">save</button><button onclick="closeModal('addModal')" class="sec">cancel</button></div></div><div id="genModal" class="modal hidden" onclick="if(event.target===this)closeModal('genModal')"><div class="modal-content"><div class="modal-hdr">generate password</div><input type="number" id="genLen" placeholder="length" value="16"><button onclick="gen()">generate</button><div id="genRes"></div><button onclick="closeModal('genModal')" class="sec">close</button></div></div><script>let pwd='',vault=[];async function api(act,data={}){const r=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({act,pwd,...data})});return r.json()}async function unlock(){pwd=document.getElementById('pwd').value;if(!pwd){msg('loginMsg','enter password','error');return}const d=await api('unlock',{pwd});if(d.ok){document.getElementById('loginScreen').classList.add('hidden');document.getElementById('app').classList.remove('hidden');load()}else{msg('loginMsg',d.msg,'error')}}async function load(){const d=await api('list');if(d.ok){vault=d.data||[];render(vault)}}function render(e){const c=document.getElementById('entries');if(!e||e.length===0){c.innerHTML='<div class="empty"><h3>no passwords yet</h3><p>add your first password</p></div>';return}let h='';for(let i=0;i<e.length;i++){const x=e[i];h+='<div class="entry"><div class="entry-hdr"><div class="entry-name">'+x.n+'</div><div class="entry-actions"><button onclick="copy(\''+x.p+'\')">copy</button><button onclick="del(\''+x.id+'\')" class="danger">delete</button></div></div><div class="field"><span class="lbl">username:</span><span class="val" onclick="copy(\''+x.u+'\')">'+x.u+'</span></div><div class="field"><span class="lbl">password:</span><span class="val" onclick="copy(\''+x.p+'\')">'+x.p+'</span></div>';if(x.url){h+='<div class="field"><span class="lbl">url:</span><span class="val">'+x.url+'</span></div>'}if(x.note){h+='<div class="field"><span class="lbl">notes:</span><span class="val">'+x.note+'</span></div>'}h+='</div>'}c.innerHTML=h}function search(){const q=document.getElementById('q').value.toLowerCase();if(!q){render(vault);return}const f=vault.filter(e=>e.n.toLowerCase().includes(q)||e.u.toLowerCase().includes(q)||(e.url&&e.url.toLowerCase().includes(q)));render(f)}function showAdd(){document.getElementById('addModal').classList.remove('hidden')}function showGen(){document.getElementById('genModal').classList.remove('hidden')}function closeModal(id){document.getElementById(id).classList.add('hidden')}async function add(){const n=document.getElementById('newN').value,u=document.getElementById('newU').value,p=document.getElementById('newP').value,url=document.getElementById('newUrl').value,note=document.getElementById('newNote').value;if(!n||!u||!p){alert('name, username, password required');return}const d=await api('add',{name:n,user:u,pass:p,url,note});if(d.ok){load();closeModal('addModal');msg('msg','password added','success');document.getElementById('newN').value='';document.getElementById('newU').value='';document.getElementById('newP').value='';document.getElementById('newUrl').value='';document.getElementById('newNote').value=''}}async function del(id){if(!confirm('delete?'))return;const d=await api('delete',{id});if(d.ok){load();msg('msg','deleted','success')}}async function gen(){const l=parseInt(document.getElementById('genLen').value)||16;const d=await api('generate',{len:l});if(d.ok){document.getElementById('genRes').innerHTML='<div class="status success"><strong>generated:</strong><br><span class="val" onclick="copy(\''+d.data+'\')" style="font-size:1.2em;display:block;margin-top:10px">'+d.data+'</span></div>'}}function copy(t){navigator.clipboard.writeText(t).then(()=>msg('msg','copied','success'))}function msg(id,m,t){const el=document.getElementById(id);el.innerHTML='<div class="status '+t+'">'+m+'</div>';setTimeout(()=>el.innerHTML='',3000)}function logout(){if(!confirm('logout?'))return;pwd='';vault=[];document.getElementById('loginScreen').classList.remove('hidden');document.getElementById('app').classList.add('hidden');document.getElementById('pwd').value=''}</script></body></html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func main() {
	fmt.Println("╔═══════════════════════════════════════╗")
	fmt.Println("║                                       ║")
	fmt.Println("║       PASSLOCK WEB SERVER             ║")
	fmt.Println("║       http://localhost:8080           ║")
	fmt.Println("║                                       ║")
	fmt.Println("╚═══════════════════════════════════════╝")
	
	http.HandleFunc("/", serveWeb)
	http.HandleFunc("/api", handleAPI)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	
	log.Println("→ web server started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}