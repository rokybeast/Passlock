package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
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

	switch req.Act {
	case "unlock":
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

		v = &Vault{E: []Entry{}, S: parts[0]}
		json.NewEncoder(w).Encode(Res{Ok: true, Msg: "vault unlocked"})

	case "list":
		if v == nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
			return
		}
		json.NewEncoder(w).Encode(Res{Ok: true, Data: v.E})

	case "add":
		if v == nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
			return
		}

		var addReq struct {
			Name string `json:"name"`
			User string `json:"user"`
			Pass string `json:"pass"`
			Url  string `json:"url,omitempty"`
			Note string `json:"note,omitempty"`
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1048576)
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "failed to read request"})
			return
		}

		if err := json.Unmarshal(body, &addReq); err != nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "invalid add request"})
			return
		}

		if addReq.Name == "" || addReq.User == "" || addReq.Pass == "" {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "name, user and pass required"})
			return
		}

		e := Entry{
			ID: fmt.Sprintf("%d", time.Now().UnixNano()),
			N:  addReq.Name,
			U:  addReq.User,
			P:  addReq.Pass,
			T:  uint64(time.Now().Unix()),
		}
		if addReq.Url != "" {
			e.Url = addReq.Url
		}
		if addReq.Note != "" {
			e.Nt = addReq.Note
		}
		v.E = append(v.E, e)
		json.NewEncoder(w).Encode(Res{Ok: true, Msg: "entry added"})

	case "delete":
		if v == nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "vault not unlocked"})
			return
		}

		var delReq struct {
			ID string `json:"id"`
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "failed to read request"})
			return
		}

		if err := json.Unmarshal(body, &delReq); err != nil {
			json.NewEncoder(w).Encode(Res{Ok: false, Msg: "invalid delete request"})
			return
		}

		newE := []Entry{}
		for _, e := range v.E {
			if e.ID != delReq.ID {
				newE = append(newE, e)
			}
		}
		v.E = newE
		json.NewEncoder(w).Encode(Res{Ok: true, Msg: "entry deleted"})

	case "gen":
		l := 16
		var genReq struct {
			Len float64 `json:"len"`
		}

		body, err := ioutil.ReadAll(r.Body)
		if err == nil {
			json.Unmarshal(body, &genReq)
			if genReq.Len > 0 {
				l = int(genReq.Len)
			}
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
		json.NewEncoder(w).Encode(Res{Ok: true, Data: string(pwd)})

	default:
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
			Msg: "vault found (use unlock to access data)",
			Data: map[string]string{
				"salt":      parts[0],
				"encrypted": fmt.Sprintf("%d bytes", len(parts[1])),
				"note":      "unlock vault to manage passwords",
			},
		})
	}
}

func webUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>PASSLOCK</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:#1e1e2e;color:#cdd6f4;font-family:system-ui;padding:20px;min-height:100vh}
        .c{max-width:900px;margin:0 auto}
        .hd{text-align:center;padding:25px;border:2px solid #89b4fa;border-radius:10px;margin-bottom:20px;background:#181825}
        .hd h1{color:#89b4fa;font-size:1.8em;margin-bottom:5px}
        .hd p{color:#6c7086;font-size:0.9em}
        .bx{padding:35px;border:2px solid #89b4fa;border-radius:10px;background:#181825;max-width:380px;margin:40px auto}
        .bx h2{color:#89b4fa;margin-bottom:18px;text-align:center;font-size:1.3em}
        input,textarea{width:100%;padding:11px;margin:7px 0;background:#313244;border:2px solid #45475a;border-radius:7px;color:#cdd6f4;font-size:14px;font-family:inherit}
        input:focus,textarea:focus{outline:0;border-color:#89b4fa}
        button{width:100%;padding:11px;margin:7px 0;background:#89b4fa;border:0;border-radius:7px;color:#1e1e2e;font-weight:600;cursor:pointer;font-size:14px;font-family:inherit;transition:all .2s}
        button:hover{background:#a6c8ff;transform:translateY(-1px)}
        button:active{transform:translateY(0)}
        button.sc{background:#313244;color:#89b4fa;border:2px solid #45475a}
        button.sc:hover{background:#45475a;border-color:#89b4fa}
        button.dg{background:#f38ba8;color:#1e1e2e}
        button.dg:hover{background:#f5a9bc}
        .ct{display:flex;gap:10px;margin:18px 0;flex-wrap:wrap}
        .ct button{width:auto;padding:10px 18px;flex:1;min-width:110px}
        .srch{flex:2;min-width:180px}
        .ent{margin-top:18px}
        .en{background:#181825;border:2px solid#313244;border-radius:10px;padding:18px;margin-bottom:13px;transition:border .2s}
        .en:hover{border-color:#89b4fa}
        .et{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
        .nm{color:#89b4fa;font-size:1.15em;font-weight:600}
        .bt{display:flex;gap:7px}
        .bt button{width:auto;padding:6px 11px;margin:0;font-size:13px}
        .fd{margin:7px 0;display:flex;gap:10px;align-items:flex-start}
        .fd .lb{color:#6c7086;min-width:70px;font-size:14px}
        .fd .vl{color:#a6e3a1;flex:1;cursor:pointer;word-break:break-all;font-size:14px}
        .fd .vl:hover{text-decoration:underline}
        .hid{display:none!important}
        .md{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;z-index:999}
        .mb{background:#1e1e2e;border:2px solid #89b4fa;border-radius:10px;padding:28px;max-width:480px;width:88%;max-height:85vh;overflow-y:auto}
        .mh{color:#89b4fa;font-size:1.25em;margin-bottom:16px;text-align:center;font-weight:600}
        .ms{padding:11px;margin:9px 0;border-left:4px solid;border-radius:6px;font-size:14px}
        .ms.ok{border-color:#a6e3a1;color:#a6e3a1;background:rgba(166,227,161,.08)}
        .ms.er{border-color:#f38ba8;color:#f38ba8;background:rgba(243,139,168,.08)}
        .em{text-align:center;padding:35px;color:#6c7086;font-size:15px}
    </style>
</head>
<body>
    <div class="c">
        <div class="hd">
            <h1>PASSLOCK</h1>
            <p>password manager</p>
        </div>
        <div id="lg" class="bx">
            <h2>unlock vault</h2>
            <input type="password" id="pw" placeholder="master password" onkeypress="if(event.key==='Enter')ul()">
            <button onclick="ul()">unlock</button>
            <div id="lm"></div>
        </div>
        <div id="ap" class="hid">
            <div class="ct">
                <input type="text" id="qr" class="srch" placeholder="search..." oninput="sr()">
                <button onclick="sa()">add</button>
                <button onclick="sg()" class="sc">generate</button>
                <button onclick="lo()" class="dg">logout</button>
            </div>
            <div id="ms"></div>
            <div id="es"></div>
        </div>
    </div>
    <div id="am" class="md hid" onclick="if(event.target===this)hd('am')">
        <div class="mb">
            <div class="mh">add password</div>
            <input type="text" id="nm" placeholder="name">
            <input type="text" id="us" placeholder="username">
            <input type="text" id="ps" placeholder="password">
            <input type="text" id="ur" placeholder="url (optional)">
            <textarea id="nt" placeholder="notes (optional)" rows="3"></textarea>
            <button onclick="ad()">save</button>
            <button onclick="hd('am')" class="sc">cancel</button>
        </div>
    </div>
    <div id="gm" class="md hid" onclick="if(event.target===this)hd('gm')">
        <div class="mb">
            <div class="mh">generate password</div>
            <input type="number" id="ln" value="16" min="4" max="64">
            <button onclick="gn()">generate</button>
            <div id="go"></div>
            <button onclick="hd('gm')" class="sc">close</button>
        </div>
    </div>
    <script>
        let p='',vt=[];
        async function ap(a,d={}){
            try{
                const r=await fetch('/api',{
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({act:a,...d})
                });
                return await r.json();
            }catch(e){
                return{ok:false,msg:'network error'};
            }
        }
        async function ul(){
            p=document.getElementById('pw').value;
            if(!p){
                sm('lm','enter password','er');
                return;
            }
            const d=await ap('unlock',{pwd:p});
            if(d.ok){
                document.getElementById('lg').classList.add('hid');
                document.getElementById('ap').classList.remove('hid');
                ld();
            }else{
                sm('lm',d.msg||'unlock failed','er');
            }
        }
        async function ld(){
            const d=await ap('list');
            if(d.ok){
                vt=d.data||[];
                rn(vt);
            }
        }
        function rn(e){
            const c=document.getElementById('es');
            if(!e||e.length===0){
                c.innerHTML='<div class="em">no passwords saved yet</div>';
                return;
            }
            let h='';
            e.forEach(x=>{
                h+='<div class="en"><div class="et"><div class="nm">'+x.n+'</div><div class="bt"><button onclick="cp(\''+x.p.replace(/'/g,"\\'")+'\')">copy</button><button onclick="dl(\''+x.id+'\')" class="dg">delete</button></div></div><div class="fd"><span class="lb">user:</span><span class="vl" onclick="cp(\''+x.u.replace(/'/g,"\\'")+'\')">'+x.u+'</span></div><div class="fd"><span class="lb">pass:</span><span class="vl" onclick="cp(\''+x.p.replace(/'/g,"\\'")+'\')">'+x.p+'</span></div>';
                if(x.url)h+='<div class="fd"><span class="lb">url:</span><span class="vl">'+x.url+'</span></div>';
                if(x.nt)h+='<div class="fd"><span class="lb">notes:</span><span class="vl">'+x.nt+'</span></div>';
                h+='</div>';
            });
            c.innerHTML=h;
        }
        function sr(){
            const q=document.getElementById('qr').value.toLowerCase();
            if(!q){
                rn(vt);
                return;
            }
            const f=vt.filter(e=>e.n.toLowerCase().includes(q)||e.u.toLowerCase().includes(q)||(e.url&&e.url.toLowerCase().includes(q)));
            rn(f);
        }
        function sa(){
            sh('am');
        }
        function sg(){
            sh('gm');
        }
        function sh(i){
            document.getElementById(i).classList.remove('hid');
        }
        function hd(i){
            document.getElementById(i).classList.add('hid');
        }
        async function ad(){
            const n=document.getElementById('nm').value.trim(),
                  u=document.getElementById('us').value.trim(),
                  ps=document.getElementById('ps').value.trim(),
                  ur=document.getElementById('ur').value.trim(),
                  nt=document.getElementById('nt').value.trim();
            if(!n||!u||!ps){
                alert('name, username and password required');
                return;
            }
            const d=await ap('add',{name:n,user:u,pass:ps,url:ur,note:nt});
            if(d.ok){
                ld();
                hd('am');
                sm('ms','password added','ok');
                document.getElementById('nm').value='';
                document.getElementById('us').value='';
                document.getElementById('ps').value='';
                document.getElementById('ur').value='';
                document.getElementById('nt').value='';
            }
        }
        async function dl(i){
            if(!confirm('delete this password?'))return;
            const d=await ap('delete',{id:i});
            if(d.ok){
                ld();
                sm('ms','password deleted','ok');
            }
        }
        async function gn(){
            const l=parseInt(document.getElementById('ln').value)||16;
            const d=await ap('gen',{len:l});
            if(d.ok){
                document.getElementById('go').innerHTML='<div class="ms ok"><strong>generated:</strong><br><span class="vl" onclick="cp(\''+d.data.replace(/'/g,"\\'")+'\')" style="font-size:1.05em;margin-top:7px;display:block">'+d.data+'</span></div>';
            }
        }
        function cp(t){
            navigator.clipboard.writeText(t).then(()=>sm('ms','copied to clipboard','ok')).catch(()=>sm('ms','copy failed','er'));
        }
        function sm(i,m,t){
            const el=document.getElementById(i);
            el.innerHTML='<div class="ms '+t+'">'+m+'</div>';
            setTimeout(()=>el.innerHTML='',2200);
        }
        function lo(){
            if(!confirm('logout?'))return;
            p='';
            vt=[];
            document.getElementById('lg').classList.remove('hid');
            document.getElementById('ap').classList.add('hid');
            document.getElementById('pw').value='';
        }
    </script>
</body>
</html>`

	fmt.Fprint(w, html)
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

	http.HandleFunc("/", webUI)
	http.HandleFunc("/api", handle)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	log.Println("→ server started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
