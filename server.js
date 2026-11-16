require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-this-secret";
const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(DATA_DIR, {recursive:true});
fs.mkdirSync(UPLOAD_DIR, {recursive:true});
const db = new Database(path.join(DATA_DIR, "arsenal.sqlite"));
db.pragma("journal_mode = WAL");
app.use(cors());
app.use(express.json({limit:"2mb"}));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','coach','player')),
 player_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS players (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, nickname TEXT,
 number INTEGER NOT NULL, position TEXT DEFAULT 'A definir', photo TEXT,
 active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS historical_player_stats (
 id INTEGER PRIMARY KEY,
 games INTEGER NOT NULL DEFAULT 0,
 goals INTEGER NOT NULL DEFAULT 0,
 assists INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS matches (
 id INTEGER PRIMARY KEY AUTOINCREMENT, opponent TEXT NOT NULL, date TEXT NOT NULL,
 time TEXT, venue TEXT, status TEXT DEFAULT 'scheduled',
 arsenal_score INTEGER, opponent_score INTEGER, notes TEXT
);
CREATE TABLE IF NOT EXISTS attendance (
 id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER NOT NULL, player_id INTEGER NOT NULL,
 present INTEGER DEFAULT 0, confirmed_by INTEGER, UNIQUE(match_id,player_id)
);
CREATE TABLE IF NOT EXISTS match_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER NOT NULL, player_id INTEGER NOT NULL,
 type TEXT NOT NULL CHECK(type IN ('goal','assist')), minute INTEGER
);
CREATE TABLE IF NOT EXISTS match_mvp (
 match_id INTEGER PRIMARY KEY, player_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fan_votes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, match_id INTEGER NOT NULL, player_id INTEGER NOT NULL,
 voter_key TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(match_id,voter_key)
);
`);

const players = [
 ["Lobo",3],["Nathan",8],["James",5],["Pedro",14],["Adjavan",77],["Anderson",5],
 ["Arthur",16],["Baiano",11],["Bruno",18],["CR7Nordestino",7],["Edivanio",10],
 ["Eliclecio",12],["Ericlis",8],["Henrique",14],["Hiago",14],["Hugo",10],
 ["Cesar",11],["Itamir",5],["Jefferson",1],["Jonathan",11],["Nando",4],["Pingo",6],
 ["Rafa",4],["Riquelmy",17],["Ruan",10],["Thony",9],["Tyago",12],["Victor",11],
 ["Wallace",17],["Wallysson",4],["Willames",1],["Willemberg",16],["Wilson",2],["Ygor",9]
];
const slug = s => s.normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-zA-Z0-9]/g,"");
const insertPlayer = db.prepare("INSERT INTO players(name,nickname,number,position) VALUES(?,?,?,?)");
const insertUser = db.prepare("INSERT OR IGNORE INTO users(username,password_hash,role,player_id) VALUES(?,?,?,?)");
const findPlayer = db.prepare("SELECT id FROM players WHERE name=? AND number=?");
const seed = db.transaction(() => {
  for (const [name,num] of players) {
    let p = findPlayer.get(name,num);
    if (!p) { const info = insertPlayer.run(name,name,num,"A definir"); p={id:info.lastInsertRowid}; }
    const username = `${slug(name)}${String(num).padStart(2,"0")}2027`;
    insertUser.run(username,bcrypt.hashSync(process.env.PLAYER_DEFAULT_PASSWORD || "2024",10),"player",p.id);
  }
  for (const [name,user] of [["Augusto","Augusto012027"],["Mateus","Mateus012027"]]) {
    insertUser.run(user,bcrypt.hashSync(process.env.COACH_DEFAULT_PASSWORD || "2024",10),"coach",null);
  }
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    insertUser.run(process.env.ADMIN_USERNAME,bcrypt.hashSync(process.env.ADMIN_PASSWORD,10),"admin",null);
  }
});
seed();

const auth = (req,res,next) => {
 const h=req.headers.authorization||"";
 try { req.user=jwt.verify(h.replace(/^Bearer\s+/i,""),JWT_SECRET); next(); }
 catch { res.status(401).json({error:"Faça login para continuar."}); }
};
const allow = (...roles) => (req,res,next) => {
 if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({error:"Acesso não autorizado."});
 next();
};
const publicMatch = id => db.prepare("SELECT * FROM matches WHERE id=?").get(id);
const stats = (period) => {
 const year = new Date().getFullYear();
 const where = period==="year" ? "WHERE status='played' AND substr(date,1,4)=?" : "WHERE status='played'";
 const rows = period==="year" ? db.prepare(`SELECT * FROM matches ${where}`).all(String(year)) : db.prepare(`SELECT * FROM matches ${where}`).all();
 const w=rows.filter(m=>m.arsenal_score>m.opponent_score).length;
 const d=rows.filter(m=>m.arsenal_score===m.opponent_score).length;
 const l=rows.length-w-d;
 const gf=rows.reduce((a,m)=>a+(m.arsenal_score||0),0), ga=rows.reduce((a,m)=>a+(m.opponent_score||0),0);
 return {games:rows.length,wins:w,draws:d,losses:l,goalsFor:gf,goalsAgainst:ga,goalDifference:gf-ga,points: w*3+d,winRate:rows.length?Math.round(((w*3+d)/(rows.length*3))*100):0};
};
app.post("/api/login",(req,res)=>{
 const {username,password}=req.body||{};
 const u=db.prepare("SELECT * FROM users WHERE username=?").get(String(username||"").trim());
 if(!u || !bcrypt.compareSync(String(password||""),u.password_hash)) return res.status(401).json({error:"Usuário ou senha inválidos."});
 const token=jwt.sign({id:u.id,username:u.username,role:u.role,playerId:u.player_id},JWT_SECRET,{expiresIn:"7d"});
 res.json({token,user:{username:u.username,role:u.role,playerId:u.player_id}});
});
app.get("/api/me",auth,(req,res)=>res.json(req.user));
app.get("/api/players",(req,res)=>res.json(db.prepare("SELECT * FROM players WHERE active=1 ORDER BY number,name").all()));


app.get("/api/players/:id",(req,res)=>{
 const p=db.prepare("SELECT * FROM players WHERE id=?").get(req.params.id);
 if(!p) return res.status(404).json({error:"Atleta não encontrado."});

 const historical=db.prepare("SELECT * FROM historical_player_stats WHERE id=?").get(p.id)||{games:0,goals:0,assists:0};

 const goals=db.prepare("SELECT COUNT(*) n FROM match_events e JOIN matches m ON m.id=e.match_id WHERE e.player_id=? AND e.type='goal' AND m.status='played'").get(p.id).n+historical.goals;

 const assists=db.prepare("SELECT COUNT(*) n FROM match_events e JOIN matches m ON m.id=e.match_id WHERE e.player_id=? AND e.type='assist' AND m.status='played'").get(p.id).n+historical.assists;

 const games=db.prepare("SELECT COUNT(*) n FROM attendance a JOIN matches m ON m.id=a.match_id WHERE a.player_id=? AND a.present=1 AND m.status='played'").get(p.id).n+historical.games;

 const mvps=db.prepare("SELECT COUNT(*) n FROM match_mvp v JOIN matches m ON m.id=v.match_id WHERE v.player_id=? AND m.status='played'").get(p.id).n;

 res.json({...p,goals,assists,games,mvps,goalAverage:games?(goals/games).toFixed(2):"0.00"});
});

app.get("/api/stats",(req,res)=>res.json({season:stats("year"),allTime:stats("all")}));

app.get("/api/rankings",(req,res)=>{
 const period=req.query.period==="all"?"all":"year";
 const year=new Date().getFullYear();

 const rank=(type)=>{
  const historicalColumn=type==="goal"?"goals":"assists";
  const includeHistorical=period==="all";

  const eventDate=period==="year"?"AND substr(m.date,1,4)=?":"";
  const attendanceDate=period==="year"?"AND substr(mm.date,1,4)=?":"";

  const historicalGoals=includeHistorical
   ? `+ COALESCE((SELECT hs.${historicalColumn} FROM historical_player_stats hs WHERE hs.id=p.id),0)`
   : "";

  const historicalGames=includeHistorical
   ? `+ COALESCE((SELECT hs.games FROM historical_player_stats hs WHERE hs.id=p.id),0)`
   : "";

  const sql=`
   SELECT p.id,p.name,p.nickname,p.number,p.position,p.photo,

   (
    COALESCE((
     SELECT COUNT(*)
     FROM match_events e
     JOIN matches m ON m.id=e.match_id
     WHERE e.player_id=p.id
     AND e.type=?
     AND m.status='played'
     ${eventDate}
    ),0)
    ${historicalGoals}
   ) value,

   (
    COALESCE((
     SELECT COUNT(*)
     FROM attendance a
     JOIN matches mm ON mm.id=a.match_id
     WHERE a.player_id=p.id
     AND a.present=1
     AND mm.status='played'
     ${attendanceDate}
    ),0)
    ${historicalGames}
   ) games

   FROM players p
   WHERE p.active=1
   ORDER BY value DESC,p.name
  `;

  const params=period==="year"
   ? [type,String(year),String(year)]
   : [type];

  return db.prepare(sql).all(...params);
 };

 const mvps=db.prepare(`
  SELECT p.id,p.name,p.nickname,p.number,p.position,p.photo,
  COUNT(m.id) value
  FROM players p
  LEFT JOIN match_mvp v ON v.player_id=p.id
  LEFT JOIN matches m ON m.id=v.match_id
  AND m.status='played'
  ${period==="year"?"AND substr(m.date,1,4)=?":""}
  WHERE p.active=1
  GROUP BY p.id
  ORDER BY value DESC,p.name
 `).all(...(period==="year"?[String(year)]:[]));

 res.json({
  goals:rank("goal"),
  assists:rank("assist"),
  mvps
 });
});

app.get("/api/matches",(req,res)=>{
 const rows=db.prepare("SELECT * FROM matches ORDER BY date DESC,time DESC").all();
 res.json(rows.map(m=>({...m,related:db.prepare("SELECT p.id,p.name,p.nickname,p.number,p.photo,a.present FROM attendance a JOIN players p ON p.id=a.player_id WHERE a.match_id=? AND a.present=1 ORDER BY p.number").all(m.id)})));
});
app.get("/api/matches/:id",(req,res)=>{
 const m=publicMatch(req.params.id); if(!m)return res.status(404).json({error:"Partida não encontrada."});
 const related=db.prepare("SELECT p.*,a.present FROM attendance a JOIN players p ON p.id=a.player_id WHERE a.match_id=? AND a.present=1").all(m.id);
 const events=db.prepare("SELECT e.type,e.minute,p.id playerId,p.name,p.nickname,p.number FROM match_events e JOIN players p ON p.id=e.player_id WHERE e.match_id=?").all(m.id);
 const mvp=db.prepare("SELECT p.id,p.name,p.nickname,p.number FROM match_mvp v JOIN players p ON p.id=v.player_id WHERE v.match_id=?").get(m.id)||null;
 const votes=db.prepare("SELECT p.id,p.name,p.nickname,p.number,COUNT(v.id) votes FROM fan_votes v JOIN players p ON p.id=v.player_id WHERE v.match_id=? GROUP BY p.id ORDER BY votes DESC").all(m.id);
 res.json({...m,related,events,mvp,votes});
});
app.get("/api/opponents",(req,res)=>{
 const names=db.prepare("SELECT DISTINCT opponent FROM matches WHERE status='played' ORDER BY opponent").all().map(x=>x.opponent);
 res.json(names.map(name=>{
  const ms=db.prepare("SELECT * FROM matches WHERE opponent=? AND status='played' ORDER BY date DESC").all(name);
  return {name,games:ms.length,goalsFor:ms.reduce((a,m)=>a+m.arsenal_score,0),goalsAgainst:ms.reduce((a,m)=>a+m.opponent_score,0),wins:ms.filter(m=>m.arsenal_score>m.opponent_score).length,draws:ms.filter(m=>m.arsenal_score===m.opponent_score).length,losses:ms.filter(m=>m.arsenal_score<m.opponent_score).length,matches:ms.map(m=>({...m,related:db.prepare("SELECT p.name,p.nickname,p.number FROM attendance a JOIN players p ON p.id=a.player_id WHERE a.match_id=? AND a.present=1").all(m.id)}))};
 }));
});
app.post("/api/matches/:id/vote",(req,res)=>{
 const {playerId,voterKey}=req.body||{}; const m=publicMatch(req.params.id);
 if(!m||m.status!=="played")return res.status(400).json({error:"Votação disponível após a partida."});
 const eligible=db.prepare("SELECT 1 FROM attendance WHERE match_id=? AND player_id=? AND present=1").get(m.id,playerId);
 if(!eligible)return res.status(400).json({error:"Vote apenas em atletas relacionados."});
 try{db.prepare("INSERT INTO fan_votes(match_id,player_id,voter_key) VALUES(?,?,?)").run(m.id,playerId,String(voterKey||"").slice(0,100));}
 catch{return res.status(409).json({error:"Este navegador já votou nesta partida."});}
 res.json({ok:true});
});
app.post("/api/players",auth,allow("admin","coach"),(req,res)=>{
 const {name,nickname,number,position}=req.body||{};
 if(!name||number===undefined)return res.status(400).json({error:"Nome e camisa são obrigatórios."});
 const info=db.prepare("INSERT INTO players(name,nickname,number,position) VALUES(?,?,?,?)").run(name,nickname||name,Number(number),position||"A definir");
 const username=`${slug(name)}${String(number).padStart(2,"0")}2027`;
 const password=bcrypt.hashSync(process.env.PLAYER_DEFAULT_PASSWORD||"2024",10);
 insertUser.run(username,password,"player",info.lastInsertRowid);
 res.json({id:info.lastInsertRowid,username});
});
const storage=multer.diskStorage({destination:UPLOAD_DIR,filename:(req,file,cb)=>cb(null,Date.now()+"-"+file.originalname.replace(/[^a-zA-Z0-9.-]/g,"_"))});
const upload=multer({storage,limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>cb(null,/^image\/(jpeg|png|webp)$/.test(file.mimetype))});
app.post("/api/players/:id/photo",auth,allow("admin","coach"),upload.single("photo"),(req,res)=>{
 if(!req.file)return res.status(400).json({error:"Envie uma imagem JPG, PNG ou WEBP de até 5 MB."});
 const url="/uploads/"+req.file.filename; db.prepare("UPDATE players SET photo=? WHERE id=?").run(url,req.params.id); res.json({photo:url});
});
app.post("/api/matches",auth,allow("admin","coach"),(req,res)=>{
 const {opponent,date,time,venue}=req.body||{}; if(!opponent||!date)return res.status(400).json({error:"Adversário e data são obrigatórios."});
 const r=db.prepare("INSERT INTO matches(opponent,date,time,venue) VALUES(?,?,?,?)").run(opponent,date,time||"",venue||"");
 res.json({id:r.lastInsertRowid});
});

app.delete("/api/matches/:id",auth,allow("admin"),(req,res)=>{
 const id=Number(req.params.id);
 const match=db.prepare("SELECT id FROM matches WHERE id=?").get(id);
 if(!match)return res.status(404).json({error:"Partida não encontrada."});

 const remove=db.transaction(()=>{
  db.prepare("DELETE FROM attendance WHERE match_id=?").run(id);
  db.prepare("DELETE FROM match_events WHERE match_id=?").run(id);
  db.prepare("DELETE FROM match_mvp WHERE match_id=?").run(id);
  db.prepare("DELETE FROM fan_votes WHERE match_id=?").run(id);
  db.prepare("DELETE FROM matches WHERE id=?").run(id);
 });

 remove();
 res.json({ok:true});
});

app.put("/api/matches/:id/attendance",auth,allow("admin","coach"),(req,res)=>{
 const {playerIds=[]}=req.body||{}; const m=publicMatch(req.params.id); if(!m)return res.status(404).json({error:"Partida não encontrada."});
 const tx=db.transaction(()=>{
  db.prepare("DELETE FROM attendance WHERE match_id=?").run(m.id);
  const ins=db.prepare("INSERT INTO attendance(match_id,player_id,present,confirmed_by) VALUES(?,?,1,?)");
  for(const id of playerIds)ins.run(m.id,id,req.user.id);
 }); tx(); res.json({ok:true,count:playerIds.length});
});
app.post("/api/matches/:id/confirm",(req,res,next)=>{auth(req,res,()=>{if(req.user.role!=="player")return res.status(403).json({error:"Apenas atletas podem confirmar por este botão."});next();});},(req,res)=>{
 const m=publicMatch(req.params.id); if(!m||m.status!=="scheduled")return res.status(400).json({error:"Não há confirmação aberta."});
 db.prepare("INSERT INTO attendance(match_id,player_id,present,confirmed_by) VALUES(?,?,1,?) ON CONFLICT(match_id,player_id) DO UPDATE SET present=1,confirmed_by=excluded.confirmed_by").run(m.id,req.user.playerId,req.user.id); res.json({ok:true});
});
app.put("/api/matches/:id/result",auth,allow("admin","coach"),(req,res)=>{
 const {arsenalScore,opponentScore,goals=[],assists=[],mvpId}=req.body||{};
 if(!Number.isInteger(Number(arsenalScore))||!Number.isInteger(Number(opponentScore)))return res.status(400).json({error:"Informe placares válidos."});
 const m=publicMatch(req.params.id); if(!m)return res.status(404).json({error:"Partida não encontrada."});
 const tx=db.transaction(()=>{
  db.prepare("UPDATE matches SET arsenal_score=?,opponent_score=?,status='played' WHERE id=?").run(Number(arsenalScore),Number(opponentScore),m.id);
  db.prepare("DELETE FROM match_events WHERE match_id=?").run(m.id);
  const ins=db.prepare("INSERT INTO match_events(match_id,player_id,type,minute) VALUES(?,?,?,?)");
  goals.forEach(x=>ins.run(m.id,x.playerId,"goal",x.minute||null));
  assists.forEach(x=>ins.run(m.id,x.playerId,"assist",x.minute||null));
  db.prepare("DELETE FROM match_mvp WHERE match_id=?").run(m.id);
  if(mvpId)db.prepare("INSERT INTO match_mvp(match_id,player_id) VALUES(?,?)").run(m.id,mvpId);
 }); tx(); res.json({ok:true});
});
app.get("/api/compare",(req,res)=>{
 const ids=(req.query.ids||"").split(",").map(Number).filter(Boolean).slice(0,4);
 const period=req.query.period==="all"?"all":"year", year=String(new Date().getFullYear());
 const result=ids.map(id=>{
  const p=db.prepare("SELECT * FROM players WHERE id=?").get(id); if(!p)return null;
  const date=period==="year"?"AND substr(m.date,1,4)=?":"";
  const args=period==="year"?[id,year]:[id];
  const games=db.prepare(`SELECT COUNT(*) n FROM attendance a JOIN matches m ON m.id=a.match_id WHERE a.player_id=? AND a.present=1 AND m.status='played' ${date}`).get(...args).n;
  const goals=db.prepare(`SELECT COUNT(*) n FROM match_events e JOIN matches m ON m.id=e.match_id WHERE e.player_id=? AND e.type='goal' AND m.status='played' ${date}`).get(...args).n;
  const assists=db.prepare(`SELECT COUNT(*) n FROM match_events e JOIN matches m ON m.id=e.match_id WHERE e.player_id=? AND e.type='assist' AND m.status='played' ${date}`).get(...args).n;
  return {...p,games,goals,assists};
 }); res.json(result.filter(Boolean));
});
app.get("/api/next-match",(req,res)=>res.json(db.prepare("SELECT * FROM matches WHERE status='scheduled' AND date>=date('now') ORDER BY date,time LIMIT 1").get()||null));
app.get("/api/admin/players",auth,allow("admin","coach"),(req,res)=>res.json(db.prepare("SELECT p.*,u.username FROM players p LEFT JOIN users u ON u.player_id=p.id WHERE p.active=1 ORDER BY p.number,p.name").all()));
app.delete("/api/players/:id",auth,allow("admin","coach"),(req,res)=>{db.prepare("UPDATE players SET active=0 WHERE id=?").run(req.params.id);res.json({ok:true});});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Arsenal FUT7 rodando em http://localhost:${PORT}`));
