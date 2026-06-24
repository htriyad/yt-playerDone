import { Hono } from "hono";
import { cors } from "hono/cors";

/* ── Env ───────────────────────────────────────────── */
interface Env {
  DB: D1Database;
  ADMIN_USER: string;
  ADMIN_PASS: string;
  SESSION_SECRET: string;
}

const app = new Hono<{ Bindings: Env }>();

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
  allowHeaders: ["Content-Type","Authorization","X-Admin-Token","X-User-Token"],
}));

/* ── D1 key-value store ─────────────────────────────── */
async function rd<T>(db: D1Database, key: string, def: T): Promise<T> {
  const row = await db.prepare("SELECT value FROM kv_store WHERE key=?").bind(key).first<{value:string}>();
  if (!row) return def;
  try { return JSON.parse(row.value) as T; } catch { return def; }
}
async function wr(db: D1Database, key: string, data: unknown): Promise<void> {
  await db.prepare("INSERT INTO kv_store(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at")
    .bind(key, JSON.stringify(data), Date.now()).run();
}

/* ── HMAC admin tokens ──────────────────────────────── */
async function makeAdminToken(secret: string): Promise<string> {
  const ts = Date.now().toString();
  const key = await crypto.subtle.importKey("raw", enc(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc(ts));
  return `${ts}.${hex(sig)}`;
}
async function verifyAdminToken(token: string, secret: string): Promise<boolean> {
  const dot = token.lastIndexOf(".");
  if (dot === -1) return false;
  const ts = token.slice(0, dot), sig = token.slice(dot+1);
  const key = await crypto.subtle.importKey("raw", enc(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const expected = await crypto.subtle.sign("HMAC", key, enc(ts));
  return sig === hex(expected);
}
const enc = (s: string) => new TextEncoder().encode(s);
const hex = (buf: ArrayBuffer) => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");

/* ── Session helpers ────────────────────────────────── */
async function sessionGet(db: D1Database, token: string): Promise<string|null> {
  const row = await db.prepare("SELECT username FROM sessions WHERE token=?").bind(token).first<{username:string}>();
  return row?.username ?? null;
}
async function sessionSet(db: D1Database, token: string, username: string): Promise<void> {
  await db.prepare("INSERT OR REPLACE INTO sessions(token,username,created_at) VALUES(?,?,?)").bind(token,username,Date.now()).run();
}
async function sessionDelete(db: D1Database, token: string): Promise<void> {
  await db.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();
}
async function sessionDeleteByUser(db: D1Database, username: string): Promise<void> {
  await db.prepare("DELETE FROM sessions WHERE username=?").bind(username).run();
}

/* ── Types ──────────────────────────────────────────── */
interface IpEntry { approvedAt?: string; name?: string; banned?: boolean; addedAt?: string }
interface IpMap { [ip: string]: IpEntry }
interface Video { id:string; videoId:string; title:string; subjectId:string; chapterId?:string; desc:string; date:string; course:string; online:boolean }
interface Chapter { id:string; name:string; order?:number }
interface Subject { id:string; name:string; course:string; color?:string; chapters:Chapter[]; createdAt:string; password?:string }
interface JoinedMember { id:string; name:string; ip:string; joinedAt:string; deviceInfo?:string }
interface AccessGate { live:boolean; codes:string[] }
interface Message { id:string; ip:string; fullName?:string; message:string; timestamp:string; status:"pending"|"noted"; type?:string; alertType?:string; subject?:string; deviceInfo?:any }
interface UniversalUser { id:string; username:string; password:string; note?:string; createdAt:string; banned?:boolean; universalAccess?:boolean; firstLoginDevice?:string; firstLoginAt?:string }
interface Quiz { id:string; title:string; desc:string; timeMinutes:number; published:boolean; createdAt:string; questions:any[] }
interface Notification { id:string; title:string; body:string; createdAt:string; recipients?:string[]; readBy?:string[]; toUser?:string; read?:boolean }
interface DashMenuItem { id:string; label:string; icon:string; bg:string; chevron:string; path:string; order:number; enabled:boolean }
interface FlashDeck { id:string; name:string; subject:string; description:string; createdAt:string }
interface FlashCard { id:string; deckId:string; front:string; back:string; hint?:string; order:number }
interface DoubtQuestion { id:string; ip:string; username?:string; fullName?:string; question:string; audioData?:string; imageData?:string; pdfData?:string; pdfName?:string; links?:string[]; subject?:string; timestamp:string; status:"open"|"answered"; reply?:any }

/* ── Helpers ────────────────────────────────────────── */
function clientIp(req: Request): string {
  return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For")?.split(",")[0].trim() || "unknown";
}
function getUserToken(req: Request): string|null {
  const auth = req.headers.get("authorization") || req.headers.get("x-user-token");
  if (!auth) return null;
  return auth.replace("Bearer ","").trim() || null;
}
async function getLoggedInUser(db: D1Database, req: Request): Promise<UniversalUser|null> {
  const token = getUserToken(req);
  if (!token) return null;
  const username = await sessionGet(db, token);
  if (!username) return null;
  const users = await rd<UniversalUser[]>(db, "users.json", []);
  return users.find(u => u.username === username) || null;
}
async function isAllowed(db: D1Database, req: Request): Promise<boolean> {
  const ip = clientIp(req);
  const ips = await rd<IpMap>(db, "ips.json", {});
  if (ips[ip]?.banned) return false;
  const token = getUserToken(req);
  if (token) {
    const username = await sessionGet(db, token);
    if (username) {
      const users = await rd<UniversalUser[]>(db, "users.json", []);
      const user = users.find(u => u.username === username);
      if (user?.banned) return false;
      return true;
    }
  }
  if (ip in ips) return true;
  if (ip === "127.0.0.1" || ip === "::1") return true;
  return false;
}

/* ── Middleware factories ────────────────────────────── */
function adminAuthMiddleware() {
  return async (c: any, next: any) => {
    const token = c.req.header("authorization")?.replace("Bearer ","") || c.req.header("x-admin-token");
    if (!token || !await verifyAdminToken(token, c.env.SESSION_SECRET)) return c.json({error:"Unauthorized"},401);
    await next();
  };
}
function userAuthMiddleware() {
  return async (c: any, next: any) => {
    const allowed = await isAllowed(c.env.DB, c.req.raw);
    if (!allowed) return c.json({error:"Access denied"},403);
    await next();
  };
}

/* ── Seed defaults if missing ───────────────────────── */
async function seedDefaults(db: D1Database) {
  const [ips,gate,subjects,vids,settings,dashmenu] = await Promise.all([
    rd(db,"ips.json",null), rd(db,"access-gate.json",null), rd(db,"subjects.json",null),
    rd(db,"vids.json",null), rd(db,"settings.json",null), rd(db,"dashmenu.json",null),
  ]);
  const jobs: Promise<void>[] = [];
  if (!ips) jobs.push(wr(db,"ips.json",{}));
  if (!gate) jobs.push(wr(db,"access-gate.json",{live:false,codes:[]}));
  if (!settings) jobs.push(wr(db,"settings.json",{universalSite:false,universalFree:false}));
  if (!subjects) jobs.push(wr(db,"subjects.json",[
    {id:"sub-physics",name:"Physics",course:"HSC Science",color:"#7c3aed",chapters:[{id:"ch-p1",name:"Mechanics",order:1},{id:"ch-p2",name:"Thermodynamics",order:2}],createdAt:new Date().toISOString()},
    {id:"sub-math",name:"Mathematics",course:"HSC Math",color:"#2563eb",chapters:[{id:"ch-m1",name:"Algebra",order:1},{id:"ch-m2",name:"Calculus",order:2}],createdAt:new Date().toISOString()},
  ]));
  if (!vids) jobs.push(wr(db,"vids.json",[
    {id:"1",videoId:"O6HL1Q3MCrM",title:"Chapter 1: Introduction to Physics",subjectId:"sub-physics",desc:"Newton's Laws of Motion",date:"19 Nov, 2025 08:00 PM",course:"HSC Science",online:true},
    {id:"2",videoId:"dQw4w9WgXcQ",title:"Chapter 2: Thermodynamics",subjectId:"sub-physics",desc:"Heat & Temperature",date:"22 Nov, 2025 09:00 AM",course:"HSC Science",online:true},
  ]));
  if (!dashmenu) jobs.push(wr(db,"dashmenu.json",[
    {id:"m1",label:"AI Tutor",icon:"🤖",bg:"#ede9fe",chevron:"#7c3aed",path:"/ai-tutor",order:1,enabled:true},
    {id:"m2",label:"Past Classes",icon:"🎬",bg:"#fff3e0",chevron:"#e65100",path:"/past-classes",order:2,enabled:true},
    {id:"m3",label:"Live Exam",icon:"📝",bg:"#e3f2fd",chevron:"#2e7d32",path:"/exams",order:3,enabled:true},
    {id:"m4",label:"My Progress",icon:"🏆",bg:"#fef3c7",chevron:"#d97706",path:"/profile",order:5,enabled:true},
    {id:"m5",label:"Live Class",icon:"👨‍🏫",bg:"#e8f5e9",chevron:"#e53935",path:"/",order:7,enabled:true},
    {id:"m6",label:"Q&A Service",icon:"💬",bg:"#e0f7fa",chevron:"#2e7d32",path:"/ask",order:9,enabled:true},
    {id:"m7",label:"Course & Content",icon:"📚",bg:"#fce4ec",chevron:"#e65100",path:"/",order:10,enabled:true},
  ]));
  await Promise.all(jobs);
}

/* ══════════════════════════════════════════════════════
   ROUTES
══════════════════════════════════════════════════════ */

/* health */
app.get("/api/healthz", c => c.json({status:"ok"}));

/* ── Access gate ── */
app.get("/api/access-code/status", async c => {
  const gate = await rd<AccessGate>(c.env.DB,"access-gate.json",{live:false,codes:[]});
  return c.json({live:gate.live});
});

app.post("/api/access-code/validate", async c => {
  const {code,deviceInfo} = await c.req.json<any>();
  if (!code) return c.json({ok:false,error:"No code provided"},400);
  const gate = await rd<AccessGate>(c.env.DB,"access-gate.json",{live:false,codes:[]});
  if (!gate.live) return c.json({ok:false,error:"Access is currently closed"},403);
  if (!gate.codes.includes(String(code).trim())) return c.json({ok:false,error:"Invalid access code"},403);
  const ip = clientIp(c.req.raw);
  const ips = await rd<IpMap>(c.env.DB,"ips.json",{});
  if (!ips[ip]) {
    ips[ip] = {name:String(code).trim(),addedAt:new Date().toISOString()};
    await wr(c.env.DB,"ips.json",ips);
  }
  const members = await rd<JoinedMember[]>(c.env.DB,"members.json",[]);
  if (!members.find(m=>m.ip===ip)) {
    members.push({id:crypto.randomUUID(),name:String(code).trim(),ip,joinedAt:new Date().toISOString(),deviceInfo:deviceInfo?JSON.stringify(deviceInfo):undefined});
    await wr(c.env.DB,"members.json",members);
  }
  return c.json({ok:true});
});

/* ── check-ip ── */
app.get("/api/check-ip", async c => {
  const ip = clientIp(c.req.raw);
  const token = getUserToken(c.req.raw);
  const [ips,settings] = await Promise.all([rd<IpMap>(c.env.DB,"ips.json",{}),rd<any>(c.env.DB,"settings.json",{universalSite:false,universalFree:false})]);
  if (settings.universalSite) return c.json({allowed:true,ip,universalSite:true});
  if (ips[ip]?.banned) return c.json({allowed:false,ip,banned:true});
  if (token) {
    const username = await sessionGet(c.env.DB,token);
    if (username) {
      const users = await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
      const user = users.find(u=>u.username===username);
      if (user?.banned) return c.json({allowed:false,ip,banned:true,userBanned:true});
      return c.json({allowed:true,ip,universalUser:true,username:user?.username||null,universalAccess:user?.universalAccess||false,name:user?.note||null});
    }
  }
  const ipOk = ip in ips || ip==="127.0.0.1" || ip==="::1";
  if (!ipOk) return c.json({allowed:false,ip});
  return c.json({allowed:true,ip,universalUser:false,username:null,name:ips[ip]?.name||null});
});

/* ── Public message (access request) ── */
app.post("/api/message", async c => {
  const ip = clientIp(c.req.raw);
  const {fullName,message,deviceInfo} = await c.req.json<any>();
  if (!fullName?.trim()) return c.json({error:"Full name is required"},400);
  const [ips,msgs] = await Promise.all([rd<IpMap>(c.env.DB,"ips.json",{}),rd<Message[]>(c.env.DB,"msgs.json",[])]);
  if (ips[ip]?.banned) return c.json({error:"Your access has been permanently blocked."},403);
  const oneWeekAgo = Date.now()-7*24*60*60*1000;
  const recent = msgs.filter(m=>m.ip===ip&&m.type==="access-request"&&new Date(m.timestamp).getTime()>oneWeekAgo);
  if (recent.length>=2) return c.json({error:"You have already sent 2 requests this week."},429);
  msgs.push({id:crypto.randomUUID(),ip,fullName:fullName.trim(),message:message?.trim()||"",timestamp:new Date().toISOString(),status:"pending",type:"access-request",deviceInfo:deviceInfo||undefined});
  await wr(c.env.DB,"msgs.json",msgs);
  return c.json({ok:true});
});

/* ── Security alert ── */
app.post("/api/security/alert", async c => {
  const ip = clientIp(c.req.raw);
  const {alertType,details,username} = await c.req.json<any>().catch(()=>({}));
  const msgs = await rd<Message[]>(c.env.DB,"msgs.json",[]);
  const label = alertType==="devtools"?"🛠️ DevTools Opened":alertType==="extension"?"🧩 Browser Extension":alertType==="view-source"?"📄 View Source Attempt":"🚨 Security Alert";
  msgs.push({id:crypto.randomUUID(),ip,message:`${label}\n${username?`User: @${username}\n`:""}${details?`Details: ${JSON.stringify(details)}`:""}`,timestamp:new Date().toISOString(),status:"pending",type:"security-alert",alertType});
  await wr(c.env.DB,"msgs.json",msgs);
  return c.json({ok:true});
});

/* ── Subjects (public) ── */
app.get("/api/subjects", async c => {
  const settings = await rd<any>(c.env.DB,"settings.json",{universalSite:false,universalFree:false});
  if (!settings.universalFree && !settings.universalSite && !await isAllowed(c.env.DB,c.req.raw)) return c.json({error:"Access denied"},403);
  const subjects = await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  return c.json(subjects.map(({password:_pw,...s})=>({...s,locked:!!_pw})));
});

app.post("/api/subjects/:id/unlock", async c => {
  const settings = await rd<any>(c.env.DB,"settings.json",{universalSite:false,universalFree:false});
  if (!settings.universalFree && !settings.universalSite && !await isAllowed(c.env.DB,c.req.raw)) return c.json({error:"Access denied"},403);
  const {password} = await c.req.json<any>();
  const subjects = await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const subj = subjects.find(s=>s.id===c.req.param("id"));
  if (!subj) return c.json({error:"Subject not found"},404);
  if (!subj.password) return c.json({ok:true});
  if (subj.password!==password) return c.json({ok:false,error:"Wrong password"},403);
  return c.json({ok:true});
});

/* ── Videos (public) ── */
app.get("/api/videos", async c => {
  const settings = await rd<any>(c.env.DB,"settings.json",{universalSite:false,universalFree:false});
  if (!settings.universalFree && !settings.universalSite && !await isAllowed(c.env.DB,c.req.raw)) return c.json({error:"Access denied"},403);
  return c.json(await rd<Video[]>(c.env.DB,"vids.json",[]));
});

/* ── User auth ── */
app.post("/api/user/login", async c => {
  const {username,password,deviceFingerprint} = await c.req.json<any>();
  if (!username||!password) return c.json({error:"username and password required"},400);
  const users = await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const user = users.find(u=>u.username===username&&u.password===password);
  if (!user) return c.json({error:"Invalid username or password"},401);
  if (user.banned) return c.json({error:"Your account has been permanently banned. Contact admin."},403);
  if (deviceFingerprint) {
    if (!user.firstLoginDevice) {
      const i = users.findIndex(u=>u.id===user.id);
      users[i].firstLoginDevice = deviceFingerprint; users[i].firstLoginAt = new Date().toISOString();
      await wr(c.env.DB,"users.json",users);
    } else if (user.firstLoginDevice!==deviceFingerprint) {
      return c.json({error:"This account is already bound to another device. Contact admin to reset your device.",deviceLocked:true},403);
    }
  }
  const token = crypto.randomUUID();
  await sessionSet(c.env.DB,token,user.username);
  return c.json({token,username:user.username,universalAccess:user.universalAccess||false});
});

app.post("/api/user/logout", async c => {
  const token = getUserToken(c.req.raw);
  if (token) await sessionDelete(c.env.DB,token);
  return c.json({ok:true});
});

app.post("/api/user/register", async c => {
  const {username,password} = await c.req.json<any>();
  if (!username||!password) return c.json({error:"username and password required"},400);
  const uname = String(username).trim().toLowerCase().replace(/[^a-z0-9_]/g,"");
  if (uname.length<3) return c.json({error:"Username must be at least 3 characters"},400);
  if (String(password).length<6) return c.json({error:"Password must be at least 6 characters"},400);
  const users = await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  if (users.find(u=>u.username===uname)) return c.json({error:"Username already taken"},409);
  const newUser: UniversalUser = {id:crypto.randomUUID(),username:uname,password:String(password),createdAt:new Date().toISOString(),universalAccess:false,banned:false};
  users.push(newUser); await wr(c.env.DB,"users.json",users);
  const token = crypto.randomUUID();
  await sessionSet(c.env.DB,token,uname);
  return c.json({token,username:uname,universalAccess:false});
});

app.get("/api/validate-token", async c => {
  const token = getUserToken(c.req.raw);
  if (!token) return c.json({valid:false});
  const username = await sessionGet(c.env.DB,token);
  if (!username) return c.json({valid:false});
  const users = await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const user = users.find(u=>u.username===username);
  if (user?.banned) { await sessionDelete(c.env.DB,token); return c.json({valid:false,banned:true}); }
  return c.json({valid:true,username,universalAccess:user?.universalAccess||false});
});

/* ── Notifications (user) ── */
app.get("/api/notifications", userAuthMiddleware(), async c => {
  const token = getUserToken(c.req.raw);
  const username = token ? await sessionGet(c.env.DB,token) : null;
  const all = await rd<Notification[]>(c.env.DB,"notifs.json",[]);
  const visible = all.filter((n:any)=>{
    if (n.toUser) return n.toUser===username;
    const r=n.recipients; if(!r||r.length===0) return true;
    return username?r.includes(username):false;
  }).map((n:any)=>({...n,read:username?(n.read===true||!!(n.readBy?.includes(username))):false,createdAt:n.createdAt||new Date().toISOString(),title:n.title||(n.fromUser?`From @${n.fromUser}`:"Notification"),body:n.body||n.text||""}));
  return c.json(visible.slice(0,150));
});

app.post("/api/notifications/:id/read", userAuthMiddleware(), async c => {
  const token = getUserToken(c.req.raw);
  const username = token ? await sessionGet(c.env.DB,token) : null;
  if (!username) return c.json({ok:true});
  const all = await rd<Notification[]>(c.env.DB,"notifs.json",[]);
  const n = all.find((x:any)=>x.id===c.req.param("id"));
  if (!n) return c.json({error:"Not found"},404);
  (n as any).readBy = (n as any).readBy||[]; if (!(n as any).readBy.includes(username)) (n as any).readBy.push(username);
  (n as any).read = true; await wr(c.env.DB,"notifs.json",all);
  return c.json({ok:true});
});

app.post("/api/notifications/read-all", userAuthMiddleware(), async c => {
  const token = getUserToken(c.req.raw);
  const username = token ? await sessionGet(c.env.DB,token) : null;
  if (!username) return c.json({ok:true});
  const all = await rd<any[]>(c.env.DB,"notifs.json",[]);
  for (const n of all) {
    if (n.toUser) { if(n.toUser===username){n.read=true;} continue; }
    const r=n.recipients; const visible=!r||r.length===0||r.includes(username); if(!visible) continue;
    n.readBy=n.readBy||[]; if(!n.readBy.includes(username)) n.readBy.push(username); n.read=true;
  }
  await wr(c.env.DB,"notifs.json",all);
  return c.json({ok:true});
});

/* ── Dashboard menu ── */
app.get("/api/dashboard-menu", userAuthMiddleware(), async c => {
  const items = await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[]);
  return c.json(items.filter(i=>i.enabled).sort((a,b)=>a.order-b.order));
});

/* ── Quizzes (student) ── */
app.get("/api/quizzes", userAuthMiddleware(), async c => {
  const all = await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  return c.json(all.filter(q=>q.published).map(q=>({id:q.id,title:q.title,desc:q.desc,timeMinutes:q.timeMinutes,createdAt:q.createdAt,questionCount:q.questions.length})));
});
app.get("/api/quizzes/:id", userAuthMiddleware(), async c => {
  const all = await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  const quiz = all.find(q=>q.id===c.req.param("id")&&q.published);
  if (!quiz) return c.json({error:"Not found"},404);
  return c.json({id:quiz.id,title:quiz.title,desc:quiz.desc,timeMinutes:quiz.timeMinutes,questions:quiz.questions.map((q:any)=>({id:q.id,text:q.text,options:q.options}))});
});
app.post("/api/quiz-submit", userAuthMiddleware(), async c => {
  const {quizId,answers} = await c.req.json<any>();
  const all = await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  const quiz = all.find(q=>q.id===quizId);
  if (!quiz) return c.json({error:"Quiz not found"},404);
  let correct=0;
  const results = quiz.questions.map((q:any)=>{const chosen=answers[q.id]||null;const isRight=chosen===q.correct;if(isRight)correct++;return{id:q.id,text:q.text,options:q.options,chosen,correct:q.correct,isRight,solution:q.solution};});
  return c.json({score:correct,total:quiz.questions.length,results});
});

/* ── Doubts (student) ── */
app.post("/api/doubts", userAuthMiddleware(), async c => {
  const ip = clientIp(c.req.raw);
  const {question,audioData,imageData,fullName,pdfData,pdfName,links,subject} = await c.req.json<any>();
  if (!question?.trim()&&!audioData) return c.json({error:"question or audio required"},400);
  const username = (await getLoggedInUser(c.env.DB,c.req.raw))?.username;
  const doubts = await rd<DoubtQuestion[]>(c.env.DB,"doubts.json",[]);
  const item: DoubtQuestion = {id:crypto.randomUUID(),ip,username,fullName:String(fullName||username||"Student").slice(0,100),question:String(question||"").slice(0,3000),audioData:audioData?String(audioData).slice(0,8_000_000):undefined,imageData:imageData?String(imageData).slice(0,8_000_000):undefined,pdfData:pdfData?String(pdfData).slice(0,10_000_000):undefined,pdfName:pdfName?String(pdfName).slice(0,200):undefined,links:Array.isArray(links)?links.slice(0,10).map((l:string)=>String(l).slice(0,500)):undefined,subject:subject?String(subject).slice(0,80):undefined,timestamp:new Date().toISOString(),status:"open"};
  doubts.unshift(item);
  const notifs = await rd<Notification[]>(c.env.DB,"notifs.json",[]);
  notifs.unshift({id:crypto.randomUUID(),title:"❓ New Student Question",body:`${item.fullName} asked: ${(item.question||"Voice question").slice(0,90)}`,createdAt:new Date().toISOString(),recipients:[c.env.ADMIN_USER],readBy:[]});
  await Promise.all([wr(c.env.DB,"doubts.json",doubts.slice(0,500)),wr(c.env.DB,"notifs.json",notifs.slice(0,300))]);
  return c.json({ok:true,id:item.id});
});

app.get("/api/doubts/my", userAuthMiddleware(), async c => {
  const user = await getLoggedInUser(c.env.DB,c.req.raw);
  const ip = clientIp(c.req.raw);
  const doubts = await rd<DoubtQuestion[]>(c.env.DB,"doubts.json",[]);
  return c.json(doubts.filter(d=>d.username===user?.username||d.ip===ip));
});

/* ── Flashcard decks (student) ── */
app.get("/api/flashcard-decks", userAuthMiddleware(), async c => {
  const [decks,cards] = await Promise.all([rd<FlashDeck[]>(c.env.DB,"flashdecks.json",[]),rd<FlashCard[]>(c.env.DB,"flashcards.json",[])]);
  return c.json(decks.map(d=>({...d,cardCount:cards.filter(c2=>c2.deckId===d.id).length})));
});
app.get("/api/flashcard-decks/:id/cards", userAuthMiddleware(), async c => {
  const cards = (await rd<FlashCard[]>(c.env.DB,"flashcards.json",[])).filter(c2=>c2.deckId===c.req.param("id"));
  return c.json(cards.sort((a,b)=>a.order-b.order));
});

/* ── Content request ── */
app.post("/api/content-request", userAuthMiddleware(), async c => {
  const ip = clientIp(c.req.raw);
  const token = getUserToken(c.req.raw);
  const username = token ? await sessionGet(c.env.DB,token) : null;
  const {subject,message} = await c.req.json<any>();
  if (!subject) return c.json({error:"subject required"},400);
  const msgs = await rd<Message[]>(c.env.DB,"msgs.json",[]);
  const oneWeekAgo = Date.now()-7*24*60*60*1000;
  const recent = msgs.filter(m=>(m.ip===ip)&&m.type==="content-request"&&new Date(m.timestamp).getTime()>oneWeekAgo);
  if (recent.length>=2) return c.json({error:"You have already sent 2 content requests this week."},429);
  const body=`📚 Course Access Request\nSubject: ${subject}\n${username?`Student: @${username}\n`:""}${message?`Message: ${message}`:""}`;
  msgs.push({id:crypto.randomUUID(),ip,message:body,timestamp:new Date().toISOString(),status:"pending",type:"content-request",subject});
  await wr(c.env.DB,"msgs.json",msgs);
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN LOGIN
══════════════════════════════════════════════════════ */
app.post("/api/admin/login", async c => {
  const {username,password} = await c.req.json<any>();
  if (username===c.env.ADMIN_USER && password===c.env.ADMIN_PASS) {
    return c.json({token: await makeAdminToken(c.env.SESSION_SECRET)});
  }
  return c.json({error:"Invalid credentials"},401);
});

/* ══════════════════════════════════════════════════════
   ADMIN — SETTINGS
══════════════════════════════════════════════════════ */
app.get("/api/admin/settings", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"settings.json",{universalSite:false,universalFree:false})));
app.patch("/api/admin/settings", adminAuthMiddleware(), async c => {
  const current = await rd<any>(c.env.DB,"settings.json",{universalSite:false,universalFree:false});
  const {universalSite,universalFree} = await c.req.json<any>();
  if (typeof universalSite==="boolean") current.universalSite=universalSite;
  if (typeof universalFree==="boolean") current.universalFree=universalFree;
  await wr(c.env.DB,"settings.json",current);
  return c.json(current);
});

/* ══════════════════════════════════════════════════════
   ADMIN — ACCESS GATE
══════════════════════════════════════════════════════ */
app.get("/api/admin/access-gate", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"access-gate.json",{live:false,codes:[]})));

app.post("/api/admin/access-gate/toggle", adminAuthMiddleware(), async c => {
  const gate = await rd<AccessGate>(c.env.DB,"access-gate.json",{live:false,codes:[]});
  gate.live=!gate.live; await wr(c.env.DB,"access-gate.json",gate);
  return c.json(gate);
});

app.post("/api/admin/access-gate/codes", adminAuthMiddleware(), async c => {
  const {action,code} = await c.req.json<any>();
  if (!code||!code.trim()) return c.json({error:"Invalid code"},400);
  const gate = await rd<AccessGate>(c.env.DB,"access-gate.json",{live:false,codes:[]});
  const trimmed=code.trim();
  if (action==="add") { if(!gate.codes.includes(trimmed)) gate.codes.push(trimmed); }
  else if (action==="remove") { gate.codes=gate.codes.filter((c2:string)=>c2!==trimmed); }
  else return c.json({error:"action must be add or remove"},400);
  await wr(c.env.DB,"access-gate.json",gate);
  return c.json(gate);
});

/* ══════════════════════════════════════════════════════
   ADMIN — MEMBERS
══════════════════════════════════════════════════════ */
app.get("/api/admin/members", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"members.json",[])));

app.delete("/api/admin/members/:id", adminAuthMiddleware(), async c => {
  const members = await rd<JoinedMember[]>(c.env.DB,"members.json",[]);
  const member = members.find(m=>m.id===c.req.param("id"));
  if (!member) return c.json({error:"Member not found"},404);
  const ips = await rd<IpMap>(c.env.DB,"ips.json",{});
  if (ips[member.ip]) { delete ips[member.ip]; }
  await Promise.all([wr(c.env.DB,"members.json",members.filter(m=>m.id!==c.req.param("id"))),wr(c.env.DB,"ips.json",ips)]);
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — IPs
══════════════════════════════════════════════════════ */
app.get("/api/admin/ips", adminAuthMiddleware(), async c => {
  const ips=await rd<IpMap>(c.env.DB,"ips.json",{});
  return c.json(Object.entries(ips).map(([ip,v])=>({ip,...v})));
});
app.post("/api/admin/ips", adminAuthMiddleware(), async c => {
  const {ip,name}=await c.req.json<any>();
  if (!ip) return c.json({error:"ip required"},400);
  const ips=await rd<IpMap>(c.env.DB,"ips.json",{});
  ips[ip.trim()]={approvedAt:new Date().toISOString(),name:name||undefined};
  await wr(c.env.DB,"ips.json",ips); return c.json({ok:true});
});
app.patch("/api/admin/ips/:ip/ban", adminAuthMiddleware(), async c => {
  const ipKey=decodeURIComponent(c.req.param("ip"));
  const ips=await rd<IpMap>(c.env.DB,"ips.json",{});
  if (!ips[ipKey]) ips[ipKey]={approvedAt:new Date().toISOString()};
  ips[ipKey].banned=!ips[ipKey].banned;
  await wr(c.env.DB,"ips.json",ips); return c.json({ok:true,banned:ips[ipKey].banned});
});
app.delete("/api/admin/ips/:ip", adminAuthMiddleware(), async c => {
  const ips=await rd<IpMap>(c.env.DB,"ips.json",{});
  delete ips[decodeURIComponent(c.req.param("ip"))];
  await wr(c.env.DB,"ips.json",ips); return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — MESSAGES / INBOX
══════════════════════════════════════════════════════ */
app.get("/api/admin/msgs", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"msgs.json",[])));
app.patch("/api/admin/msgs/:id", adminAuthMiddleware(), async c => {
  const msgs=await rd<Message[]>(c.env.DB,"msgs.json",[]);
  const i=msgs.findIndex(m=>m.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  msgs[i].status="noted"; await wr(c.env.DB,"msgs.json",msgs); return c.json({ok:true});
});
app.delete("/api/admin/msgs/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"msgs.json",(await rd<Message[]>(c.env.DB,"msgs.json",[])).filter(m=>m.id!==c.req.param("id")));
  return c.json({ok:true});
});
app.post("/api/admin/msgs/:id/approve-ip", adminAuthMiddleware(), async c => {
  const msgs=await rd<Message[]>(c.env.DB,"msgs.json",[]);
  const msg=msgs.find(m=>m.id===c.req.param("id")); if(!msg) return c.json({error:"Message not found"},404);
  const ips=await rd<IpMap>(c.env.DB,"ips.json",{});
  ips[msg.ip]={approvedAt:new Date().toISOString(),name:msg.fullName||undefined};
  const i=msgs.findIndex(m=>m.id===c.req.param("id")); if(i!==-1){msgs[i].status="noted";}
  await Promise.all([wr(c.env.DB,"ips.json",ips),wr(c.env.DB,"msgs.json",msgs)]);
  return c.json({ok:true,ip:msg.ip,name:msg.fullName});
});
app.post("/api/admin/msgs/:id/quick-user", adminAuthMiddleware(), async c => {
  const {username,password,note}=await c.req.json<any>();
  if (!username||!password) return c.json({error:"username and password required"},400);
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  if (users.find(u=>u.username===username)) return c.json({error:"Username already exists"},400);
  const user: UniversalUser={id:crypto.randomUUID(),username:username.trim(),password,note:note||"",createdAt:new Date().toISOString()};
  users.push(user);
  const msgs=await rd<Message[]>(c.env.DB,"msgs.json",[]);
  const i=msgs.findIndex(m=>m.id===c.req.param("id")); if(i!==-1){msgs[i].status="noted";}
  await Promise.all([wr(c.env.DB,"users.json",users),wr(c.env.DB,"msgs.json",msgs)]);
  return c.json({id:user.id,username:user.username,createdAt:user.createdAt});
});

/* ══════════════════════════════════════════════════════
   ADMIN — UNIVERSAL USERS
══════════════════════════════════════════════════════ */
app.get("/api/admin/users", adminAuthMiddleware(), async c => {
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  return c.json(users.map(u=>({id:u.id,username:u.username,note:u.note,createdAt:u.createdAt,banned:u.banned||false,universalAccess:u.universalAccess||false,firstLoginDevice:u.firstLoginDevice?"set":null,firstLoginAt:u.firstLoginAt||null})));
});
app.post("/api/admin/users", adminAuthMiddleware(), async c => {
  const {username,password,note,universalAccess}=await c.req.json<any>();
  if (!username||!password) return c.json({error:"username and password required"},400);
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  if (users.find(u=>u.username===username)) return c.json({error:"Username already exists"},400);
  const user: UniversalUser={id:crypto.randomUUID(),username:username.trim(),password,note:note||"",createdAt:new Date().toISOString(),universalAccess:!!universalAccess};
  users.push(user); await wr(c.env.DB,"users.json",users);
  return c.json({id:user.id,username:user.username,createdAt:user.createdAt});
});
app.delete("/api/admin/users/:id", adminAuthMiddleware(), async c => {
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const target=users.find(u=>u.id===c.req.param("id"));
  if (target) await sessionDeleteByUser(c.env.DB,target.username);
  await wr(c.env.DB,"users.json",users.filter(u=>u.id!==c.req.param("id")));
  return c.json({ok:true});
});
app.patch("/api/admin/users/:id/password", adminAuthMiddleware(), async c => {
  const {password}=await c.req.json<any>(); if(!password) return c.json({error:"password required"},400);
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const i=users.findIndex(u=>u.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  users[i].password=password; await wr(c.env.DB,"users.json",users); return c.json({ok:true});
});
app.patch("/api/admin/users/:id/ban", adminAuthMiddleware(), async c => {
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const i=users.findIndex(u=>u.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  users[i].banned=!users[i].banned;
  if (users[i].banned) await sessionDeleteByUser(c.env.DB,users[i].username);
  await wr(c.env.DB,"users.json",users); return c.json({ok:true,banned:users[i].banned});
});
app.patch("/api/admin/users/:id/universal-access", adminAuthMiddleware(), async c => {
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const i=users.findIndex(u=>u.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  users[i].universalAccess=!users[i].universalAccess;
  await wr(c.env.DB,"users.json",users); return c.json({ok:true,universalAccess:users[i].universalAccess});
});
app.patch("/api/admin/users/:id/reset-device", adminAuthMiddleware(), async c => {
  const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]);
  const i=users.findIndex(u=>u.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  delete users[i].firstLoginDevice; delete users[i].firstLoginAt;
  await wr(c.env.DB,"users.json",users); return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — VIDEOS
══════════════════════════════════════════════════════ */
app.get("/api/admin/videos", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"vids.json",[])));
app.post("/api/admin/videos", adminAuthMiddleware(), async c => {
  const {videoId,title,subjectId,desc,date,course,online}=await c.req.json<any>();
  if (!videoId||!title) return c.json({error:"videoId and title required"},400);
  const vids=await rd<Video[]>(c.env.DB,"vids.json",[]);
  const vid: Video={id:crypto.randomUUID(),videoId,title,subjectId:subjectId||"",desc:desc||"",date:date||"",course:course||"",online:!!online};
  vids.unshift(vid); await wr(c.env.DB,"vids.json",vids); return c.json(vid);
});
app.put("/api/admin/videos/:id", adminAuthMiddleware(), async c => {
  const vids=await rd<Video[]>(c.env.DB,"vids.json",[]);
  const i=vids.findIndex(v=>v.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  vids[i]={...vids[i],...await c.req.json<any>(),id:vids[i].id};
  await wr(c.env.DB,"vids.json",vids); return c.json(vids[i]);
});
app.delete("/api/admin/videos/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"vids.json",(await rd<Video[]>(c.env.DB,"vids.json",[])).filter(v=>v.id!==c.req.param("id")));
  return c.json({ok:true});
});
app.post("/api/admin/videos/bulk", adminAuthMiddleware(), async c => {
  const {videos,subjectId,chapterId,course,online}=await c.req.json<any>();
  if (!Array.isArray(videos)||videos.length===0) return c.json({error:"videos[] required"},400);
  const list=await rd<Video[]>(c.env.DB,"vids.json",[]);
  const existing=new Set(list.map(v=>v.videoId));
  const created: Video[]=[]; let added=0;
  for (const it of videos) {
    const vid=String(it?.videoId||"").trim(); const title=String(it?.title||"").trim();
    if (!vid||!title||existing.has(vid)) continue;
    created.push({id:crypto.randomUUID(),videoId:vid,title,subjectId:subjectId||"",chapterId:chapterId||undefined,desc:String(it?.desc||it?.duration||"").slice(0,800),date:new Date().toLocaleString(),course:course||"",online:!!online});
    existing.add(vid); added++;
  }
  await wr(c.env.DB,"vids.json",[...created,...list]);
  return c.json({ok:true,total:videos.length,added,skipped:videos.length-added,created});
});
app.post("/api/admin/videos/transfer", adminAuthMiddleware(), async c => {
  const {videoIds,targetSubjectId,targetChapterId}=await c.req.json<any>();
  if (!Array.isArray(videoIds)||!targetSubjectId) return c.json({error:"videoIds[] and targetSubjectId required"},400);
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  if (!subjects.find(s=>s.id===targetSubjectId)) return c.json({error:"Target subject not found"},404);
  const vids=await rd<Video[]>(c.env.DB,"vids.json",[]);
  const ids=new Set(videoIds); let moved=0;
  for (const v of vids) { if(ids.has(v.id)){v.subjectId=targetSubjectId;v.chapterId=targetChapterId||undefined;moved++;} }
  await wr(c.env.DB,"vids.json",vids); return c.json({ok:true,moved});
});

/* ══════════════════════════════════════════════════════
   ADMIN — SUBJECTS & CHAPTERS
══════════════════════════════════════════════════════ */
app.get("/api/admin/subjects", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"subjects.json",[])));
app.post("/api/admin/subjects", adminAuthMiddleware(), async c => {
  const {name,course,color}=await c.req.json<any>();
  if (!name) return c.json({error:"name required"},400);
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const subj: Subject={id:"sub-"+crypto.randomUUID().slice(0,8),name:String(name).trim(),course:String(course||"").trim(),color:color||"#7c3aed",chapters:[],createdAt:new Date().toISOString()};
  subjects.push(subj); await wr(c.env.DB,"subjects.json",subjects); return c.json(subj);
});
app.put("/api/admin/subjects/:id", adminAuthMiddleware(), async c => {
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const i=subjects.findIndex(s=>s.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  const b=await c.req.json<any>();
  subjects[i]={...subjects[i],...(b.name!==undefined?{name:String(b.name).trim()}:{}),...(b.course!==undefined?{course:String(b.course).trim()}:{}),...(b.color!==undefined?{color:String(b.color)}:{}),...(b.password!==undefined?{password:b.password===null||b.password===""?undefined:String(b.password)}:{})};
  await wr(c.env.DB,"subjects.json",subjects); return c.json(subjects[i]);
});
app.delete("/api/admin/subjects/:id", adminAuthMiddleware(), async c => {
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const next=subjects.filter(s=>s.id!==c.req.param("id"));
  if (next.length===subjects.length) return c.json({error:"Not found"},404);
  const vids=await rd<Video[]>(c.env.DB,"vids.json",[]);
  let changed=false;
  for (const v of vids) { if(v.subjectId===c.req.param("id")){v.subjectId="";v.chapterId=undefined;changed=true;} }
  await Promise.all([wr(c.env.DB,"subjects.json",next),...(changed?[wr(c.env.DB,"vids.json",vids)]:[])]); return c.json({ok:true});
});
app.post("/api/admin/subjects/:id/chapters", adminAuthMiddleware(), async c => {
  const {name}=await c.req.json<any>(); if(!name) return c.json({error:"name required"},400);
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const subj=subjects.find(s=>s.id===c.req.param("id")); if(!subj) return c.json({error:"Subject not found"},404);
  const ch: Chapter={id:"ch-"+crypto.randomUUID().slice(0,8),name:String(name).trim(),order:subj.chapters.length+1};
  subj.chapters.push(ch); await wr(c.env.DB,"subjects.json",subjects); return c.json(ch);
});
app.put("/api/admin/subjects/:sid/chapters/:cid", adminAuthMiddleware(), async c => {
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const subj=subjects.find(s=>s.id===c.req.param("sid")); if(!subj) return c.json({error:"Subject not found"},404);
  const ch=subj.chapters.find(c2=>c2.id===c.req.param("cid")); if(!ch) return c.json({error:"Chapter not found"},404);
  const b=await c.req.json<any>(); if(b?.name!==undefined) ch.name=String(b.name).trim(); if(typeof b?.order==="number") ch.order=b.order;
  await wr(c.env.DB,"subjects.json",subjects); return c.json(ch);
});
app.delete("/api/admin/subjects/:sid/chapters/:cid", adminAuthMiddleware(), async c => {
  const subjects=await rd<Subject[]>(c.env.DB,"subjects.json",[]);
  const subj=subjects.find(s=>s.id===c.req.param("sid")); if(!subj) return c.json({error:"Subject not found"},404);
  subj.chapters=subj.chapters.filter(c2=>c2.id!==c.req.param("cid"));
  const vids=await rd<Video[]>(c.env.DB,"vids.json",[]);
  let changed=false;
  for (const v of vids) { if(v.chapterId===c.req.param("cid")){v.chapterId=undefined;changed=true;} }
  await Promise.all([wr(c.env.DB,"subjects.json",subjects),...(changed?[wr(c.env.DB,"vids.json",vids)]:[])]); return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — YOUTUBE PLAYLIST IMPORT
══════════════════════════════════════════════════════ */
function extractPlaylistId(input: string): string|null {
  const s=(input||"").trim(); if(!s) return null;
  try { const u=new URL(s); const list=u.searchParams.get("list"); if(list) return list; } catch {}
  if (/^[A-Za-z0-9_-]{10,}$/.test(s)&&!s.includes("/")) return s;
  const m=s.match(/[?&]list=([A-Za-z0-9_-]+)/); return m?m[1]:null;
}
const YT_BROWSE_URL="https://www.youtube.com/youtubei/v1/browse?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8";
const YT_HEADERS={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36","X-YouTube-Client-Name":"1","X-YouTube-Client-Version":"2.20240101.00.00"};
async function fetchYtPage(pid: string, continuation?: string): Promise<any> {
  const body: any={context:{client:{clientName:"WEB",clientVersion:"2.20240101.00.00",hl:"en",gl:"US"}}};
  if (continuation) body.continuation=continuation; else body.browseId=`VL${pid}`;
  const r=await fetch(YT_BROWSE_URL,{method:"POST",headers:YT_HEADERS,body:JSON.stringify(body)});
  if (!r.ok) throw new Error(`YouTube responded ${r.status}`);
  return r.json();
}
function ytExtractVideos(data: any): Array<{videoId:string;title:string;thumbnail:string;duration:string}> {
  const out: any[]=[]; const visit=(n: any)=>{
    if(!n||typeof n!=="object") return; if(Array.isArray(n)){n.forEach(visit);return;}
    const r=n.playlistVideoRenderer;
    if(r){const vid=r.videoId;const title=r.title?.runs?.[0]?.text||r.title?.simpleText||"";const thumb=r.thumbnail?.thumbnails?.slice(-1)?.[0]?.url||(vid?`https://i.ytimg.com/vi/${vid}/mqdefault.jpg`:"");const dur=r.lengthText?.simpleText||r.lengthText?.runs?.[0]?.text||"";if(vid&&title&&title!=="[Private video]"&&title!=="[Deleted video]") out.push({videoId:vid,title,thumbnail:thumb,duration:dur});}
    for(const v of Object.values(n)) visit(v);
  }; visit(data); return out;
}
function ytExtractContinuation(data: any): string|null {
  const visit=(n: any): string|null=>{
    if(!n||typeof n!=="object") return null; if(Array.isArray(n)){for(const x of n){const t=visit(x);if(t)return t;}return null;}
    if(n.continuationCommand?.token) return n.continuationCommand.token;
    for(const v of Object.values(n)){const t=visit(v);if(t)return t;} return null;
  }; return visit(data);
}
function ytPlaylistTitle(data: any): string {
  return data?.header?.playlistHeaderRenderer?.title?.simpleText||data?.header?.playlistHeaderRenderer?.title?.runs?.[0]?.text||data?.metadata?.playlistMetadataRenderer?.title||"YouTube Playlist";
}

app.post("/api/admin/playlist/fetch", adminAuthMiddleware(), async c => {
  const {playlist}=await c.req.json<any>();
  const pid=extractPlaylistId(playlist); if(!pid) return c.json({error:"Couldn't find a YouTube playlist ID in that URL."},400);
  try {
    const all: any[]=[]; let continuation: string|null=null; let title="YouTube Playlist";
    for(let page=0;page<12;page++){
      const data=await fetchYtPage(pid,continuation||undefined); if(page===0) title=ytPlaylistTitle(data);
      all.push(...ytExtractVideos(data)); continuation=ytExtractContinuation(data); if(!continuation) break;
    }
    if(all.length===0) return c.json({error:"Playlist is empty, private, or not accessible."},404);
    const existing=new Set((await rd<Video[]>(c.env.DB,"vids.json",[])).map(v=>v.videoId));
    return c.json({title,playlistId:pid,total:all.length,videos:all.map(v=>({...v,exists:existing.has(v.videoId)}))});
  } catch(err: any) { return c.json({error:err?.message||"Failed to fetch playlist"},500); }
});

app.post("/api/admin/playlist/fetch-import", adminAuthMiddleware(), async c => {
  const {playlist,subjectId,chapterId,course,online}=await c.req.json<any>();
  const pid=extractPlaylistId(playlist); if(!pid) return c.json({error:"Couldn't find a YouTube playlist ID."},400);
  try {
    const all: any[]=[]; let continuation: string|null=null;
    for(let page=0;page<12;page++){
      const data=await fetchYtPage(pid,continuation||undefined); all.push(...ytExtractVideos(data));
      continuation=ytExtractContinuation(data); if(!continuation) break;
    }
    if(all.length===0) return c.json({error:"Playlist is empty or not accessible."},404);
    const list=await rd<Video[]>(c.env.DB,"vids.json",[]); const existing=new Set(list.map(v=>v.videoId));
    const created: Video[]=[];
    for(const it of all){if(!it.videoId||existing.has(it.videoId)) continue;created.push({id:crypto.randomUUID(),videoId:it.videoId,title:it.title,subjectId:subjectId||"",chapterId:chapterId||undefined,desc:it.duration||"",date:new Date().toLocaleString(),course:course||"",online:!!online});existing.add(it.videoId);}
    await wr(c.env.DB,"vids.json",[...created,...list]);
    return c.json({ok:true,total:all.length,added:created.length,skipped:all.length-created.length});
  } catch(err: any) { return c.json({error:err?.message||"Import failed"},500); }
});

/* ══════════════════════════════════════════════════════
   ADMIN — QUIZZES
══════════════════════════════════════════════════════ */
app.get("/api/admin/quizzes", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"quizzes.json",[])));
app.post("/api/admin/quizzes", adminAuthMiddleware(), async c => {
  const {title,desc,timeMinutes,questions}=await c.req.json<any>(); if(!title) return c.json({error:"title required"},400);
  const quizzes=await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  const quiz: Quiz={id:crypto.randomUUID(),title,desc:desc||"",timeMinutes:timeMinutes||30,published:false,createdAt:new Date().toISOString(),questions:questions||[]};
  quizzes.unshift(quiz); await wr(c.env.DB,"quizzes.json",quizzes); return c.json(quiz);
});
app.put("/api/admin/quizzes/:id", adminAuthMiddleware(), async c => {
  const quizzes=await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  const i=quizzes.findIndex(q=>q.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  quizzes[i]={...quizzes[i],...await c.req.json<any>(),id:quizzes[i].id};
  await wr(c.env.DB,"quizzes.json",quizzes); return c.json(quizzes[i]);
});
app.patch("/api/admin/quizzes/:id/publish", adminAuthMiddleware(), async c => {
  const quizzes=await rd<Quiz[]>(c.env.DB,"quizzes.json",[]);
  const i=quizzes.findIndex(q=>q.id===c.req.param("id")); if(i===-1) return c.json({error:"Not found"},404);
  quizzes[i].published=!quizzes[i].published; await wr(c.env.DB,"quizzes.json",quizzes); return c.json({published:quizzes[i].published});
});
app.delete("/api/admin/quizzes/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"quizzes.json",(await rd<Quiz[]>(c.env.DB,"quizzes.json",[])).filter(q=>q.id!==c.req.param("id")));
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — NOTIFICATIONS
══════════════════════════════════════════════════════ */
app.get("/api/admin/notifications", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"notifs.json",[])));
app.post("/api/admin/notifications", adminAuthMiddleware(), async c => {
  const {title,body,recipients}=await c.req.json<any>(); if(!title||!body) return c.json({error:"title and body required"},400);
  let recList: string[]=[];
  if (Array.isArray(recipients)) { const users=await rd<UniversalUser[]>(c.env.DB,"users.json",[]); const valid=new Set(users.map(u=>u.username)); recList=recipients.filter((r: any)=>typeof r==="string"&&valid.has(r)); }
  const notifs=await rd<Notification[]>(c.env.DB,"notifs.json",[]);
  const n: Notification={id:crypto.randomUUID(),title,body,createdAt:new Date().toISOString(),recipients:recList,readBy:[]};
  notifs.unshift(n); await wr(c.env.DB,"notifs.json",notifs); return c.json(n);
});
app.delete("/api/admin/notifications/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"notifs.json",(await rd<Notification[]>(c.env.DB,"notifs.json",[])).filter(n=>n.id!==c.req.param("id")));
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — DASHBOARD MENU
══════════════════════════════════════════════════════ */
app.get("/api/admin/dashboard-menu", adminAuthMiddleware(), async c => c.json((await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[])).sort((a,b)=>a.order-b.order)));
app.post("/api/admin/dashboard-menu", adminAuthMiddleware(), async c => {
  const {label,icon,bg,chevron,path:navPath,order,enabled}=await c.req.json<any>(); if(!label||!icon) return c.json({error:"label and icon required"},400);
  const items=await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[]);
  const item: DashMenuItem={id:crypto.randomUUID(),label:String(label).trim(),icon:String(icon).trim(),bg:bg||"#f3f4f6",chevron:chevron||"#666",path:navPath||"/",order:typeof order==="number"?order:(items.length+1),enabled:enabled!==false};
  items.push(item); await wr(c.env.DB,"dashmenu.json",items); return c.json(item);
});
app.put("/api/admin/dashboard-menu/:id", adminAuthMiddleware(), async c => {
  const items=await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[]);
  const i=items.findIndex(x=>x.id===c.req.param("id")); if(i<0) return c.json({error:"Not found"},404);
  const b=await c.req.json<any>();
  items[i]={...items[i],...(b.label!==undefined?{label:String(b.label).trim()}:{}),...(b.icon!==undefined?{icon:String(b.icon).trim()}:{}),...(b.bg!==undefined?{bg:String(b.bg)}:{}),...(b.chevron!==undefined?{chevron:String(b.chevron)}:{}),...(b.path!==undefined?{path:String(b.path)}:{}),...(typeof b.order==="number"?{order:b.order}:{}),...(typeof b.enabled==="boolean"?{enabled:b.enabled}:{})};
  await wr(c.env.DB,"dashmenu.json",items); return c.json(items[i]);
});
app.delete("/api/admin/dashboard-menu/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"dashmenu.json",(await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[])).filter(x=>x.id!==c.req.param("id")));
  return c.json({ok:true});
});
app.post("/api/admin/dashboard-menu/reorder", adminAuthMiddleware(), async c => {
  const {ids}=await c.req.json<any>(); if(!Array.isArray(ids)) return c.json({error:"ids array required"},400);
  const items=await rd<DashMenuItem[]>(c.env.DB,"dashmenu.json",[]);
  ids.forEach((id: string,idx: number)=>{const it=items.find(x=>x.id===id);if(it) it.order=idx+1;});
  await wr(c.env.DB,"dashmenu.json",items); return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — DOUBTS
══════════════════════════════════════════════════════ */
app.get("/api/doubts", adminAuthMiddleware(), async c => c.json(await rd(c.env.DB,"doubts.json",[])));
app.patch("/api/doubts/:id/reply", adminAuthMiddleware(), async c => {
  const {text,audioData,imageData,pdfData,pdfName,links}=await c.req.json<any>();
  const doubts=await rd<DoubtQuestion[]>(c.env.DB,"doubts.json",[]);
  const i=doubts.findIndex(d=>d.id===c.req.param("id")); if(i<0) return c.json({error:"Not found"},404);
  doubts[i].reply={text:text?String(text).slice(0,5000):undefined,audioData:audioData?String(audioData).slice(0,8_000_000):undefined,imageData:imageData?String(imageData).slice(0,8_000_000):undefined,pdfData:pdfData?String(pdfData).slice(0,10_000_000):undefined,pdfName:pdfName?String(pdfName).slice(0,200):undefined,links:Array.isArray(links)?links.slice(0,10).map((l: string)=>String(l).slice(0,500)):undefined,repliedAt:new Date().toISOString()};
  doubts[i].status="answered";
  const studentUser=doubts[i].username;
  if (studentUser) {
    const notifs=await rd<Notification[]>(c.env.DB,"notifs.json",[]);
    notifs.unshift({id:crypto.randomUUID(),title:"👨‍🏫 Teacher answered your question!",body:text?String(text).slice(0,90):"Check the Q&A page for your answer.",createdAt:new Date().toISOString(),recipients:[studentUser],readBy:[]});
    await wr(c.env.DB,"notifs.json",notifs.slice(0,300));
  }
  await wr(c.env.DB,"doubts.json",doubts); return c.json({ok:true});
});
app.patch("/api/doubts/:id/reopen", adminAuthMiddleware(), async c => {
  const doubts=await rd<DoubtQuestion[]>(c.env.DB,"doubts.json",[]);
  const i=doubts.findIndex(d=>d.id===c.req.param("id")); if(i<0) return c.json({error:"Not found"},404);
  doubts[i].status="open"; doubts[i].reply=undefined; await wr(c.env.DB,"doubts.json",doubts); return c.json({ok:true});
});
app.delete("/api/doubts/:id", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"doubts.json",(await rd<DoubtQuestion[]>(c.env.DB,"doubts.json",[])).filter(d=>d.id!==c.req.param("id")));
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — FLASHCARDS
══════════════════════════════════════════════════════ */
app.get("/api/admin/flashcard-decks", adminAuthMiddleware(), async c => {
  const [decks,cards]=await Promise.all([rd<FlashDeck[]>(c.env.DB,"flashdecks.json",[]),rd<FlashCard[]>(c.env.DB,"flashcards.json",[])]);
  return c.json(decks.map(d=>({...d,cardCount:cards.filter(c2=>c2.deckId===d.id).length})));
});
app.post("/api/admin/flashcard-decks", adminAuthMiddleware(), async c => {
  const {name,subject,description}=await c.req.json<any>(); if(!name) return c.json({error:"name required"},400);
  const decks=await rd<FlashDeck[]>(c.env.DB,"flashdecks.json",[]);
  const deck: FlashDeck={id:crypto.randomUUID(),name:String(name).trim(),subject:String(subject||"").trim(),description:String(description||"").trim(),createdAt:new Date().toISOString()};
  decks.push(deck); await wr(c.env.DB,"flashdecks.json",decks); return c.json(deck);
});
app.put("/api/admin/flashcard-decks/:id", adminAuthMiddleware(), async c => {
  const decks=await rd<FlashDeck[]>(c.env.DB,"flashdecks.json",[]);
  const i=decks.findIndex(d=>d.id===c.req.param("id")); if(i<0) return c.json({error:"Not found"},404);
  decks[i]={...decks[i],...await c.req.json<any>(),id:decks[i].id}; await wr(c.env.DB,"flashdecks.json",decks); return c.json(decks[i]);
});
app.delete("/api/admin/flashcard-decks/:id", adminAuthMiddleware(), async c => {
  await Promise.all([wr(c.env.DB,"flashdecks.json",(await rd<FlashDeck[]>(c.env.DB,"flashdecks.json",[])).filter(d=>d.id!==c.req.param("id"))),wr(c.env.DB,"flashcards.json",(await rd<FlashCard[]>(c.env.DB,"flashcards.json",[])).filter(c2=>c2.deckId!==c.req.param("id")))]);
  return c.json({ok:true});
});
app.get("/api/admin/flashcard-decks/:id/cards", adminAuthMiddleware(), async c => {
  return c.json((await rd<FlashCard[]>(c.env.DB,"flashcards.json",[])).filter(c2=>c2.deckId===c.req.param("id")).sort((a,b)=>a.order-b.order));
});
app.post("/api/admin/flashcard-decks/:id/cards", adminAuthMiddleware(), async c => {
  const {front,back,hint}=await c.req.json<any>(); if(!front||!back) return c.json({error:"front and back required"},400);
  const cards=await rd<FlashCard[]>(c.env.DB,"flashcards.json",[]);
  const card: FlashCard={id:crypto.randomUUID(),deckId:c.req.param("id"),front:String(front).trim(),back:String(back).trim(),hint:hint||undefined,order:cards.filter(c2=>c2.deckId===c.req.param("id")).length};
  cards.push(card); await wr(c.env.DB,"flashcards.json",cards); return c.json(card);
});
app.put("/api/admin/flashcard-decks/:deckId/cards/:cardId", adminAuthMiddleware(), async c => {
  const cards=await rd<FlashCard[]>(c.env.DB,"flashcards.json",[]);
  const i=cards.findIndex(c2=>c2.id===c.req.param("cardId")); if(i<0) return c.json({error:"Not found"},404);
  cards[i]={...cards[i],...await c.req.json<any>(),id:cards[i].id,deckId:cards[i].deckId}; await wr(c.env.DB,"flashcards.json",cards); return c.json(cards[i]);
});
app.delete("/api/admin/flashcard-decks/:deckId/cards/:cardId", adminAuthMiddleware(), async c => {
  await wr(c.env.DB,"flashcards.json",(await rd<FlashCard[]>(c.env.DB,"flashcards.json",[])).filter(c2=>c2.id!==c.req.param("cardId")));
  return c.json({ok:true});
});

/* ══════════════════════════════════════════════════════
   ADMIN — SECURITY
══════════════════════════════════════════════════════ */
app.get("/api/admin/security/bot-blocked", adminAuthMiddleware(), async c => c.json([]));
app.delete("/api/admin/security/bot-block/:ip", adminAuthMiddleware(), async c => c.json({ok:true}));

/* ══════════════════════════════════════════════════════
   MAIN EXPORT
══════════════════════════════════════════════════════ */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    ctx.waitUntil(seedDefaults(env.DB));
    return app.fetch(request, env, ctx);
  },
};
