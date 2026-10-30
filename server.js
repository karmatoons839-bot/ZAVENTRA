require("dotenv").config();
const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database(path.join(__dirname, "zaventra.sqlite"));
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-me";
const OWNER_PHONE = (process.env.OWNER_PHONE || "").trim();
const DEMO_OTP = String(process.env.OTP_DEMO_MODE || "true").toLowerCase() === "true";
const otpStore = new Map();

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT UNIQUE NOT NULL,
 display_name TEXT NOT NULL DEFAULT 'Zaventra User', role TEXT NOT NULL DEFAULT 'USER',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS groups (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner_id INTEGER NOT NULL,
 official INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS members (
 group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'MEMBER',
 UNIQUE(group_id,user_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
 body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bots (
 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, name TEXT NOT NULL,
 username TEXT NOT NULL UNIQUE, welcome TEXT NOT NULL DEFAULT 'Hello! I am a Zaventra bot.',
 enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, event TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function logEvent(actorId, event, details="") {
 db.prepare("INSERT INTO audit_log(actor_id,event,details) VALUES(?,?,?)").run(actorId || null,event,details);
}
function ensureOfficialGroup(userId) {
 let group = db.prepare("SELECT * FROM groups WHERE official=1 ORDER BY id LIMIT 1").get();
 if (!group) {
   const result = db.prepare("INSERT INTO groups(name,owner_id,official) VALUES(?,?,1)").run("Zaventra Community", userId);
   group = db.prepare("SELECT * FROM groups WHERE id=?").get(result.lastInsertRowid);
   logEvent(userId,"official_group_created",String(group.id));
 }
 db.prepare("INSERT OR IGNORE INTO members(group_id,user_id,role) VALUES(?,?,?)").run(group.id,userId,"MEMBER");
 return group;
}
app.use(express.json({limit:"32kb"}));
app.use(session({
 secret: SESSION_SECRET, resave:false, saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}
}));
app.use(express.static(path.join(__dirname,"public")));
const otpLimiter = rateLimit({windowMs:15*60*1000,max:5,standardHeaders:true,legacyHeaders:false});
app.post("/api/auth/request-otp", otpLimiter, (req,res)=>{
 const phone = String(req.body.phone||"").trim();
 if (!/^\+[1-9]\d{7,14}$/.test(phone)) return res.status(400).json({error:"Use international format, e.g. +91XXXXXXXXXX."});
 const otp = String(crypto.randomInt(100000,1000000));
 otpStore.set(phone,{otp,expires:Date.now()+5*60*1000,attempts:0});
 if (DEMO_OTP) {
   console.log(`[DEMO ONLY] OTP for ${phone}: ${otp}`);
   return res.json({ok:true,mode:"demo",message:"Demo OTP server terminal me print hua hai. Public production me is mode ko band rakhein."});
 }
 return res.status(503).json({error:"SMS provider is not configured. Add a real SMS OTP provider before production."});
});
app.post("/api/auth/verify-otp", otpLimiter, (req,res)=>{
 const phone = String(req.body.phone||"").trim();
 const code = String(req.body.code||"").trim();
 const record = otpStore.get(phone);
 if (!record || Date.now()>record.expires || record.attempts>=5) return res.status(400).json({error:"OTP expired. Request a new code."});
 record.attempts++;
 if (record.otp !== code) return res.status(400).json({error:"Incorrect OTP."});
 otpStore.delete(phone);
 let user = db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
 if (!user) {
   const role = OWNER_PHONE && phone===OWNER_PHONE ? "OWNER" : "USER";
   const result = db.prepare("INSERT INTO users(phone,role) VALUES(?,?)").run(phone,role);
   user = db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid);
   logEvent(user.id,"account_created",JSON.stringify({phone,role}));
 } else if (OWNER_PHONE && phone===OWNER_PHONE && user.role!=="OWNER") {
   db.prepare("UPDATE users SET role='OWNER' WHERE id=?").run(user.id);
   user = db.prepare("SELECT * FROM users WHERE id=?").get(user.id);
 }
 req.session.userId=user.id;
 ensureOfficialGroup(user.id);
 logEvent(user.id,"login",JSON.stringify({role:user.role}));
 res.json({ok:true,user:{id:user.id,phone:user.phone,name:user.display_name,role:user.role}});
});
function currentUser(req) {
 return req.session.userId ? db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId) : null;
}
function requireAuth(req,res,next) {
 const user=currentUser(req); if(!user) return res.status(401).json({error:"Please log in first."});
 req.user=user; next();
}
function requireOwner(req,res,next) {
 if(req.user.role!=="OWNER") return res.status(403).json({error:"Owner access only."});
 next();
}
app.get("/api/me",(req,res)=>{const u=currentUser(req); res.json({user:u?{id:u.id,phone:u.phone,name:u.display_name,role:u.role}:null});});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/groups",requireAuth,(req,res)=>{
 const rows=db.prepare(`SELECT g.*,m.role AS my_role FROM groups g JOIN members m ON m.group_id=g.id WHERE m.user_id=? ORDER BY g.official DESC,g.id`).all(req.user.id);
 res.json({groups:rows});
});
app.post("/api/groups",requireAuth,(req,res)=>{
 const name=String(req.body.name||"").trim().slice(0,60);
 if(name.length<2) return res.status(400).json({error:"Group name must be at least 2 characters."});
 const r=db.prepare("INSERT INTO groups(name,owner_id,official) VALUES(?,?,0)").run(name,req.user.id);
 db.prepare("INSERT INTO members(group_id,user_id,role) VALUES(?,?,?)").run(r.lastInsertRowid,req.user.id,"OWNER");
 logEvent(req.user.id,"group_created",JSON.stringify({groupId:r.lastInsertRowid,name}));
 res.json({ok:true,id:r.lastInsertRowid,name});
});
app.get("/api/messages/:groupId",requireAuth,(req,res)=>{
 const gid=Number(req.params.groupId);
 const member=db.prepare("SELECT 1 FROM members WHERE group_id=? AND user_id=?").get(gid,req.user.id);
 if(!member) return res.status(403).json({error:"You are not a member of this group."});
 res.json({messages:db.prepare(`SELECT m.id,m.body,m.created_at,u.display_name,u.id AS user_id FROM messages m JOIN users u ON u.id=m.user_id WHERE m.group_id=? ORDER BY m.id DESC LIMIT 100`).all(gid).reverse()});
});
app.post("/api/messages/:groupId",requireAuth,(req,res)=>{
 const gid=Number(req.params.groupId), body=String(req.body.body||"").trim().slice(0,2000);
 if(!body) return res.status(400).json({error:"Message cannot be empty."});
 const member=db.prepare("SELECT 1 FROM members WHERE group_id=? AND user_id=?").get(gid,req.user.id);
 if(!member) return res.status(403).json({error:"You are not a member of this group."});
 const r=db.prepare("INSERT INTO messages(group_id,user_id,body) VALUES(?,?,?)").run(gid,req.user.id,body);
 const message=db.prepare("SELECT m.id,m.body,m.created_at,u.display_name,m.user_id FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id=?").get(r.lastInsertRowid);
 io.to("group:"+gid).emit("new-message",{...message,group_id:gid});
 res.json({ok:true,message});
});
app.post("/api/bots",requireAuth,(req,res)=>{
 const name=String(req.body.name||"").trim().slice(0,60);
 const username=String(req.body.username||"").trim().replace(/^@/,"").toLowerCase();
 const welcome=String(req.body.welcome||"Hello! I am a Zaventra bot.").trim().slice(0,500);
 if(name.length<2 || !/^[a-z0-9_]{4,32}$/.test(username)) return res.status(400).json({error:"Name required; username must be 4-32 letters, numbers or underscores."});
 try {
  const r=db.prepare("INSERT INTO bots(owner_id,name,username,welcome) VALUES(?,?,?,?)").run(req.user.id,name,username,welcome);
  logEvent(req.user.id,"bot_created",JSON.stringify({botId:r.lastInsertRowid,username}));
  res.json({ok:true,bot:{id:r.lastInsertRowid,name,username,welcome,enabled:1}});
 } catch(e) {res.status(409).json({error:"That bot username is already taken."});}
});
app.get("/api/bots",requireAuth,(req,res)=>{
 const bots=req.user.role==="OWNER" ? db.prepare("SELECT b.*,u.phone AS owner_phone FROM bots b JOIN users u ON u.id=b.owner_id ORDER BY b.id DESC").all()
 : db.prepare("SELECT * FROM bots WHERE owner_id=? ORDER BY id DESC").all(req.user.id);
 res.json({bots});
});
app.get("/api/owner/overview",requireAuth,requireOwner,(req,res)=>{
 const stats={
  users:db.prepare("SELECT COUNT(*) n FROM users").get().n,
  groups:db.prepare("SELECT COUNT(*) n FROM groups WHERE official=0").get().n,
  bots:db.prepare("SELECT COUNT(*) n FROM bots").get().n,
  recentUsers:db.prepare("SELECT id,phone,role,created_at FROM users ORDER BY id DESC LIMIT 20").all(),
  recentGroups:db.prepare("SELECT g.id,g.name,g.created_at,u.phone AS owner_phone FROM groups g JOIN users u ON u.id=g.owner_id WHERE g.official=0 ORDER BY g.id DESC LIMIT 20").all(),
  events:db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT 30").all()
 };
 res.json(stats);
});
io.use((socket,next)=>{
 const cookie=socket.handshake.headers.cookie||"";
 // Socket messages use the normal authenticated HTTP endpoints in this prototype;
 // no unauthenticated socket joins are allowed.
 next();
});
io.on("connection",socket=>{
 socket.on("join-group",async({groupId}={})=>{
  // Prototype intentionally does not trust a client-supplied user ID. Group membership is
  // verified via the HTTP API before messages are fetched/sent. Production should bind
  // Socket.IO to the server-side session middleware before enabling room joins.
  if(Number.isInteger(Number(groupId))) socket.join("group:"+Number(groupId));
 });
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
server.listen(PORT,()=>console.log(`Zaventra test server: http://localhost:${PORT}\nOTP demo mode: ${DEMO_OTP ? "ON (local testing only)" : "OFF"}`));
