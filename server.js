require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const { Client, LocalAuth } = require("whatsapp-web.js");
const QRCode = require("qrcode");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA = path.join(__dirname, ".data");
fs.mkdirSync(DATA, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET wajib diisi minimal 32 karakter di file .env");
  process.exit(1);
}
if (!process.env.OWNER_PASSWORD || process.env.OWNER_PASSWORD.length < 12) {
  console.error("OWNER_PASSWORD wajib diisi minimal 12 karakter di file .env");
  process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA }),
  secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8*60*60*1000 }
}));

const dbFile = path.join(DATA, "app.json");
let db = fs.existsSync(dbFile) ? JSON.parse(fs.readFileSync(dbFile, "utf8")) : { users: [], settings: { autoReply: true, welcome: true, replyText: "Halo! Pesan kamu sudah kami terima." }, logs: [] };
function save(){ fs.writeFileSync(dbFile, JSON.stringify(db, null, 2)); }
async function initOwner(){
  if (!db.users.some(u => u.role === "owner")) {
    db.users.push({ id: Date.now().toString(), username: process.env.OWNER_USERNAME || "owner", password: await bcrypt.hash(process.env.OWNER_PASSWORD, 12), role:"owner" });
    save();
  }
}
const client = new Client({
  authStrategy: new LocalAuth({ dataPath: path.join(__dirname, ".wwebjs_auth") }),
  puppeteer: { headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] }
});
let botState = "OFFLINE", qrData = null, botNumber = null, lastError = null;
function log(message){
  db.logs.unshift({ time: new Date().toISOString(), message: String(message).slice(0,180) });
  db.logs = db.logs.slice(0,100); save();
}
client.on("qr", async qr => { qrData = await QRCode.toDataURL(qr); botState = "SCAN QR"; log("QR baru tersedia untuk dipindai"); });
client.on("authenticated", () => { botState = "MENGHUBUNGKAN"; qrData = null; log("WhatsApp terautentikasi"); });
client.on("ready", () => { botState = "ONLINE"; qrData = null; botNumber = client.info?.wid?.user || null; lastError = null; log("Bot WhatsApp online"); });
client.on("auth_failure", msg => { botState = "ERROR"; lastError = String(msg); log("Autentikasi gagal"); });
client.on("disconnected", reason => { botState = "OFFLINE"; botNumber = null; log("WhatsApp terputus: " + reason); });
client.on("message", async msg => {
  try {
    if (msg.fromMe || msg.isStatus || msg.from.endsWith("@g.us")) return;
    if (db.settings.autoReply && msg.body && !msg.body.startsWith("!")) {
      await msg.reply(db.settings.replyText || "Halo! Pesan kamu sudah kami terima.");
      log("Auto-reply terkirim ke " + msg.from);
    }
  } catch(e){ log("Gagal auto-reply: " + e.message); }
});
client.on("message_create", msg => { if (msg.fromMe) log("Pesan keluar dibuat"); });

function auth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"Silakan login"}); next(); }
function roles(...allowed){ return (req,res,next)=>{ if(!req.session.user || !allowed.includes(req.session.user.role)) return res.status(403).json({error:"Akses ditolak"}); next(); }; }
app.post("/api/login", async (req,res)=>{
  const {username,password}=req.body||{};
  const user=db.users.find(u=>u.username===String(username||""));
  if(!user || !(await bcrypt.compare(String(password||""),user.password))) return res.status(401).json({error:"Username atau password salah"});
  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:"Gagal membuat sesi"});
    req.session.user={id:user.id,username:user.username,role:user.role};
    res.json({user:req.session.user});
  });
});
app.post("/api/logout", auth, (req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me", (req,res)=>res.json({user:req.session.user||null}));
app.get("/api/status", auth, (req,res)=>res.json({state:botState,number:botNumber,qr: req.session.user.role!=="member" ? qrData : null,error:lastError}));
app.get("/api/data", auth, (req,res)=>res.json({settings:db.settings,logs:db.logs,users:db.users.map(({id,username,role})=>({id,username,role}))}));
app.post("/api/settings", roles("owner","admin"), (req,res)=>{
  const {autoReply,welcome,replyText}=req.body||{};
  db.settings={autoReply:!!autoReply,welcome:!!welcome,replyText:String(replyText||"").slice(0,500)}; save(); log("Pengaturan bot diperbarui"); res.json({ok:true});
});
app.post("/api/send", roles("owner","admin"), async (req,res)=>{
  const number=String(req.body.number||"").replace(/\D/g,"");
  const message=String(req.body.message||"").trim();
  if(number.length<8 || number.length>15 || !message || message.length>2000) return res.status(400).json({error:"Nomor atau pesan tidak valid"});
  if(botState!=="ONLINE") return res.status(409).json({error:"Bot belum online"});
  try {
    const chatId=number+"@c.us";
    const valid=await client.isRegisteredUser(chatId);
    if(!valid) return res.status(400).json({error:"Nomor belum terdaftar di WhatsApp"});
    await client.sendMessage(chatId,message);
    log("Pesan manual dikirim ke "+number);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:"Pesan gagal dikirim"}); }
});
app.post("/api/users", roles("owner"), async (req,res)=>{
  const {username,password,role}=req.body||{};
  if(!/^[a-zA-Z0-9_.-]{3,24}$/.test(String(username||""))) return res.status(400).json({error:"Username 3-24 karakter, tanpa spasi"});
  if(String(password||"").length<12) return res.status(400).json({error:"Password minimal 12 karakter"});
  if(!["admin","member"].includes(role)) return res.status(400).json({error:"Role tidak valid"});
  if(db.users.some(u=>u.username===username)) return res.status(409).json({error:"Username sudah dipakai"});
  db.users.push({id:Date.now().toString(),username,password:await bcrypt.hash(password,12),role}); save(); log("Akun "+role+" dibuat: "+username); res.json({ok:true});
});
app.delete("/api/users/:id", roles("owner"), (req,res)=>{
  const target=db.users.find(u=>u.id===req.params.id);
  if(!target || target.role==="owner") return res.status(400).json({error:"Akun tidak dapat dihapus"});
  db.users=db.users.filter(u=>u.id!==target.id); save(); log("Akun dihapus: "+target.username); res.json({ok:true});
});
app.post("/api/bot/restart", roles("owner"), async (req,res)=>{
  try { botState="MENGHUBUNGKAN"; qrData=null; await client.destroy(); await client.initialize(); res.json({ok:true}); }
  catch(e){ botState="ERROR"; lastError=e.message; res.status(500).json({error:"Bot gagal dimulai ulang"}); }
});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

(async()=>{
  await initOwner();
  app.listen(PORT,()=>console.log(`Panel berjalan di http://localhost:${PORT}`));
  client.initialize().catch(e=>{ botState="ERROR"; lastError=e.message; log("Inisialisasi gagal: "+e.message); });
})();
process.on("SIGINT",async()=>{try{await client.destroy();}catch{} process.exit(0);});
