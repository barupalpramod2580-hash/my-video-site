const express = require("express");
const session = require("express-session");
const multer = require("multer");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 3000;

const VIDEO_DIR = path.join(__dirname, "videos");
const THUMB_DIR = path.join(__dirname, "thumbnails");

fs.mkdirSync(VIDEO_DIR, { recursive: true });
fs.mkdirSync(THUMB_DIR, { recursive: true });

const db = new Database("database.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    can_upload INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    filename TEXT,
    thumbnail TEXT,
    uploaded_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

/*
  Default admin:
  username: admin
  password: change-this-password
*/

const adminExists = db
  .prepare("SELECT id FROM users WHERE username=?")
  .get("admin");

if (!adminExists) {
  db.prepare(
    "INSERT INTO users(username,password,can_upload) VALUES(?,?,?)"
  ).run("admin", "change-this-password", 1);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "CHANGE_THIS_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

const videoStorage = multer.diskStorage({
  destination: VIDEO_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + Math.random().toString(36).slice(2) + ext);
  }
});

const imageStorage = multer.diskStorage({
  destination: THUMB_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + Math.random().toString(36).slice(2) + ext);
  }
});

const upload = multer({
  storage: videoStorage,
  limits: {
    fileSize: 2 * 1024 * 1024 * 1024
  }
});

const thumbnailUpload = multer({
  storage: imageStorage,
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

function loggedIn(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

function uploader(req, res, next) {
  if (!req.session.user || !req.session.user.can_upload) {
    return res.status(403).json({
      error: "Upload permission required"
    });
  }

  next();
}

/* LOGIN */

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const user = db
    .prepare(
      "SELECT id,username,password,can_upload FROM users WHERE username=?"
    )
    .get(username);

  if (!user || user.password !== password) {
    return res.status(401).json({
      error: "Wrong username or password"
    });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    can_upload: user.can_upload
  };

  res.json({
    success: true,
    user: req.session.user
  });
});

/* LOGOUT */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

/* CURRENT USER */

app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

/* GET VIDEOS */

app.get("/api/videos", (req, res) => {
  const videos = db
    .prepare(`
      SELECT id,title,description,thumbnail,uploaded_by,created_at
      FROM videos
      ORDER BY id DESC
    `)
    .all();

  res.json(videos);
});

/* UPLOAD */

app.post(
  "/api/upload",
  uploader,
  upload.single("video"),
  thumbnailUpload.single("thumbnail"),
  (req, res) => {

    if (!req.file) {
      return res.status(400).json({
        error: "Video required"
      });
    }

    const title = req.body.title || "Untitled";
    const description = req.body.description || "";

    const thumbnail = req.files?.thumbnail
      ? req.files.thumbnail[0].filename
      : null;

    db.prepare(`
      INSERT INTO videos
      (title,description,filename,thumbnail,uploaded_by)
      VALUES (?,?,?,?,?)
    `).run(
      title,
      description,
      req.file.filename,
      thumbnail,
      req.session.user.username
    );

    res.json({
      success: true
    });
  }
);

/* VIDEO STREAM */

app.get("/video/:id", (req, res) => {

  const video = db
    .prepare("SELECT * FROM videos WHERE id=?")
    .get(req.params.id);

  if (!video) {
    return res.status(404).send("Video not found");
  }

  const filePath = path.join(VIDEO_DIR, video.filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("File not found");
  }

  const stat = fs.statSync(filePath);
  const range = req.headers.range;

  if (!range) {
    res.writeHead(200, {
      "Content-Length": stat.size,
      "Content-Type": "video/mp4"
    });

    fs.createReadStream(filePath).pipe(res);
    return;
  }

  const parts = range.replace(/bytes=/, "").split("-");
  const start = parseInt(parts[0], 10);
  const end = parts[1]
    ? parseInt(parts[1], 10)
    : stat.size - 1;

  const chunkSize = end - start + 1;

  res.writeHead(206, {
    "Content-Range": `bytes ${start}-${end}/${stat.size}`,
    "Accept-Ranges": "bytes",
    "Content-Length": chunkSize,
    "Content-Type": "video/mp4"
  });

  fs.createReadStream(filePath, {
    start,
    end
  }).pipe(res);
});

/* THUMBNAIL */

app.get("/thumbnail/:id", (req, res) => {

  const video = db
    .prepare("SELECT thumbnail FROM videos WHERE id=?")
    .get(req.params.id);

  if (!video || !video.thumbnail) {
    return res.status(404).send("No thumbnail");
  }

  const filePath = path.join(THUMB_DIR, video.thumbnail);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Thumbnail not found");
  }

  res.sendFile(filePath);
});

/* DOWNLOAD */

app.get("/download/:id", (req, res) => {

  const video = db
    .prepare("SELECT * FROM videos WHERE id=?")
    .get(req.params.id);

  if (!video) {
    return res.status(404).send("Video not found");
  }

  const filePath = path.join(VIDEO_DIR, video.filename);

  res.download(filePath, video.title + path.extname(video.filename));
});

/* DELETE */

app.delete("/api/videos/:id", loggedIn, (req, res) => {

  const video = db
    .prepare("SELECT * FROM videos WHERE id=?")
    .get(req.params.id);

  if (!video) {
    return res.status(404).json({
      error: "Video not found"
    });
  }

  if (
    req.session.user.username !== "admin" &&
    req.session.user.username !== video.uploaded_by
  ) {
    return res.status(403).json({
      error: "Not allowed"
    });
  }

  const filePath = path.join(VIDEO_DIR, video.filename);

  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  if (video.thumbnail) {
    const thumb = path.join(THUMB_DIR, video.thumbnail);

    if (fs.existsSync(thumb)) {
      fs.unlinkSync(thumb);
    }
  }

  db.prepare("DELETE FROM videos WHERE id=?").run(req.params.id);

  res.json({
    success: true
  });
});

/* ADMIN - CREATE UPLOADER */

app.post("/api/users", loggedIn, (req, res) => {

  if (req.session.user.username !== "admin") {
    return res.status(403).json({
      error: "Admin only"
    });
  }

  const { username, password } = req.body;

  try {

    db.prepare(`
      INSERT INTO users(username,password,can_upload)
      VALUES(?,?,1)
    `).run(username, password);

    res.json({
      success: true
    });

  } catch {

    res.status(400).json({
      error: "Username already exists"
    });

  }
});

app.listen(PORT, () => {

  console.log(`
================================
My Video Website Started
================================

Open:
http://localhost:${PORT}

Admin:
username: admin
password: change-this-password

Change the password before using this online.
`);

});
