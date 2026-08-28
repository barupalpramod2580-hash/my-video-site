const express = require("express");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const multer = require("multer");
const postgres = require("postgres");

const {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");

const {
  getSignedUrl,
} = require("@aws-sdk/s3-request-presigner");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================
   ENVIRONMENT CHECK
========================= */

const required = [
  "DATABASE_URL",
  "R2_ACCOUNT_ID",
  "R2_ACCESS_KEY_ID",
  "R2_SECRET_ACCESS_KEY",
  "R2_BUCKET",
  "SESSION_SECRET",
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

/* =========================
   DATABASE
========================= */

const sql = postgres(process.env.DATABASE_URL, {
  ssl: "require",
  max: 5,
});

/* =========================
   CLOUDFLARE R2
========================= */

const r2 = new S3Client({
  region: "auto",
  endpoint:
    `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

const BUCKET = process.env.R2_BUCKET;

/* =========================
   TEMP UPLOAD DIRECTORY
========================= */

const TEMP_DIR = path.join(os.tmpdir(), "my-video-site");

if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

/* =========================
   MULTER
========================= */

const upload = multer({
  dest: TEMP_DIR,

  limits: {
    fileSize: 2 * 1024 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    if (file.fieldname === "video") {

      if (!file.mimetype.startsWith("video/")) {
        return cb(
          new Error("Only video files are allowed.")
        );
      }

    }

    if (file.fieldname === "thumbnail") {

      if (!file.mimetype.startsWith("image/")) {
        return cb(
          new Error("Only image thumbnails are allowed.")
        );
      }

    }

    cb(null, true);
  }
});

/* =========================
   EXPRESS
========================= */

app.use(express.json());

app.use(
  cookieSession({
    name: "session",
    keys: [process.env.SESSION_SECRET],
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
);

/* =========================
   DATABASE SETUP
========================= */

async function setupDatabase() {

  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'uploader',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      video_key TEXT NOT NULL,
      thumbnail_key TEXT,
      uploaded_by INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  const existing =
    await sql`
      SELECT id
      FROM users
      WHERE username = ${process.env.ADMIN_USERNAME || "admin"}
      LIMIT 1
    `;

  if (existing.length === 0) {

    const username =
      process.env.ADMIN_USERNAME || "admin";

    const password =
      process.env.ADMIN_PASSWORD;

    if (!password) {
      throw new Error(
        "ADMIN_PASSWORD environment variable is required."
      );
    }

    const hash =
      await bcrypt.hash(password, 12);

    await sql`
      INSERT INTO users
      (username, password_hash, role)
      VALUES
      (${username}, ${hash}, 'admin')
    `;

    console.log(
      `Created admin user: ${username}`
    );
  }

  console.log("Database ready.");
}

/* =========================
   AUTH HELPERS
========================= */

function requireLogin(req, res, next) {

  if (!req.session || !req.session.user) {

    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

function requireAdmin(req, res, next) {

  if (
    !req.session ||
    !req.session.user ||
    req.session.user.role !== "admin"
  ) {

    return res.status(403).json({
      error: "Admin permission required"
    });
  }

  next();
}

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {

  try {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    if (!username || !password) {

      return res.status(400).json({
        error: "Username and password required"
      });
    }

    const rows =
      await sql`
        SELECT id, username, password_hash, role
        FROM users
        WHERE username = ${username}
        LIMIT 1
      `;

    if (rows.length === 0) {

      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const user = rows[0];

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {

      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    res.json({
      success: true,
      user: req.session.user
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Login error"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {

  res.json({
    user:
      req.session && req.session.user
        ? req.session.user
        : null
  });
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {

  req.session = null;

  res.json({
    success: true
  });
});

/* =========================
   CREATE UPLOADER
========================= */

app.post(
  "/api/users",
  requireAdmin,
  async (req, res) => {

    try {

      const username =
        String(req.body.username || "").trim();

      const password =
        String(req.body.password || "");

      if (!username || !password) {

        return res.status(400).json({
          error: "Username and password required"
        });
      }

      if (password.length < 8) {

        return res.status(400).json({
          error: "Password must be at least 8 characters"
        });
      }

      const exists =
        await sql`
          SELECT id
          FROM users
          WHERE username = ${username}
          LIMIT 1
        `;

      if (exists.length > 0) {

        return res.status(409).json({
          error: "Username already exists"
        });
      }

      const hash =
        await bcrypt.hash(password, 12);

      await sql`
        INSERT INTO users
        (username, password_hash, role)
        VALUES
        (${username}, ${hash}, 'uploader')
      `;

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Could not create uploader"
      });
    }
  }
);

/* =========================
   UPLOAD VIDEO
========================= */

app.post(
  "/api/upload",
  requireLogin,
  upload.fields([
    {
      name: "video",
      maxCount: 1
    },
    {
      name: "thumbnail",
      maxCount: 1
    }
  ]),
  async (req, res) => {

    let videoPath = null;
    let thumbnailPath = null;

    try {

      const title =
        String(req.body.title || "").trim();

      const description =
        String(req.body.description || "").trim();

      if (!title) {

        return res.status(400).json({
          error: "Video title is required"
        });
      }

      if (
        !req.files ||
        !req.files.video ||
        !req.files.video[0]
      ) {

        return res.status(400).json({
          error: "Video file is required"
        });
      }

      const video =
        req.files.video[0];

      videoPath = video.path;

      const videoExt =
        path.extname(video.originalname)
        .toLowerCase() || ".mp4";

      const random =
        crypto.randomBytes(16).toString("hex");

      const videoKey =
        `videos/${Date.now()}-${random}${videoExt}`;

      /* Upload video to R2 */

      await r2.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: videoKey,
          Body: fs.createReadStream(videoPath),
          ContentType:
            video.mimetype || "video/mp4"
        })
      );

      let thumbnailKey = null;

      if (
        req.files.thumbnail &&
        req.files.thumbnail[0]
      ) {

        const thumbnail =
          req.files.thumbnail[0];

        thumbnailPath =
          thumbnail.path;

        const thumbExt =
          path.extname(
            thumbnail.originalname
          ).toLowerCase() || ".jpg";

        thumbnailKey =
          `thumbnails/${Date.now()}-${random}${thumbExt}`;

        await r2.send(
          new PutObjectCommand({
            Bucket: BUCKET,
            Key: thumbnailKey,
            Body: fs.createReadStream(
              thumbnailPath
            ),
            ContentType:
              thumbnail.mimetype || "image/jpeg"
          })
        );
      }

      const inserted =
        await sql`
          INSERT INTO videos
          (
            title,
            description,
            video_key,
            thumbnail_key,
            uploaded_by
          )
          VALUES
          (
            ${title},
            ${description},
            ${videoKey},
            ${thumbnailKey},
            ${req.session.user.id}
          )
          RETURNING id
        `;

      res.json({
        success: true,
        id: inserted[0].id
      });

    } catch (error) {

      console.error("UPLOAD ERROR:", error);

      res.status(500).json({
        error: "Video upload failed"
      });

    } finally {

      if (videoPath) {
        fs.unlink(
          videoPath,
          () => {}
        );
      }

      if (thumbnailPath) {
        fs.unlink(
          thumbnailPath,
          () => {}
        );
      }
    }
  }
);

/* =========================
   LIST VIDEOS
========================= */

app.get("/api/videos", async (req, res) => {

  try {

    const rows =
      await sql`
        SELECT
          v.id,
          v.title,
          v.description,
          v.thumbnail_key,
          v.created_at,
          COALESCE(
            u.username,
            'Unknown'
          ) AS uploaded_by
        FROM videos v
        LEFT JOIN users u
          ON u.id = v.uploaded_by
        ORDER BY v.created_at DESC
      `;

    res.json(
      rows.map(v => ({
        id: v.id,
        title: v.title,
        description: v.description,
        thumbnail: !!v.thumbnail_key,
        uploaded_by: v.uploaded_by,
        created_at: v.created_at
      }))
    );

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Could not load videos"
    });
  }
});

/* =========================
   SINGLE VIDEO
========================= */

app.get(
  "/api/videos/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          error: "Invalid video ID"
        });
      }

      const rows =
        await sql`
          SELECT
            id,
            title,
            description,
            video_key,
            thumbnail_key,
            created_at
          FROM videos
          WHERE id = ${id}
          LIMIT 1
        `;

      if (rows.length === 0) {

        return res.status(404).json({
          error: "Video not found"
        });
      }

      const video = rows[0];

      res.json({
        id: video.id,
        title: video.title,
        description: video.description,
        created_at: video.created_at
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Could not load video"
      });
    }
  }
);

/* =========================
   VIDEO REDIRECT
========================= */

app.get(
  "/video/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const rows =
        await sql`
          SELECT video_key
          FROM videos
          WHERE id = ${id}
          LIMIT 1
        `;

      if (rows.length === 0) {

        return res.status(404).send(
          "Video not found"
        );
      }

      const url =
        await getSignedUrl(
          r2,
          new (require(
            "@aws-sdk/client-s3"
          ).GetObjectCommand)({
            Bucket: BUCKET,
            Key: rows[0].video_key
          }),
          {
            expiresIn: 3600
          }
        );

      res.redirect(url);

    } catch (error) {

      console.error(error);

      res.status(500).send(
        "Could not open video"
      );
    }
  }
);

/* =========================
   THUMBNAIL
========================= */

app.get(
  "/thumbnail/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const rows =
        await sql`
          SELECT thumbnail_key
          FROM videos
          WHERE id = ${id}
          LIMIT 1
        `;

      if (
        rows.length === 0 ||
        !rows[0].thumbnail_key
      ) {

        return res.status(404).send(
          "Thumbnail not found"
        );
      }

      const url =
        await getSignedUrl(
          r2,
          new (require(
            "@aws-sdk/client-s3"
          ).GetObjectCommand)({
            Bucket: BUCKET,
            Key: rows[0].thumbnail_key
          }),
          {
            expiresIn: 3600
          }
        );

      res.redirect(url);

    } catch (error) {

      console.error(error);

      res.status(500).send(
        "Could not open thumbnail"
      );
    }
  }
);

/* =========================
   DOWNLOAD
========================= */

app.get(
  "/download/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const rows =
        await sql`
          SELECT
            id,
            title,
            video_key
          FROM videos
          WHERE id = ${id}
          LIMIT 1
        `;

      if (rows.length === 0) {

        return res.status(404).send(
          "Video not found"
        );
      }

      const safeName =
        rows[0].title
          .replace(/[^a-zA-Z0-9-_ ]/g, "")
          .trim()
          .slice(0, 80) || "video";

      const command =
        new (require(
          "@aws-sdk/client-s3"
        ).GetObjectCommand)({
          Bucket: BUCKET,
          Key: rows[0].video_key,
          ResponseContentDisposition:
            `attachment; filename="${safeName}.mp4"`
        });

      const url =
        await getSignedUrl(
          r2,
          command,
          {
            expiresIn: 3600
          }
        );

      res.redirect(url);

    } catch (error) {

      console.error(error);

      res.status(500).send(
        "Download failed"
      );
    }
  }
);

/* =========================
   DELETE VIDEO
========================= */

app.delete(
  "/api/videos/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const rows =
        await sql`
          SELECT
            video_key,
            thumbnail_key
          FROM videos
          WHERE id = ${id}
          LIMIT 1
        `;

      if (rows.length === 0) {

        return res.status(404).json({
          error: "Video not found"
        });
      }

      const video =
        rows[0];

      /* Delete video from R2 */

      await r2.send(
        new DeleteObjectCommand({
          Bucket: BUCKET,
          Key: video.video_key
        })
      );

      /* Delete thumbnail */

      if (video.thumbnail_key) {

        await r2.send(
          new DeleteObjectCommand({
            Bucket: BUCKET,
            Key: video.thumbnail_key
          })
        );
      }

      /* Delete database record */

      await sql`
        DELETE FROM videos
        WHERE id = ${id}
      `;

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Delete failed"
      });
    }
  }
);

/* =========================
   STATIC WEBSITE
========================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {

    console.error(error);

    if (
      error.code === "LIMIT_FILE_SIZE"
    ) {

      return res.status(413).json({
        error:
          "File is too large. Maximum is 2 GB."
      });
    }

    res.status(500).json({
      error:
        error.message || "Server error"
    });
  }
);

/* =========================
   START SERVER
========================= */

setupDatabase()
  .then(() => {

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `Server running on port ${PORT}`
        );
      }
    );

  })
  .catch(error => {

    console.error(
      "Database setup failed:",
      error
    );

    process.exit(1);
  });
