const express = require("express");
const path = require("path");
const fs = require("fs");
const os = require("os");
const bcrypt = require("bcryptjs");
const cookieSession = require("cookie-session");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   ENVIRONMENT VARIABLES
========================= */

const required = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SESSION_SECRET",
  "ADMIN_USERNAME",
  "ADMIN_PASSWORD"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

/* =========================
   SUPABASE
========================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const BUCKET = "videos";

/* =========================
   TEMP DIRECTORY
========================= */

const TEMP_DIR = path.join(
  os.tmpdir(),
  "my-video-site"
);

if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, {
    recursive: true
  });
}

/* =========================
   MULTER
========================= */

const upload = multer({
  dest: TEMP_DIR,

  limits: {
    fileSize: 50 * 1024 * 1024
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
          new Error("Only image files are allowed.")
        );
      }
    }

    cb(null, true);
  }
});

/* =========================
   MIDDLEWARE
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
   DATABASE
========================= */

async function dbSetup() {

  const { error } =
    await supabase.rpc(
      "create_video_tables"
    );

  /*
    If the RPC doesn't exist, the app will continue.
    Tables should be created manually using the SQL
    supplied below.
  */

  if (error) {
    console.log(
      "Database tables must be created in Supabase SQL Editor."
    );
  }
}

/* =========================
   AUTH
========================= */

function requireLogin(req, res, next) {

  if (
    !req.session ||
    !req.session.user
  ) {

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

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (!username || !password) {

        return res.status(400).json({
          error:
            "Username and password required"
        });
      }

      const { data, error } =
        await supabase
          .from("users")
          .select(
            "id,username,password_hash,role"
          )
          .eq("username", username)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {

        return res.status(401).json({
          error:
            "Invalid username or password"
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          data.password_hash
        );

      if (!valid) {

        return res.status(401).json({
          error:
            "Invalid username or password"
        });
      }

      req.session.user = {
        id: data.id,
        username: data.username,
        role: data.role
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
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  (req, res) => {

    res.json({
      user:
        req.session &&
        req.session.user
          ? req.session.user
          : null
    });
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  "/api/logout",
  (req, res) => {

    req.session = null;

    res.json({
      success: true
    });
  }
);

/* =========================
   CREATE UPLOADER
========================= */

app.post(
  "/api/users",
  requireAdmin,
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (!username || !password) {

        return res.status(400).json({
          error:
            "Username and password required"
        });
      }

      if (password.length < 8) {

        return res.status(400).json({
          error:
            "Password must be at least 8 characters"
        });
      }

      const { data: existing } =
        await supabase
          .from("users")
          .select("id")
          .eq("username", username)
          .maybeSingle();

      if (existing) {

        return res.status(409).json({
          error:
            "Username already exists"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const { error } =
        await supabase
          .from("users")
          .insert({
            username,
            password_hash: passwordHash,
            role: "uploader"
          });

      if (error) {
        throw error;
      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not create uploader"
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
        String(
          req.body.title || ""
        ).trim();

      const description =
        String(
          req.body.description || ""
        ).trim();

      if (!title) {

        return res.status(400).json({
          error:
            "Video title is required"
        });
      }

      if (
        !req.files ||
        !req.files.video ||
        !req.files.video[0]
      ) {

        return res.status(400).json({
          error:
            "Video file is required"
        });
      }

      const video =
        req.files.video[0];

      videoPath = video.path;

      const extension =
        path.extname(
          video.originalname
        ).toLowerCase() || ".mp4";

      const filename =
        `${Date.now()}-${Math.random()
          .toString(36)
          .slice(2)}${extension}`;

      const videoKey =
        `videos/${filename}`;

      const videoBuffer =
        fs.readFileSync(videoPath);

      const { error: uploadError } =
        await supabase.storage
          .from(BUCKET)
          .upload(
            videoKey,
            videoBuffer,
            {
              contentType:
                video.mimetype ||
                "video/mp4",

              upsert: false
            }
          );

      if (uploadError) {
        throw uploadError;
      }

      let thumbnailKey = null;

      if (
        req.files.thumbnail &&
        req.files.thumbnail[0]
      ) {

        const thumbnail =
          req.files.thumbnail[0];

        thumbnailPath =
          thumbnail.path;

        const thumbExtension =
          path.extname(
            thumbnail.originalname
          ).toLowerCase() || ".jpg";

        thumbnailKey =
          `thumbnails/${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}${thumbExtension}`;

        const thumbBuffer =
          fs.readFileSync(
            thumbnailPath
          );

        const {
          error: thumbError
        } =
          await supabase.storage
            .from(BUCKET)
            .upload(
              thumbnailKey,
              thumbBuffer,
              {
                contentType:
                  thumbnail.mimetype ||
                  "image/jpeg",

                upsert: false
              }
            );

        if (thumbError) {
          throw thumbError;
        }
      }

      const { data, error } =
        await supabase
          .from("videos")
          .insert({
            title,
            description,
            video_key: videoKey,
            thumbnail_key: thumbnailKey,
            uploaded_by:
              req.session.user.id
          })
          .select("id")
          .single();

      if (error) {
        throw error;
      }

      res.json({
        success: true,
        id: data.id
      });

    } catch (error) {

      console.error(
        "UPLOAD ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Video upload failed"
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

app.get(
  "/api/videos",
  async (req, res) => {

    try {

      const { data, error } =
        await supabase
          .from("videos")
          .select(`
            id,
            title,
            description,
            thumbnail_key,
            created_at,
            users(username)
          `)
          .order(
            "created_at",
            {
              ascending: false
            }
          );

      if (error) {
        throw error;
      }

      res.json(
        (data || []).map(video => ({
          id: video.id,
          title: video.title,
          description:
            video.description || "",
          thumbnail:
            !!video.thumbnail_key,
          uploaded_by:
            video.users
              ? video.users.username
              : "Unknown",
          created_at:
            video.created_at
        }))
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load videos"
      });
    }
  }
);

/* =========================
   SINGLE VIDEO
========================= */

app.get(
  "/api/videos/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { data, error } =
        await supabase
          .from("videos")
          .select(
            "id,title,description,video_key,thumbnail_key,created_at"
          )
          .eq("id", id)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {

        return res.status(404).json({
          error:
            "Video not found"
        });
      }

      res.json({
        id: data.id,
        title: data.title,
        description:
          data.description || "",
        created_at:
          data.created_at
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not load video"
      });
    }
  }
);

/* =========================
   VIDEO
========================= */

app.get(
  "/video/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { data, error } =
        await supabase
          .from("videos")
          .select("video_key")
          .eq("id", id)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {

        return res.status(404).send(
          "Video not found"
        );
      }

      const {
        data: publicData
      } =
        supabase.storage
          .from(BUCKET)
          .getPublicUrl(
            data.video_key
          );

      res.redirect(
        publicData.publicUrl
      );

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

      const { data, error } =
        await supabase
          .from("videos")
          .select("thumbnail_key")
          .eq("id", id)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (
        !data ||
        !data.thumbnail_key
      ) {

        return res.status(404).send(
          "Thumbnail not found"
        );
      }

      const {
        data: publicData
      } =
        supabase.storage
          .from(BUCKET)
          .getPublicUrl(
            data.thumbnail_key
          );

      res.redirect(
        publicData.publicUrl
      );

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

      const { data, error } =
        await supabase
          .from("videos")
          .select(
            "title,video_key"
          )
          .eq("id", id)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {

        return res.status(404).send(
          "Video not found"
        );
      }

      const {
        data: publicData
      } =
        supabase.storage
          .from(BUCKET)
          .getPublicUrl(
            data.video_key
          );

      res.redirect(
        publicData.publicUrl
      );

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

      const { data, error } =
        await supabase
          .from("videos")
          .select(
            "video_key,thumbnail_key"
          )
          .eq("id", id)
          .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {

        return res.status(404).json({
          error:
            "Video not found"
        });
      }

      const files = [];

      if (data.video_key) {
        files.push(data.video_key);
      }

      if (data.thumbnail_key) {
        files.push(
          data.thumbnail_key
        );
      }

      if (files.length) {

        await supabase.storage
          .from(BUCKET)
          .remove(files);
      }

      const { error: deleteError } =
        await supabase
          .from("videos")
          .delete()
          .eq("id", id);

      if (deleteError) {
        throw deleteError;
      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Delete failed"
      });
    }
  }
);

/* =========================
   STATIC FILES
========================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {

    console.error(error);

    if (
      error.code ===
      "LIMIT_FILE_SIZE"
    ) {

      return res.status(413).json({
        error:
          "Maximum video size is 50 MB."
      });
    }

    res.status(500).json({
      error:
        error.message ||
        "Server error"
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `MyFlix running on port ${PORT}`
    );
  }
);
