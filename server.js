require("dotenv").config();
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const multer = require("multer");
const app = express();
const mongoose = require("mongoose");

const IS_PROD = process.env.NODE_ENV === "production";

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public"), { maxAge: IS_PROD ? "7d" : 0 }));

if (!process.env.SESSION_SECRET) {
  if (IS_PROD) {
    console.error("SESSION_SECRET is required in production — set it in Render's Environment tab");
    process.exit(1);
  } else {
    console.warn("SESSION_SECRET not set — using dev fallback");
  }
}

app.use(
  session({
    name: "fob.sid",
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    proxy: IS_PROD,
    cookie: {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

const UPLOAD_ROOT = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_ROOT)) {
  fs.mkdirSync(UPLOAD_ROOT, { recursive: true });
}

const URI = process.env.MONGO_URI;
if (!URI) {
  console.error("MONGO_URI is missing — set it in Render's Environment tab");
  process.exit(1);
}

mongoose
  .connect(URI, { serverSelectionTimeoutMS: 10000 })
  .then((conn) => console.log(`MongoDB connected: ${conn.connection.host}`))
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      unique: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [50, "Name must be under 50 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      lowercase: true,
      unique: true,
      match: [/^\S+@\S+\.\S+$/, "Please enter a valid email"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select: false,
    },
  },
  { timestamps: true }
);

UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

const User = mongoose.model("User", UserSchema);

const FileSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: [true, "Title is required"],
      trim: true,
      maxlength: [120, "Title must be under 120 characters"],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [500, "Description must be under 500 characters"],
      default: "",
    },
    category: {
      type: String,
      enum: ["image", "pdf", "document", "spreadsheet", "presentation", "video", "audio", "archive", "other"],
      default: "other",
    },
    originalName: { type: String, required: true },
    storedName: { type: String, required: true },
    size: { type: Number, required: true },
    mimetype: { type: String, required: true },
    downloads: { type: Number, default: 0 },
    ratings: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
        value: { type: Number, min: 1, max: 5, required: true },
      },
    ],
  },
  { timestamps: true }
);

FileSchema.index({ createdAt: -1 });
FileSchema.index({ category: 1, createdAt: -1 });

const File = mongoose.model("File", FileSchema);

const SubscriptionSchema = new mongoose.Schema(
  {
    subscriber: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    channel: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

SubscriptionSchema.index({ subscriber: 1, channel: 1 }, { unique: true });

const Subscription = mongoose.model("Subscription", SubscriptionSchema);

function detectCategory(mimetype, ext) {
  if (mimetype.startsWith("image/")) return "image";
  if (mimetype === "application/pdf" || ext === "pdf") return "pdf";
  if (["doc", "docx", "odt", "rtf", "txt", "md"].includes(ext)) return "document";
  if (["xls", "xlsx", "ods", "csv"].includes(ext)) return "spreadsheet";
  if (["ppt", "pptx", "odp"].includes(ext)) return "presentation";
  if (mimetype.startsWith("video/")) return "video";
  if (mimetype.startsWith("audio/")) return "audio";
  if (["zip", "rar", "7z", "tar", "gz"].includes(ext)) return "archive";
  return "other";
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(UPLOAD_ROOT, req.session.userId);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).slice(0, 10);
    cb(null, unique + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
});

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.redirect("/login");
  next();
};

app.get("/healthz", (req, res) => res.status(200).json({ ok: true }));

app.get("/", async (req, res) => {
  if (!req.session.userId) {
    return res.render("index", {
      files: [],
      filesJSON: "[]",
      subscriptionsCount: 0,
    });
  }

  try {
    const files = await File.find()
      .populate("owner", "name")
      .sort({ createdAt: -1 })
      .lean();

    const userId = req.session.userId;
    const filesForClient = files.map((f) => {
      const avg = f.ratings.length
        ? f.ratings.reduce((s, r) => s + r.value, 0) / f.ratings.length
        : 0;
      const mine = f.ratings.find((r) => r.user.toString() === userId);
      return {
        id: f._id.toString(),
        title: f.title,
        description: f.description || "",
        category: f.category,
        originalName: f.originalName,
        ext: path.extname(f.originalName).slice(1).toLowerCase(),
        size: f.size,
        mimetype: f.mimetype,
        downloads: f.downloads,
        createdAt: f.createdAt,
        owner: {
          id: f.owner._id.toString(),
          name: f.owner.name,
        },
        avgRating: Number(avg.toFixed(1)),
        ratingCount: f.ratings.length,
        userRating: mine ? mine.value : 0,
        isOwner: f.owner._id.toString() === userId,
      };
    });

    res.render("index", {
      files,
      filesJSON: JSON.stringify(filesForClient),
      subscriptionsCount: 0,
    });
  } catch (err) {
    console.error("Index error:", err);
    res.render("index", { files: [], filesJSON: "[]", subscriptionsCount: 0 });
  }
});

app.get("/signup", (req, res) => {
  if (req.session.userId) return res.redirect("/");
  res.render("signup", { error: null, old: {} });
});

app.get("/login", (req, res) => {
  if (req.session.userId) return res.redirect("/");
  res.render("login", { error: null, old: {} });
});

app.post("/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: "All fields are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: "Password must be at least 6 characters" });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2) {
      return res.status(400).json({ success: false, error: "Name must be at least 2 characters" });
    }
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ success: false, error: "Please enter a valid email" });
    }

    const existing = await User.findOne({
      $or: [{ email: cleanEmail }, { name: cleanName }],
    });

    if (existing) {
      if (existing.email === cleanEmail) {
        return res.status(400).json({ success: false, error: "An account with this email already exists" });
      }
      return res.status(400).json({ success: false, error: "This name is already taken" });
    }

    const user = await User.create({ name: cleanName, email: cleanEmail, password });

    req.session.userId = user._id.toString();
    req.session.user = { id: user._id, name: user.name, email: user.email };

    return res.status(201).json({ success: true, redirect: "/" });
  } catch (err) {
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ success: false, error: `This ${field} is already taken` });
    }
    if (err.name === "ValidationError") {
      const first = Object.values(err.errors)[0];
      return res.status(400).json({ success: false, error: first.message });
    }
    console.error("Signup error:", err);
    return res.status(500).json({ success: false, error: "Something went wrong" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email and password are required" });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
      return res.status(400).json({ success: false, error: "Please enter a valid email" });
    }

    const user = await User.findOne({ email: cleanEmail }).select("+password");
    if (!user) return res.status(400).json({ success: false, error: "Invalid email or password" });

    const match = await user.comparePassword(password);
    if (!match) return res.status(400).json({ success: false, error: "Invalid email or password" });

    req.session.userId = user._id.toString();
    req.session.user = { id: user._id, name: user.name, email: user.email };

    return res.status(200).json({ success: true, redirect: "/" });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, error: "Something went wrong" });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("fob.sid");
    res.redirect("/login");
  });
});

app.get("/upload", requireAuth, (req, res) => {
  res.render("upload", { error: null });
});

app.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render("upload", { error: "Please choose a file" });
    }

    const title = (req.body.title || "").trim();
    const description = (req.body.description || "").trim();

    if (!title) {
      fs.unlinkSync(req.file.path);
      return res.status(400).render("upload", { error: "Title is required" });
    }

    const ext = path.extname(req.file.originalname).slice(1).toLowerCase();
    const category = detectCategory(req.file.mimetype, ext);

    await File.create({
      owner: req.session.userId,
      title,
      description,
      category,
      originalName: req.file.originalname,
      storedName: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype,
    });

    return res.redirect("/");
  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).render("upload", { error: "Upload failed, please try again" });
  }
});

app.get("/file/:id/raw", requireAuth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).end();

    const filePath = path.join(UPLOAD_ROOT, file.owner.toString(), file.storedName);
    if (!fs.existsSync(filePath)) return res.status(404).end();

    res.setHeader("Content-Type", file.mimetype);
    res.setHeader("Content-Disposition", "inline");
    res.setHeader("Cache-Control", "private, max-age=3600");
    return res.sendFile(filePath);
  } catch (err) {
    console.error("Raw error:", err);
    return res.status(500).end();
  }
});

app.get("/file/:id/download", requireAuth, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).render("404", { message: "File not found" });

    const filePath = path.join(UPLOAD_ROOT, file.owner.toString(), file.storedName);
    if (!fs.existsSync(filePath)) {
      return res.status(404).render("404", { message: "File missing on disk" });
    }

    await File.updateOne({ _id: file._id }, { $inc: { downloads: 1 } });

    return res.download(filePath, file.originalName);
  } catch (err) {
    console.error("Download error:", err);
    return res.status(500).render("404", { message: "Download failed" });
  }
});

app.post("/file/:id/delete", requireAuth, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.id,
      owner: req.session.userId,
    });

    if (!file) return res.status(404).json({ success: false, error: "File not found or not yours" });

    const filePath = path.join(UPLOAD_ROOT, file.owner.toString(), file.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await File.deleteOne({ _id: file._id });

    if (req.headers.accept && req.headers.accept.includes("application/json")) {
      return res.json({ success: true });
    }
    return res.redirect("/");
  } catch (err) {
    console.error("Delete error:", err);
    return res.status(500).json({ success: false, error: "Delete failed" });
  }
});

app.post("/file/:id/rate", requireAuth, async (req, res) => {
  try {
    const value = parseInt(req.body.value, 10);
    if (!value || value < 1 || value > 5) {
      return res.status(400).json({ success: false, error: "Rating must be 1–5" });
    }

    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ success: false, error: "File not found" });

    if (file.owner.toString() === req.session.userId) {
      return res.status(400).json({ success: false, error: "You can't rate your own file" });
    }

    const existing = file.ratings.find(
      (r) => r.user.toString() === req.session.userId
    );

    if (existing) {
      existing.value = value;
    } else {
      file.ratings.push({ user: req.session.userId, value });
    }

    await file.save();

    const avg = file.ratings.reduce((s, r) => s + r.value, 0) / file.ratings.length;

    return res.json({
      success: true,
      avg: Number(avg.toFixed(1)),
      count: file.ratings.length,
      userRating: value,
    });
  } catch (err) {
    console.error("Rate error:", err);
    return res.status(500).json({ success: false, error: "Rating failed" });
  }
});

app.post("/subscribe/:userId", requireAuth, async (req, res) => {
  try {
    const channelId = req.params.userId;

    if (channelId === req.session.userId) {
      return res.status(400).json({ success: false, error: "You can't subscribe to yourself" });
    }

    const target = await User.findById(channelId).select("_id");
    if (!target) return res.status(404).json({ success: false, error: "User not found" });

    const existing = await Subscription.findOne({
      subscriber: req.session.userId,
      channel: channelId,
    });

    let subscribed;
    if (existing) {
      await Subscription.deleteOne({ _id: existing._id });
      subscribed = false;
    } else {
      await Subscription.create({
        subscriber: req.session.userId,
        channel: channelId,
      });
      subscribed = true;
    }

    const count = await Subscription.countDocuments({ channel: channelId });

    return res.json({ success: true, subscribed, count });
  } catch (err) {
    console.error("Subscribe error:", err);
    return res.status(500).json({ success: false, error: "Subscribe failed" });
  }
});

app.get("/api/subscription-status/:userId", requireAuth, async (req, res) => {
  try {
    const channelId = req.params.userId;
    const subscribed = await Subscription.exists({
      subscriber: req.session.userId,
      channel: channelId,
    });
    const count = await Subscription.countDocuments({ channel: channelId });
    return res.json({ subscribed: !!subscribed, count });
  } catch (err) {
    console.error("Sub status error:", err);
    return res.status(500).json({ subscribed: false, count: 0 });
  }
});

app.use((req, res) => {
  res.status(404).render("404", {
    message: `The page "${req.originalUrl}" was not found.`,
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);

  if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).render("upload", { error: "File is too large (max 50 MB)" });
  }

  res.status(err.status || 500).render("404", {
    message: IS_PROD ? "Something went wrong." : err.message || "Something went wrong.",
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server listening on port ${PORT}`));
