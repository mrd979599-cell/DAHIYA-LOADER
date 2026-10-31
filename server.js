require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const DB = path.join(__dirname, "data", "keys.json");

function readKeys() {
    if (!fs.existsSync(DB)) return [];
    return JSON.parse(fs.readFileSync(DB, "utf8"));
}

function saveKeys(keys) {
    fs.writeFileSync(DB, JSON.stringify(keys, null, 2));
}

function auth(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];

    try {
        req.admin = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: "Unauthorized" });
    }
}

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    if (
        username !== process.env.ADMIN_USER ||
        password !== process.env.ADMIN_PASSWORD
    ) {
        return res.status(401).json({ error: "Invalid login" });
    }

    const token = jwt.sign(
        { username },
        process.env.JWT_SECRET,
        { expiresIn: "4h" }
    );

    res.json({ token });
});

app.get("/api/keys", auth, (req, res) => {
    res.json(readKeys());
});

app.post("/api/keys", auth, (req, res) => {
    const days = Number(req.body.days);

    if (![1, 7, 30].includes(days)) {
        return res.status(400).json({ error: "Invalid duration" });
    }

    const keys = readKeys();

    const key = "DAHIYA-" +
        crypto.randomBytes(8).toString("hex").toUpperCase();

    const record = {
        key,
        days,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(
            Date.now() + days * 86400000
        ).toISOString(),
        active: true
    };

    keys.push(record);
    saveKeys(keys);

    res.json(record);
});

app.post("/api/keys/:key/toggle", auth, (req, res) => {
    const keys = readKeys();
    const item = keys.find(k => k.key === req.params.key);

    if (!item) {
        return res.status(404).json({ error: "Key not found" });
    }

    item.active = !item.active;
    saveKeys(keys);

    res.json(item);
});

app.post("/api/verify-key", (req, res) => {
    const key = String(req.body.key || "").trim();

    if (!key) {
        return res.status(400).json({ valid: false, message: "Key required" });
    }

    const item = readKeys().find(k => k.key === key);

    if (!item) {
        return res.status(401).json({ valid: false, message: "Invalid key" });
    }

    if (item.active !== true) {
        return res.status(403).json({ valid: false, message: "Key disabled" });
    }

    if (!item.expiresAt || Date.now() >= Date.parse(item.expiresAt)) {
        return res.status(403).json({ valid: false, message: "Key expired" });
    }

    return res.json({
        valid: true,
        message: "Key verified",
        expiresAt: item.expiresAt
    });
});

app.get("/api/health", (req, res) => {
    res.json({ status: "OK", name: "DAHIYA LOADER" });
});

const PORT = process.env.PORT || 3000;

if (!process.env.ADMIN_USER ||
    !process.env.ADMIN_PASSWORD ||
    !process.env.JWT_SECRET) {
    throw new Error("Admin credentials missing in .env");
}

app.listen(PORT, "0.0.0.0", () => {
    console.log("DAHIYA LOADER ADMIN SERVER ONLINE");
    console.log("Port:", PORT);
});
