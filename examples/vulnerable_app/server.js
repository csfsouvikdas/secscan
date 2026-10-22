// INTENTIONALLY VULNERABLE demo (SecScan). Never deploy this.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const app = express();

app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });

app.get("/search", (req, res) => {
  db.query("SELECT * FROM items WHERE name = '" + req.query.q + "'", (err, rows) => res.json(rows));
});

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (e, out) => res.send(out));
});

app.get("/file", (req, res) => {
  res.send(fs.readFileSync(req.query.path));
});

app.get("/page", (req, res) => {
  res.send(`<script>document.getElementById("x").innerHTML = "${req.query.msg}"</script>`);
});

const token = Math.random().toString(36);
const digest = crypto.createHash("md5").update("data").digest("hex");
const agent = { rejectUnauthorized: false };
app.get("/eval", (req, res) => res.send(String(eval(req.query.code))));

app.listen(3000, "0.0.0.0");
