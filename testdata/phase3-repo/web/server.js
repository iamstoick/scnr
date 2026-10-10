const express = require("express");
const app = express();
app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });
app.get("/go", (req, res) => res.redirect(req.query.next));
app.get("/file", (req, res) => res.sendFile(path.join(__dirname, req.query.name)));
const token = Math.random().toString(36);
app.listen(3000, "0.0.0.0");
