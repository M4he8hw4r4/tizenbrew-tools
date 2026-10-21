// TV Tools - TizenBrew service module. ES5 only (old Node on TV).
"use strict";
var http = require("http");
var fs = require("fs");
var url = require("url");

var PORT = 8090;

function send(res, code, body) {
  res.writeHead(code, { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" });
  res.end(String(body));
}

function tryExec(cmd, res) {
  try {
    var cp = require("child_process");
    cp.exec(cmd, { timeout: 20000, maxBuffer: 4 * 1024 * 1024 }, function (err, stdout, stderr) {
      var out = "EXIT:" + (err ? err.code : 0) + "\n--- STDOUT ---\n" + stdout + "\n--- STDERR ---\n" + stderr;
      send(res, 200, out);
    });
  } catch (e) {
    send(res, 500, "no child_process: " + e.message);
  }
}

var server = http.createServer(function (req, res) {
  var q = url.parse(req.url, true);
  var p = q.pathname;
  try {
    if (p === "/info") {
      var info = {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        uptime: process.uptime(),
        pid: process.pid,
        cwd: process.cwd ? process.cwd() : "?",
        env_user: process.env ? process.env.USER : "?"
      };
      return send(res, 200, JSON.stringify(info, null, 2));
    }
    if (p === "/exec") {
      var cmd = q.query.cmd;
      if (!cmd) return send(res, 400, "usage: /exec?cmd=...");
      return tryExec(cmd, res);
    }
    if (p === "/read") {
      var path = q.query.path;
      if (!path) return send(res, 400, "usage: /read?path=/proc/meminfo");
      try { return send(res, 200, fs.readFileSync(path, "utf8")); }
      catch (e) { return send(res, 500, e.message); }
    }
    if (p === "/ls") {
      var dir = q.query.path || "/";
      try {
        var items = fs.readdirSync(dir).map(function (n) {
          var st;
          try { st = fs.statSync(dir + "/" + n); } catch (e) { st = null; }
          return (st && st.isDirectory() ? "d " : "f ") + n + (st ? " " + st.size : "");
        });
        return send(res, 200, items.join("\n"));
      } catch (e) { return send(res, 500, e.message); }
    }
    if (p === "/write") {
      // GET /write?path=X&data=Y (small files)
      var wp = q.query.path, wd = q.query.data || "";
      if (!wp) return send(res, 400, "usage: /write?path=X&data=Y");
      try { fs.writeFileSync(wp, wd); return send(res, 200, "written " + wp); }
      catch (e) { return send(res, 500, e.message); }
    }
    return send(res, 200, "tv-tools ok. endpoints: /info /exec?cmd= /read?path= /ls?path= /write?path=&data=");
  } catch (e) {
    return send(res, 500, "err: " + e.message);
  }
});

server.on("error", function (e) {
  try { console.log("tv-tools server error: " + e.message); } catch (x) {}
});

server.listen(PORT, "0.0.0.0", function () {
  try { console.log("tv-tools listening on " + PORT); } catch (x) {}
});
