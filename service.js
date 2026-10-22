// TV Tools - TizenBrew service module. ES5 only (old Node on TV).
"use strict";
var http = require("http");
var fs = require("fs");
var url = require("url");

var PORT = (typeof module !== "undefined" && module.exports && module.exports.port) || 8090;

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
    if (p === "/adb") {
      // GET /adb?svc=<adb-service-string> — run an adb session from THIS process
      var svc = q.query.svc || "shell:0 debug xvvl3S1bvH.TizenBrewStandalone";
      return adbSession(svc, res);
    }
    if (p === "/adb2") {
      // GET /adb2?msg=<hex> — raw CNXN-free probe: send raw packet hex after CNXN
      var raw = q.query.msg || "";
      return adbRaw(raw, res);
    }
    if (p === "/adbsend") {
      // GET /adbsend?svc=<service>&data=<hex> — OPEN svc then WRTE hex payload, collect replies
      return adbSend(q.query.svc || "sync:", q.query.data || "", res);
    }
    if (p === "/adbuse") {
      // GET /adbuse?svc=<service> — OPEN a stream on the daemon's captured adb socket
      var svc2 = q.query.svc || "shell:id";
      return adbUse(svc2, res);
    }
    return send(res, 200, "tv-tools ok. endpoints: /info /exec?cmd= /read?path= /ls?path= /write?path=&data= /adb?svc= /adb2?msg=hex /adbsend?svc=&data=hex /adbuse?svc=");
  } catch (e) {
    return send(res, 500, "err: " + e.message);
  }
});

function adbPkt(cmd, a0, a1, payload) {
  var b = new Buffer(24 + payload.length);
  b.writeUInt32LE(cmd >>> 0, 0);
  b.writeUInt32LE(a0 >>> 0, 4);
  b.writeUInt32LE(a1 >>> 0, 8);
  b.writeUInt32LE(payload.length, 12);
  var crc = 0;
  for (var i = 0; i < payload.length; i++) crc = (crc + payload[i]) >>> 0;
  b.writeUInt32LE(crc, 16);
  b.writeUInt32LE((~cmd) >>> 0, 20);
  payload.copy(b, 24);
  return b;
}

function adbSession(svc, res) {
  var net = require("net");
  var log = [];
  var s = net.connect(26101, "127.0.0.1");
  var timer = setTimeout(function () {
    try { s.destroy(); } catch (e) {}
    send(res, 200, "TIMEOUT\n" + log.join("\n"));
  }, 4000);
  var lid = 0x1234;
  var rid = 1;
  s.on("connect", function () {
    log.push("tcp-connected");
    s.write(adbPkt(0x4e584e43, 0x01000000, 4096, new Buffer("host::"))); // CNXN
  });
  var acc = new Buffer(0);
  s.on("data", function (d) {
    acc = Buffer.concat([acc, d]);
    while (acc.length >= 24) {
      var cmd = acc.readUInt32LE(0), a0 = acc.readUInt32LE(4), a1 = acc.readUInt32LE(8), len = acc.readUInt32LE(12);
      if (acc.length < 24 + len) break;
      var pay = acc.slice(24, 24 + len);
      log.push("cmd=0x" + cmd.toString(16) + " arg0=" + a0 + " arg1=" + a1 + " len=" + len + " data=" + pay.toString("hex").substr(0, 200));
      acc = acc.slice(24 + len);
      var C = cmd >>> 0;
      if (C === 0x4e584e43) { // CNXN
        lid = a1; rid = a0 || 1;
        s.write(adbPkt(0x4e45504f, lid, rid, new Buffer(svc))); // OPEN
        log.push("sent OPEN " + svc);
      } else if (C === 0x4b4f5441) { // AUTH
        s.write(adbPkt(0x4b4f5441, 2, 0, pay)); // AUTH response w/ type 2
      } else if (C === 0x4f4b4159) { // OKAY
        s.write(adbPkt(0x4f4b4159, a1, a0, new Buffer(0))); // READY? no: send nothing; log
      } else if (C === 0x45545752) { // WRTE
        s.write(adbPkt(0x4f4b4159, a1, a0, new Buffer(0))); // OKAY back
      } else if (C === 0x45534c43) { // CLSE
        clearTimeout(timer);
        try { s.destroy(); } catch (e) {}
        return send(res, 200, "CLSE\n" + log.join("\n"));
      }
    }
  });
  s.on("close", function () {
    clearTimeout(timer);
    send(res, 200, "CLOSED\n" + log.join("\n"));
  });
  s.on("error", function (e) {
    clearTimeout(timer);
    send(res, 200, "ERR " + e.message + "\n" + log.join("\n"));
  });
}

function adbSend(svc, hex, res) {
  var net = require("net");
  var log = [];
  var s = net.connect(26101, "127.0.0.1");
  var timer = setTimeout(function () {
    try { s.destroy(); } catch (e) {}
    send(res, 200, "TIMEOUT\n" + log.join("\n"));
  }, 6000);
  s.on("connect", function () {
    log.push("tcp-connected");
    s.write(adbPkt(0x4e584e43, 0x02000000, 262144, new Buffer("host::\0"))); // CNXN
  });
  var acc = new Buffer(0);
  var sent = false;
  s.on("data", function (d) {
    acc = Buffer.concat([acc, d]);
    while (acc.length >= 24) {
      var cmd = acc.readUInt32LE(0), a0 = acc.readUInt32LE(4), a1 = acc.readUInt32LE(8), len = acc.readUInt32LE(12);
      if (acc.length < 24 + len) break;
      var pay = acc.slice(24, 24 + len);
      log.push("cmd=0x" + cmd.toString(16) + " arg0=" + a0 + " arg1=" + a1 + " len=" + len + " data=" + pay.toString("hex").substr(0, 400) + " ascii=" + pay.toString("utf8").substr(0, 160));
      acc = acc.slice(24 + len);
      var C = cmd >>> 0;
      if (C === 0x4e584e43) { // CNXN
        s.write(adbPkt(0x4e45504f, 0x1111, a0 || 1, new Buffer(svc + "\0"))); // OPEN
        log.push("sent OPEN " + svc);
      } else if (C === 0x59414b4f) { // OKAY
        if (!sent && hex) {
          sent = true;
          s.write(adbPkt(0x45545257, a1, a0, new Buffer(hex, "hex"))); // WRTE
          log.push("sent WRTE " + hex.length / 2 + " bytes");
        } else {
          s.write(adbPkt(0x59414b4f, a1, a0, new Buffer(0))); // OKAY back
        }
      } else if (C === 0x45545257) { // WRTE
        s.write(adbPkt(0x59414b4f, a1, a0, new Buffer(0))); // OKAY back
      } else if (C === 0x45534c43) { // CLSE
        clearTimeout(timer);
        try { s.destroy(); } catch (e) {}
        return send(res, 200, "CLSE\n" + log.join("\n"));
      }
    }
  });
  s.on("close", function () {
    clearTimeout(timer);
    send(res, 200, "CLOSED\n" + log.join("\n"));
  });
  s.on("error", function (e) {
    clearTimeout(timer);
    send(res, 200, "ERR " + e.message + "\n" + log.join("\n"));
  });
}

var capturedSdb = null;
try {
  var _net = require("net");
  var _origConn = _net.connect || _net.createConnection;
  var wrap = function () {
    var s = _origConn.apply(_net, arguments);
    try {
      s.on("connect", function () {
        try {
          if (s.remotePort === 26101) {
            capturedSdb = s;
            var caplog = "/tmp/caplog.txt";
            fs.writeFileSync("/tmp/capsdb.txt", "captured " + s.remoteAddress + ":" + s.remotePort + " " + new Date().toISOString());
            fs.writeFileSync(caplog, "CONNECT " + s.localPort + "\n");
            var ow = s.write;
            s.write = function (d) {
              try { fs.appendFileSync(caplog, "OUT " + (d && d.length ? new Buffer(d).toString("hex").substr(0, 300) : "?") + "\n"); } catch (e) {}
              return ow.apply(s, arguments);
            };
            s.on("data", function (d) {
              try { fs.appendFileSync(caplog, "IN " + d.toString("hex").substr(0, 300) + "\n"); } catch (e) {}
            });
            s.on("close", function () {
              try { fs.appendFileSync(caplog, "CLOSE\n"); capturedSdb = null; } catch (e) {}
            });
            s.on("error", function (e2) {
              try { fs.appendFileSync(caplog, "ERR " + e2.message + "\n"); } catch (e) {}
            });
          }
        } catch (e) {}
      });
    } catch (e) {}
    return s;
  };
  _net.connect = wrap;
  _net.createConnection = wrap;
  _net.Socket.prototype.connect = (function (orig) {
    return function () {
      var s = orig.apply(this, arguments);
      var self = this;
      this.once("connect", function () {
        try {
          if (self.remotePort === 26101) {
            capturedSdb = self;
            fs.writeFileSync("/tmp/capsdb.txt", "captured-sock " + new Date().toISOString());
          }
        } catch (e) {}
      });
      return s;
    };
  })(_net.Socket.prototype.connect);
  fs.writeFileSync("/tmp/netpatch.txt", "patched " + new Date().toISOString());
} catch (e) {
  try { fs.writeFileSync("/tmp/netpatch.txt", "patch fail " + e.message); } catch (x) {}
}

function adbUse(svc, res) {
  var log = [];
  if (!capturedSdb || capturedSdb.destroyed) {
    return send(res, 200, "no captured socket. marker: " + (function(){try{return fs.readFileSync("/tmp/capsdb.txt","utf8");}catch(e){return e.message;}})());
  }
  var acc = new Buffer(0);
  var onData = function (d) {
    acc = Buffer.concat([acc, d]);
    while (acc.length >= 24) {
      var cmd = acc.readUInt32LE(0), a0 = acc.readUInt32LE(4), a1 = acc.readUInt32LE(8), len = acc.readUInt32LE(12);
      if (acc.length < 24 + len) break;
      var pay = acc.slice(24, 24 + len);
      log.push("cmd=0x" + cmd.toString(16) + " arg0=" + a0 + " arg1=" + a1 + " len=" + len + " data=" + pay.toString("hex").substr(0, 300) + " ascii=" + pay.toString("utf8").substr(0, 120));
      acc = acc.slice(24 + len);
    }
  };
  capturedSdb.on("data", onData);
  var lid = 0x7777, rid = 0x1000 + Math.floor(Math.random() * 1000);
  try {
    capturedSdb.write(adbPkt(0x4e45504f, lid, rid, new Buffer(svc)));
    log.push("wrote OPEN local=" + lid + " svc=" + svc);
  } catch (e) {
    return send(res, 200, "write fail: " + e.message);
  }
  setTimeout(function () {
    try { capturedSdb.removeListener("data", onData); } catch (e) {}
    send(res, 200, log.join("\n"));
  }, 2500);
}

function adbRaw(hex, res) {
  var net = require("net");
  var log = [];
  var s = net.connect(26101, "127.0.0.1");
  var timer = setTimeout(function () {
    try { s.destroy(); } catch (e) {}
    send(res, 200, "TIMEOUT\n" + log.join("\n"));
  }, 4000);
  s.on("connect", function () {
    log.push("tcp-connected");
    s.write(adbPkt(0x4e584e43, 0x01000000, 4096, new Buffer("host::")));
    if (hex) setTimeout(function () { s.write(new Buffer(hex, "hex")); }, 400);
  });
  s.on("data", function (d) {
    log.push("data: " + d.toString("hex").substr(0, 300));
  });
  s.on("close", function () { clearTimeout(timer); send(res, 200, "CLOSED\n" + log.join("\n")); });
  s.on("error", function (e) { clearTimeout(timer); send(res, 200, "ERR " + e.message + "\n" + log.join("\n")); });
}

server.on("error", function (e) {
  try { console.log("tv-tools server error: " + e.message); } catch (x) {}
});

var BIND_PORT = PORT;
server.on("error", function (e) {
  try {
    if (e && e.code === "EADDRINUSE" && BIND_PORT < PORT + 20) {
      BIND_PORT++;
      server.listen(BIND_PORT, "0.0.0.0");
    }
  } catch (x) {}
});
server.on("listening", function () {
  try { fs.writeFileSync("/tmp/tvport.txt", "listening " + BIND_PORT + " pid=" + process.pid); } catch (e) {}
});
server.listen(BIND_PORT, "0.0.0.0", function () {
  try { console.log("tv-tools listening on " + BIND_PORT); } catch (x) {}
});

// One-shot adb probe on load: log result to /tmp/adbprobe.txt
try {
  (function () {
    var out = [];
    adbSession("shell:0 debug xvvl3S1bvH.TizenBrewStandalone", {
      writeHead: function () {},
      end: function (body) {
        try { require("fs").writeFileSync("/tmp/adbprobe.txt", String(body)); } catch (e) {}
      }
    });
  })();
} catch (e) {
  try { require("fs").writeFileSync("/tmp/adbprobe.txt", "ex " + e.message); } catch (x) {}
}
