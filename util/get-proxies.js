const request = require('request-promise');
const List = require('./Linked-List');

module.exports = async function GetProxies() {
    //let url = `https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&timeout=4000&country=all`;
	let url = "http://proxy.link/list/get/f8b84a47cc4d364a3629959ac24a10f7"

    let list;
    try {
        let res = await request.get(url);
        
        // validate the proxies
        let array = res.split("\n").filter(proxy => {
            // do not allow emtpy values
            if (proxy === "") {
                return false;
            }
            return true;
        })

        // now validate that we actually got proxies
        // this will validate ip:port
        let regex = new RegExp(/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$/g);
        res = regex.test(array[0]);
        if(res === false){
            throw "bad proxy list";
        }else{
            // make a circular linked list
            list = new List();
            list.arrayToList(array);
        }
		
		
    } catch (error) {
        throw error;
    }
    return list;
};






