"use strict";

const request = require('request-promise');
const List = require('./linked-List');

const url = "http://proxy.link/list/get/f8b84a47cc4d364a3629959ac24a10f7"

/**
 * Returns a circular linked lists of proxies
 */
module.exports = async () => {
    try {
        let res = await request.get(url);

        // validate the proxies
        let proxyArray = res.split("\n").filter(proxy => {
            // do not allow emtpy values
            if (proxy === "") {
                return false;
            }
            return true;
        })

        // make a circular linked list
        return new List(proxyArray);
    } catch (error) {
        throw error;
    }
}