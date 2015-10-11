var crypto = require('crypto')
var _ = require("lodash")

var initialized = false
var config = {
  appid: null,
  appsecret: null,
  noncestr: null,
  access_token: null,
  jsapi_ticket: null
}

/* 
 * 生成随机的noncestr
 **/
crypto.randomBytes(48, function(ex, buf) {
  config.noncestr = buf.toString('hex').substring(0, 32)
});

function init(_config) {
  _.extend(config, _config)
  if (initialized) return
  initialized = true
  refresh()
  setInterval(refresh, 1.5 * 60 * 60 * 1000)
}

function refresh() {
  var url = `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${config.appid}&secret=${config.appsecret}`
  request
    .get(url)
    .end(function(err, res) {
      if (err) throw err;
      var data = JSON.parse(res.text)
      config.access_token = data.access_token
      refreshJsAPITicket()
    })
}

function refreshJsAPITicket() {
  var url = `https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=${config.access_token}&type=jsapi`
  request
    .get(url)
    .end(function(err, res) {
      if (err) throw err;
      var data = JSON.parse(res.text)
      config.jsapi_ticket = data.ticket
    })
}

function signature(url) {
  var noncestr = config.noncestr;
  var timestamp = "" + (+new Date)
  var jsapi_ticket = config.jsapi_ticket;
  var signatureStr = getSignature(noncestr, timestamp, jsapi_ticket)
  return {
    signature: signatureStr,
    noncestr: noncestr,
    timestamp: timestamp
  }
}

function getSignature(noncestr, timestamp, jsapi_ticket) {
  // 微信签名算法
  var shasum = crypto.createHash('sha1');
  var data = [
    {key: "noncestr", value: noncestr},
    {key: "timestamp", value: timestamp}, 
    {key: "jsapi_ticket", value: jsapi_ticket}, 
    {key: "url", value: url}, 
  ]
  data.sort(function(a, b) {
    return a.key.localeCompare(b.key)
  })
  var query = ""
  data.forEach(function(item, i) {
    var prefix = (i !== 0)
      ? "&"
      : ""
    query += `${prefix}${item.key}=${item.value}`
  })
  shasum.update(query)
  return shasum.digest("hex")
}

module.exports = {
  init: init,
  signature: signature,
  config: config
}
