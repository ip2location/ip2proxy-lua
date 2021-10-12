local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("JSON")
local urlencode = require("urlencode")

-- for debugging purposes
local function printme(stuff)
  local inspect = require('inspect')
  print(inspect(stuff))
end

ip2proxywebservice = {
  apikey = "",
  apipackage = "",
  usessl = false
}
ip2proxywebservice.__index = ip2proxywebservice

ip2proxyresult = {
  response = '',
  countryCode = '',
  countryName = '',
  regionName = '',
  cityName = '',
  isp = '',
  proxyType = '',
  isProxy = '',
  domain = '',
  usageType = '',
  asn = '',
  as = '',
  lastSeen = '',
  threat = '',
  provider = ''
}
ip2proxyresult.__index = ip2proxyresult

-- initialize the component with the web service configuration
function ip2proxywebservice:open(apikey, apipackage, usessl)
  local x = {}
  setmetatable(x, ip2proxywebservice)  -- make ip2proxywebservice handle lookup

  x.apikey = apikey
  x.apipackage = apipackage
  x.usessl = usessl

  return x
end

-- main query
function ip2proxywebservice:lookup(ipaddress)
  local protocol = "http"
  if self.usessl then
    protocol = "https"
  end
  
  local t = {}
  
  local status, code, headers = http.request {
    method = "GET",
    url = protocol .. "://api.ip2proxy.com/?key=" .. urlencode.encode_url(self.apikey) .. "&package=" .. urlencode.encode_url(self.apipackage) .. "&ip=" .. urlencode.encode_url(ipaddress),
    sink = ltn12.sink.table(t)
  }
  local jsonstr = table.concat(t)
  local result = json:decode(jsonstr)
  setmetatable(result, ip2proxyresult)

  return result
end

-- check web service credit balance
function ip2proxywebservice:get_credit()
  local protocol = "http"
  if self.usessl then
    protocol = "https"
  end
  
  local t = {}
  
  local status, code, headers = http.request {
    method = "GET",
    url = protocol .. "://api.ip2proxy.com/?key=" .. urlencode.encode_url(self.apikey) .. "&check=true",
    sink = ltn12.sink.table(t)
  }
  local jsonstr = table.concat(t)
  local result = json:decode(jsonstr)
  setmetatable(result, ip2proxyresult)

  return result
end

return ip2proxywebservice
