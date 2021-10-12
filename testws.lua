ip2proxywebservice = require('ip2proxywebservice')

local apikey = 'YOUR_API_KEY'
local apipackage = 'PX11'
local usessl = true
local ip = '8.8.8.8'
local ws = ip2proxywebservice:open(apikey, apipackage, usessl)

local result = ws:lookup(ip)

print("response: " .. result.response)
print("countryCode: " .. result.countryCode)
print("countryName: " .. result.countryName)
print("regionName: " .. result.regionName)
print("cityName: " .. result.cityName)
print("isp: " .. result.isp)
print("domain: " .. result.domain)
print("usageType: " .. result.usageType)
print("asn: " .. result.asn)
print("as: " .. result.as)
print("lastSeen: " .. result.lastSeen)
print("threat: " .. result.threat)
print("provider: " .. result.provider)
print("proxyType: " .. result.proxyType)
print("isProxy: " .. result.isProxy)

local result2 = ws:get_credit()
print("Credit Balance: " .. result2.response)
