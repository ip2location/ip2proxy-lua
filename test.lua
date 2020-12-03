ip2proxy = require('ip2proxy')

local ip2prox = ip2proxy:open('/usr/data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL.BIN')

local result = ip2prox:get_all('8.8.8.8')

print("country_short: " .. result.country_short)
print("country_long: " .. result.country_long)
print("region: " .. result.region)
print("city: " .. result.city)
print("isp: " .. result.isp)
print("domain: " .. result.domain)
print("usagetype: " .. result.usagetype)
print("asn: " .. result.asn)
print("as: " .. result.as)
print("lastseen: " .. result.lastseen)
print("threat: " .. result.threat)
print("proxytype: " .. result.proxytype)
print("isproxy: " .. result.isproxy)

ip2prox:close()
