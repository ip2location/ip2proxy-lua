# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Installation

To install the library, use the following command:

```
luarocks install ip2proxy
```

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

```lua

ip2proxy = require('ip2proxy')

local ip2prox = ip2proxy:open('/usr/data/IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN')

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
print("provider: " .. result.provider)
print("proxytype: " .. result.proxytype)
print("isproxy: " .. result.isproxy)

ip2prox:close()
```