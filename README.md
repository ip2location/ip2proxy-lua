# IP2Proxy Lua Package

This package allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: https://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy


## Installation

```
luarocks install ip2proxy
```

## Functions
Below are the functions supported in this package.

|Function Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup.|
|close|Close and clean up the file pointer.|
|get_package_version|Get the package version (1 to 10 for PX1 to PX10 respectively).|
|get_module_version|Get the module version.|
|get_database_version|Get the database version.|
|isproxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|get_all|Return the proxy information in an object.|
|get_proxytype|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported|
|get_country_short|Return the ISO3166-1 country code (2-digits) of the proxy.|
|get_country_long|Return the ISO3166-1 country name of the proxy.|
|get_region|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported|
|get_city|Return the city name of the proxy.|
|get_isp|Return the ISP name of the proxy.|
|get_domain|Return the domain name of the proxy.|
|get_usagetype|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|get_asn|Return the autonomous system number of the proxy.|
|get_as|Return the autonomous system name of the proxy.|
|get_lastseen|Return the number of days that the proxy was last seen.|
|get_threat|Return the threat type of the proxy.|

## Usage

```lua

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

```
