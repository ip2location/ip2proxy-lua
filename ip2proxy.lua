bn = require("nums.bn")

ip2proxy = {
  metaok = false,
  databasetype = 0,
  databasecolumn = 0,
  databaseday = 0,
  databasemonth = 0,
  databaseyear = 0,
  ipv4databasecount = 0,
  ipv4databaseaddr = 0,
  ipv6databasecount = 0,
  ipv6databaseaddr = 0,
  ipv4indexbaseaddr = 0,
  ipv6indexbaseaddr = 0,
  ipv4columnsize = 0,
  ipv6columnsize = 0,
  columnsize_without_ip = 0,
  country_position_offset = 0,
  region_position_offset = 0,
  city_position_offset = 0,
  isp_position_offset = 0,
  proxytype_position_offset = 0,
  domain_position_offset = 0,
  usagetype_position_offset = 0,
  asn_position_offset = 0,
  as_position_offset = 0,
  lastseen_position_offset = 0,
  threat_position_offset = 0,
  country_enabled = false,
  region_enabled = false,
  city_enabled = false,
  isp_enabled = false,
  proxytype_enabled = false,
  domain_enabled = false,
  usagetype_enabled = false,
  asn_enabled = false,
  as_enabled = false,
  lastseen_enabled = false,
  threat_enabled = false
}
ip2proxy.__index = ip2proxy

ip2proxyrecord = {
  country_short = '',
  country_long = '',
  region = '',
  city = '',
  isp = '',
  proxytype = '',
  isproxy = '',
  domain = '',
  usagetype = '',
  asn = '',
  as = '',
  lastseen = '',
  threat = ''
}
ip2proxyrecord.__index = ip2proxyrecord

local max_ipv4_range = bn(4294967295)
local max_ipv6_range= bn("340282366920938463463374607431768211455")
local from_v4mapped = bn("281470681743360")
local to_v4mapped = bn("281474976710655")
local from_6to4 = bn("42545680458834377588178886921629466624")
local to_6to4 = bn("42550872755692912415807417417958686719")
local from_teredo = bn("42540488161975842760550356425300246528")
local to_teredo = bn("42540488241204005274814694018844196863")

local country_position = {0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3}
local region_position = {0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4}
local city_position = {0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5}
local isp_position = {0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6}
local proxytype_position = {0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2}
local domain_position = {0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7}
local usagetype_position = {0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8}
local asn_position = {0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9}
local as_position = {0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10}
local lastseen_position = {0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11}
local threat_position = {0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12}

local api_version = "3.0.0"

local modes = {
  countryshort = 0x00001,
  countrylong = 0x00002,
  region = 0x00004,
  city = 0x00008,
  isp = 0x00010,
  proxytype = 0x00020,
  isproxy = 0x00040,
  domain = 0x00080,
  usagetype = 0x00100,
  asn = 0x00200,
  as = 0x00400,
  lastseen = 0x00800,
  threat = 0x01000
}

modes.all = modes.countryshort | modes.countrylong | modes.region | modes.city | modes.isp | modes.proxytype | modes.isproxy | modes.domain | modes.usagetype | modes.asn | modes.as | modes.lastseen | modes.threat

local invalid_address = "Invalid IP address."
local missing_file = "Invalid database file."
local not_supported = "This parameter is unavailable for selected data file. Please upgrade the data file."

-- for debugging purposes
local function printme(stuff)
  local inspect = require('inspect')
  print(inspect(stuff))
end

-- read byte
local function readuint8(pos, myfile)
  myfile:seek("set", pos - 1)
  local bytestr = myfile:read(1)
  local value = 0 -- no need BigNum
  if bytestr ~= nil then
    value = string.byte(bytestr)
  end
  return value
end

-- read unsigned 32-bit integer
local function readuint32(pos, myfile)
  myfile:seek("set", pos - 1)
  local bytestr = myfile:read(4)
  local value = bn.ZERO
  if bytestr ~= nil then
    value = bn(string.unpack("<I4", bytestr))
  end
  return value
end

-- read unsigned 32-bit integer
local function readuint32row(pos, row)
  local pos2 = pos + 1 -- due to index starting with 1
  local bytestr = string.sub(row, pos2, pos2 + 3) -- strip 4 bytes
  local value = bn.ZERO
  if bytestr ~= nil then
    value = bn(string.unpack("<I4", bytestr))
  end
  return value
end

-- read unsigned 128-bit integer
local function readuint128(pos, myfile)
  myfile:seek("set", pos - 1)
  local bytestr = myfile:read(16)
  local value = bn.ZERO
  if bytestr ~= nil then
    value = bn(string.unpack("<I8", bytestr)) + (bn(string.unpack("<I8", bytestr, 9)) << 64) -- cannot read 16 bytes at once so split into 2
  end
  return value
end

-- read string
local function readstr(pos, myfile)
  myfile:seek("set", pos)
  local len = myfile:read(1)
  local strlen = 0
  if len ~= nil then
    strlen = string.byte(len)
  end
  myfile:seek("set", pos + 1)
  local bytestr = myfile:read(strlen)
  local value = ''
  if bytestr ~= nil then
    value = bytestr
  end
  return value
end

-- read float
local function readfloat(pos, myfile)
  myfile:seek("set", pos - 1)
  local bytestr = myfile:read(4)
  local value = 0.0
  if bytestr ~= nil then
    value = string.unpack("f", bytestr)
  end
  return value
end

-- read float
local function readfloatrow(pos, row)
  local pos2 = pos + 1 -- due to index starting with 1
  local bytestr = string.sub(row, pos2, pos2 + 3) -- strip 4 bytes
  local value = 0.0
  if bytestr ~= nil then
    value = string.unpack("f", bytestr)
  end
  return value
end

-- initialize the component with the database path
function ip2proxy:open(dbpath)
  local x = {}
  setmetatable(x, ip2proxy)  -- make ip2proxy handle lookup

  local file, err = io.open(dbpath, "rb")
  if file == nil then
    -- error("Couldn't open file: "..err)
    -- printme(x)
    return x
  else
    x.f = file
  end
  x.databasetype = readuint8(1, x.f)
  x.databasecolumn = readuint8(2, x.f)
  x.databaseyear = readuint8(3, x.f)
  x.databasemonth = readuint8(4, x.f)
  x.databaseday = readuint8(5, x.f)

  x.ipv4databasecount = readuint32(6, x.f):asnumber()
  x.ipv4databaseaddr = readuint32(10, x.f):asnumber()
  x.ipv6databasecount = readuint32(14, x.f):asnumber()
  x.ipv6databaseaddr = readuint32(18, x.f):asnumber()
  x.ipv4indexbaseaddr = readuint32(22, x.f):asnumber()
  x.ipv6indexbaseaddr = readuint32(26, x.f):asnumber()
  x.ipv4columnsize = x.databasecolumn * 4 -- 4 bytes each column
  x.ipv6columnsize = 16 + ((x.databasecolumn - 1) * 4) -- 4 bytes each column, except IPFrom column which is 16 bytes
  x.columnsize_without_ip = (x.databasecolumn - 1) * 4 -- 4 bytes each column, minus the IPFrom column

  local dbt = x.databasetype

  -- since both IPv4 and IPv6 use 4 bytes for the below columns, can just do it once here
  if country_position[dbt] ~= 0 then
    -- x.country_position_offset = (country_position[dbt] - 1) * 4
    x.country_position_offset = (country_position[dbt] - 2) * 4
    x.country_enabled = true
  end
  if region_position[dbt] ~= 0 then
    -- x.region_position_offset = (region_position[dbt] - 1) * 4
    x.region_position_offset = (region_position[dbt] - 2) * 4
    x.region_enabled = true
  end
  if city_position[dbt] ~= 0 then
    -- x.city_position_offset = (city_position[dbt] - 1) * 4
    x.city_position_offset = (city_position[dbt] - 2) * 4
    x.city_enabled = true
  end
  if isp_position[dbt] ~= 0 then
    -- x.isp_position_offset = (isp_position[dbt] - 1) * 4
    x.isp_position_offset = (isp_position[dbt] - 2) * 4
    x.isp_enabled = true
  end
  if proxytype_position[dbt] ~= 0 then
    -- x.proxytype_position_offset = (proxytype_position[dbt] - 1) * 4
    x.proxytype_position_offset = (proxytype_position[dbt] - 2) * 4
    x.proxytype_enabled = true
  end
  if domain_position[dbt] ~= 0 then
    -- x.domain_position_offset = (domain_position[dbt] - 1) * 4
    x.domain_position_offset = (domain_position[dbt] - 2) * 4
    x.domain_enabled = true
  end
  if usagetype_position[dbt] ~= 0 then
    -- x.usagetype_position_offset = (usagetype_position[dbt] - 1) * 4
    x.usagetype_position_offset = (usagetype_position[dbt] - 2) * 4
    x.usagetype_enabled = true
  end
  if asn_position[dbt] ~= 0 then
    -- x.asn_position_offset = (asn_position[dbt] - 1) * 4
    x.asn_position_offset = (asn_position[dbt] - 2) * 4
    x.asn_enabled = true
  end
  if as_position[dbt] ~= 0 then
    -- x.as_position_offset = (as_position[dbt] - 1) * 4
    x.as_position_offset = (as_position[dbt] - 2) * 4
    x.as_enabled = true
  end
  if lastseen_position[dbt] ~= 0 then
    -- x.lastseen_position_offset = (lastseen_position[dbt] - 1) * 4
    x.lastseen_position_offset = (lastseen_position[dbt] - 2) * 4
    x.lastseen_enabled = true
  end
  if threat_position[dbt] ~= 0 then
    -- x.threat_position_offset = (threat_position[dbt] - 1) * 4
    x.threat_position_offset = (threat_position[dbt] - 2) * 4
    x.threat_enabled = true
  end

  x.metaok = true
  -- printme(x)
  return x
end

-- close file and reset
function ip2proxy:close()
  self.metaok = false
  io.close(self.f)
end

-- get IP type and calculate IP number; calculates index too if exists
function ip2proxy:checkip(ip)
  local R = {ERROR = 0, IPV4 = 4, IPV6 = 6}
  if type(ip) ~= "string" then return R.ERROR end

  -- check for format 1.11.111.111 for ipv4
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    local ipnum = bn.ZERO
    local octet = 0
    for x,v in pairs(chunks) do
      octet = tonumber(v)
      if octet > 255 then return R.ERROR end
      ipnum = ipnum + (bn(octet) << (8 * (4 - x)))
    end

    local ipindex = 0;
    if self.ipv4indexbaseaddr > 0 then
      ipindex = ((ipnum >> 16) << 3):asnumber() + self.ipv4indexbaseaddr
    end
    return R.IPV4, ipnum, ipindex
  end

  -- check for format ::FFFF:1.11.111.111 for ipv4
  local chunks = {ip:match("^%:%:[fF][fF][fF][fF]%:(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    local ipnum = bn.ZERO
    local octet = 0
    for x,v in pairs(chunks) do
      octet = tonumber(v)
      if octet > 255 then return R.ERROR end
      ipnum = ipnum + (bn(octet) << (8 * (4 - x)))
    end

    local ipindex = 0;
    if self.ipv4indexbaseaddr > 0 then
      ipindex = ((ipnum >> 16) << 3):asnumber() + self.ipv4indexbaseaddr
    end
    return R.IPV4, ipnum, ipindex
  end

  -- check for ipv6 format, should be 8 'chunks' of numbers/letters
  -- without leading/trailing chars
  -- or fewer than 8 chunks, but with only one `::` group
  -- chunks = {ip:match("^"..(("([a-fA-F0-9]*):"):rep(8):gsub(":$","$")))}
  --  if #chunks == 8
  --  or #chunks < 8 and ip:match('::') and not ip:gsub("::","",1):match('::') then

  local isIPv6 = false;
  local hextets = 8;

  if #chunks == 0 then
    -- parse the ipv6 string using the expected pattern
    for hextet in ip:gmatch("[a-fA-F0-9]*") do
      table.insert(chunks, hextet)
    end
    if #chunks > 0 then isIPv6 = true; end
  end

  -- expand the ipv6 address and add zeroes
  if isIPv6 == true then
    for i = 1, #chunks do
      if chunks[i] == "" then
        for j = 1 , hextets - (#chunks - 1) - 1 do
          if j == 1 then chunks[i] = "0" end
          table.insert(chunks, i, "0")
        end
      end
    end
    if chunks[hextets] == "" then chunks[hextets] = "0" end
  end

  -- DEBUGGING CODE
  -- for key, value in pairs(chunks)
  -- do
      -- print(key, " -- " , value);
  -- end
  
  if #chunks == 8 then
    local ipnum = bn.ZERO
    local part = 0
    for x,v in pairs(chunks) do
      part = tonumber(v, 16)
      if #v > 0 and part > 65535 then return R.ERROR end
      ipnum = ipnum + (bn(part) << (16 * (8 - x)))
    end
    
    local override = 0
    
    -- DEBUGGING
    -- print("IPNUM BEFORE: " .. ipnum)
    
    -- special cases which should convert to equivalent IPv4
    if ipnum >= from_v4mapped and ipnum <= to_v4mapped then -- ipv4-mapped ipv6
      -- print("IPv4-mapped") -- DEBUGGING
      override = 1
      ipnum = ipnum - from_v4mapped
    elseif ipnum >= from_6to4 and ipnum <= to_6to4 then  -- 6to4
      -- print("6to4") -- DEBUGGING
      override = 1
      ipnum = ipnum >> 80
      ipnum2 = ipnum:asnumber() & 0xffffffff
      ipnum = bn(ipnum2) -- convert back to bn
    elseif ipnum >= from_teredo and ipnum <= to_teredo then -- Teredo
      -- print("Teredo") -- DEBUGGING
      override = 1
      ipnum = ~ipnum
      ipnum2 = ipnum:asnumber() & 0xffffffff
      -- print("ipnum2: " .. ipnum2) -- DEBUGGING
      ipnum = bn(ipnum2) -- convert back to bn
    end
    
    -- DEBUGGING
    -- print("IPNUM AFTER: " .. ipnum)
    
    local ipindex = 0;
    if override == 1 then
      if self.ipv4indexbaseaddr > 0 then
        ipindex = ((ipnum >> 16) << 3):asnumber() + self.ipv4indexbaseaddr
      end
      return R.IPV4, ipnum, ipindex
    else
      if self.ipv6indexbaseaddr > 0 then
        ipindex = ((ipnum >> 112) << 3):asnumber() + self.ipv6indexbaseaddr
      end
      return R.IPV6, ipnum, ipindex
    end
  end

  return R.ERROR
end

-- populate record with message
function ip2proxyrecord:loadmessage(mesg)
  local x = {}
  setmetatable(x, ip2proxyrecord)  -- make ip2proxyrecord handle lookup
  x.country_short = mesg
  x.country_long = mesg
  x.region = mesg
  x.city = mesg
  x.isp = mesg
  x.proxytype = mesg
  x.isproxy = -1
  x.domain = mesg
  x.usagetype = mesg
  x.asn = mesg
  x.as = mesg
  x.lastseen = mesg
  x.threat = mesg
  return x
end

local function round(n)
  return math.floor((math.floor(n*2) + 1)/2)
end

local function roundup(num, decimalplaces)
  local mult = 10^(decimalplaces or 0)
  return math.floor(num * mult + 0.5) / mult
end

-- main query
function ip2proxy:query(ipaddress, mode)
  local result = ip2proxyrecord:loadmessage(not_supported) -- default message

  -- read metadata
  if self.metaok ~= true then
    local result = ip2proxyrecord:loadmessage(missing_file)
    -- printme(result)
    return result
  end

  -- check IP type and return IP number & index (if exists)
  local iptype, ipno, ipindex = self:checkip(ipaddress)

  if iptype == 0 then
    local result = ip2proxyrecord:loadmessage(invalid_address)
    -- printme(result)
    return result
  end

  local colsize = 0
  local baseaddr = 0
  local low = 0
  local high = 0
  local mid = 0
  local rowoffset = 0
  local rowoffset2 = 0
  local ipfrom = bn.ZERO
  local ipto = bn.ZERO
  local maxip = bn.ZERO
  local firstcol = 4
  local countrypos = 0

  if iptype == 4 then
    baseaddr = self.ipv4databaseaddr
    high = self.ipv4databasecount
    maxip = max_ipv4_range
    colsize = self.ipv4columnsize
  else
    baseaddr = self.ipv6databaseaddr
    high = self.ipv6databasecount
    maxip = max_ipv6_range
    colsize = self.ipv6columnsize
  end

  -- reading index
  if ipindex > 0 then
    low = readuint32(ipindex, self.f):asnumber()
    high = readuint32(ipindex + 4, self.f):asnumber()
  end

  if ipno >= maxip then
    ipno = maxip - bn(1)
  end

  while low <= high do
    mid = round((low + high) / 2)
    rowoffset = baseaddr + (mid * colsize)
    rowoffset2 = rowoffset + colsize

    if iptype == 4 then
      ipfrom = readuint32(rowoffset, self.f)
      ipto = readuint32(rowoffset2, self.f)
    else
      ipfrom = readuint128(rowoffset, self.f)
      ipto = readuint128(rowoffset2, self.f)
    end

    if (ipno >= ipfrom) and (ipno < ipto) then
      if iptype == 6 then
        firstcol = 16
      end

      self.f:seek("set", rowoffset + firstcol - 1)
      local row = self.f:read(self.columnsize_without_ip)

      if self.proxytype_enabled == true then
        if (mode&modes.proxytype ~= 0) or (mode&modes.isproxy ~= 0) then
          result.proxytype = readstr(readuint32row(self.proxytype_position_offset, row):asnumber(), self.f)
        end
      end

      if self.country_enabled == true then
        if (mode&modes.countryshort ~=0) or (mode&modes.countrylong ~=0) or (mode&modes.isproxy ~= 0) then
          countrypos = readuint32row(self.country_position_offset, row):asnumber()
        end

        if (mode&modes.countryshort ~=0) or (mode&modes.isproxy ~= 0) then
          result.country_short = readstr(countrypos, self.f)
        end

        if mode&modes.countrylong ~= 0 then
          result.country_long = readstr(countrypos + 3, self.f)
        end
      end

      if (mode&modes.region ~= 0) and (self.region_enabled == true) then
        result.region = readstr(readuint32row(self.region_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.city ~= 0) and (self.city_enabled == true) then
        result.city = readstr(readuint32row(self.city_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.isp ~= 0) and (self.isp_enabled == true) then
        result.isp = readstr(readuint32row(self.isp_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.domain ~= 0) and (self.domain_enabled == true) then
        result.domain = readstr(readuint32row(self.domain_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.usagetype ~= 0) and (self.usagetype_enabled == true) then
        result.usagetype = readstr(readuint32row(self.usagetype_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.asn ~= 0) and (self.asn_enabled == true) then
        result.asn = readstr(readuint32row(self.asn_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.as ~= 0) and (self.as_enabled == true) then
        result.as = readstr(readuint32row(self.as_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.lastseen ~= 0) and (self.lastseen_enabled == true) then
        result.lastseen = readstr(readuint32row(self.lastseen_position_offset, row):asnumber(), self.f)
      end

      if (mode&modes.threat ~= 0) and (self.threat_enabled == true) then
        result.threat = readstr(readuint32row(self.threat_position_offset, row):asnumber(), self.f)
      end

      if (result.country_short == "-") or (result.proxytype == "-") then
        result.isproxy = 0
      else
        if (result.proxytype == "DCH") or (result.proxytype == "SES") then
          result.isproxy = 2
        else
          result.isproxy = 1
        end
      end

      -- printme(result)

      -- Lua style where you must have "return" as the last statement in a block
      do
        return result
      end
    else
      if ipno < ipfrom then
        high = mid - 1
      else
        low = mid + 1
      end
    end
  end

  -- printme(result)
  return result
end

-- get module version
function ip2proxy:get_module_version()
  return api_version
end

-- get package version
function ip2proxy:get_package_version()
  return self.databasetype
end

-- get database version
function ip2proxy:get_package_version()
  return "20" .. self.databaseyear .. "." .. self.databasemonth .. "." .. self.databaseday
end

-- get is proxy
function ip2proxy:isproxy(ipaddress)
  return self:query(ipaddress, modes.isproxy)
end

-- get all fields
function ip2proxy:get_all(ipaddress)
  return self:query(ipaddress, modes.all)
end

-- get country code
function ip2proxy:get_country_short(ipaddress)
  return self:query(ipaddress, modes.countryshort)
end

-- get country name
function ip2proxy:get_country_long(ipaddress)
  return self:query(ipaddress, modes.countrylong)
end

-- get region
function ip2proxy:get_region(ipaddress)
  return self:query(ipaddress, modes.region)
end

-- get city
function ip2proxy:get_city(ipaddress)
  return self:query(ipaddress, modes.city)
end

-- get isp
function ip2proxy:get_isp(ipaddress)
  return self:query(ipaddress, modes.isp)
end

-- get proxy type
function ip2proxy:get_proxytype(ipaddress)
  return self:query(ipaddress, modes.proxytype)
end

-- get domain
function ip2proxy:get_domain(ipaddress)
  return self:query(ipaddress, modes.domain)
end

-- get usage type
function ip2proxy:get_usagetype(ipaddress)
  return self:query(ipaddress, modes.usagetype)
end

-- get ASN
function ip2proxy:get_asn(ipaddress)
  return self:query(ipaddress, modes.asn)
end

-- get AS
function ip2proxy:get_as(ipaddress)
  return self:query(ipaddress, modes.as)
end

-- get last seen
function ip2proxy:get_lastseen(ipaddress)
  return self:query(ipaddress, modes.lastseen)
end

-- get threat
function ip2proxy:get_threat(ipaddress)
  return self:query(ipaddress, modes.threat)
end

return ip2proxy
