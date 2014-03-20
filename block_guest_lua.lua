--url's ip access count|url's access count |ip block time|url block time|ip count head
local param_list = {
k_param = '80,800,0,0,001',
w_param = '40,340,0,0,002',
m_param  = '80,800,0,0,003',
a_param = '80,5,0,0,004'
}
local log_file = "/var/log/nginx/lua.log"
--php post string block
local php_post_filter = "28365365.chtz.net|document.createElement"
local web_str = "@websrv"
--random is first read from  list table
local list={ w_param='test1.php',k_param='test2.php',m_param='test3.php',a_param='random_test'}

--default block time 
local block_uri_default_time  = 7200  --2 hours
local block_ip_default_time  = 10800  --3 hours

local method = ngx.var.request_method
local refer = ngx.var.http_referer
local ip = ngx.var.remote_addr
local uri = ngx.var.request_uri
local filename = ngx.var.request_filename


local request_mem_ip = ngx.md5(table.concat({ip}))
local request_mem_uri = ngx.md5(table.concat({uri}))
local block_mem_ip = ngx.md5(table.concat({ip,"block"}))
local block_mem_uri = ngx.md5(table.concat({uri,"block"}))
local block_sql_ip = ngx.md5(table.concat({ip,"sql"}))

--sql attack 
--local filter_sql = '.*[;]?((or)|(insert)|(sleep)|(select)|(union)|(update)|(delete)|(replace)|(create)|(drop)|(alter)|(grant)|(load)|(show)|(exec))[\\s(]|\x3c|%3C|%3E|/bin/|union.*select|select.*from|information_schema|and.*substring|and.*length|etc/passwd|proc/self/environ'
local filter_sql = '[;]?((or)|(insert)|(sleep)|(select)|(union)|(update)|(delete)|(replace)|(create)|(drop)|(alter)|(grant)|(load)|(show)|(exec))[\\s(]|/bin/'
local strict_sql = 'information_schema|etc/passwd|proc/self/environ'
--forbid upload file type
local filter_file_type = "(php|jsp|js)"
--xss attack
local filter_xss = "(<iframe|<script|<body|<img|javascript"

string.split = function(s,p)
    local rt= {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
    return rt

end

function eval(str)
        for k,v in pairs(param_list) do
                if str == k then
                        return(string.split(v,','))
                end
        end
end

--log function
module("logger", package.seeall)
logger_handle = {}
logger_handle["info"] = io.open(log_file, "a+")
function info(msg)
logger_handle["info"]:write(ngx.localtime() .. "|" .. ngx.req.get_method() .. "|" .. msg .. "\n")
logger_handle["info"]:flush()
end
local logger = require("logger")
local args = {}
if ngx.req.get_method() == "GET" then
args = ngx.req.get_uri_args()
else
ngx.req.read_body()
args = ngx.req.get_post_args()
end

--block ip function
local function block_count_ip(count_str,limit_str,uri_str,block_time,store_time)
		local request_ip = table.concat({count_str, uri_str})
		--ip
		local block_ip = block_str_mem:get(request_ip)
		if block_ip then
			--access limit 
			if tonumber(block_ip) > tonumber(limit_str) then
				--add to block list
				block_str_mem:set(block_mem_ip,0,block_time)
				ngx_log = "access "..uri_str.." ip: "..ip.." release times after "..block_time.." s".." limit_str "..limit_str
				logger.info(ngx_log)
				--nginx return 444
				ngx.exit(444)
			else
				--if block_ip < limit_str --->increase ip access count
				block_str_mem:incr(request_ip,1)
			end
		else
			--if block_ip is none ---> add ip dict
			block_str_mem:set(request_ip,1,store_time)
		end
end

local function random_select(id_str)
	if (ngx.var.arg_random_test  == nil ) then
		local random = math.random(100000,999999)
		local token = ngx.md5("test" .. ngx.var.remote_addr .. random..id_str )
		url = ngx.var.request_uri.."&token_test=" .. token.."&random_test=" .. random
		return ngx.redirect(url)
	else
		local token  = ngx.md5("test"..ngx.var.remote_addr .. ngx.var.arg_random_test..id_str )
		if (ngx.var.arg_token_test~= token ) then
			ngx.exit(444)
		else
			ngx.exec(web_str)
		end
	end
end

local badsqlip = block_str_mem:get(block_sql_ip)
if badsqlip  then
	ngx.exit(444);
end

if bad_refer then
	for k,v in pairs(bad_refer) do
		if refer and string.find(refer,v) then
			ngx.exit(444)
		end
	end
end

if ngx.re.match(uri,".*.php") then
	local url = ngx.unescape_uri(uri)
	--sql attack
	if filter_sql and ngx.re.match(url,filter_sql,"i") then
		ngx_log = "sql attack: IP: "..ip.." URL: "..uri
		logger.info(ngx_log)
		ngx.exit(444);
	end		
	
	if  ngx.re.match(url,strict_sql,"i") then 
		block_count_ip(request_mem_ip,3,"sql",36000,60)--count ,str ,block_time,store_time's
		ngx_log = "sql attack IP: "..ip.." URL: "..uri
		logger.info(ngx_log)
		ngx.exit(444);	
	end	
	--xss attack
	if filter_xss and ngx.re.match(url,filter_xss,"i") then
		ngx_log = "xss attack: IP: "..ip.." URL: "..uri
		logger.info(ngx_log)
		ngx.exit(444)
	end
	if ( method == "POST") then
		-- .php .js upload
		local data = ngx.req.get_body_data()
		if filter_file_type and data and ngx.re.match(data,"Content-Disposition: form-data;.*filename=\".*\\."..filter_file_type.."\"","isjo") then
			ngx_log = "file up deny IP: "..ip.." URL: "..uri.." upload php shell " --..data
			logger.info(ngx_log)
			ngx.exit(444)
		end	
		
		if (data == nil) then --post content is null 
			ngx.exec(web_str)
		end
		
		if ngx.re.match(data,php_post_filter) then 
			new_data = "php post filter IP :"..ip.." REFER :"..refer
			logger.info(new_data)  -- log file's user must be nginx'user if not will respone 500 error
			ngx.say(444)  -->say message
		end
	end
end

local block_count = 0;
for k,v in pairs(list) do
        if string.find(uri,v) then --uri's string find v
                block_count = block_count + 1
        end
end

if block_count == 0 then
        ngx.exec(web_str)
end

local function block_count_url(count_str,limit_str,block_time)
		--block uri
		local block_uri = block_str_mem:get(count_str)
		if block_uri then
			--uri access limit 
			if tonumber(block_uri) > tonumber(limit_str) then
				--add block list
				block_str_mem:set(block_mem_uri,0,block_time)
				ngx_log = "access url:"..ip.." "..uri.." release times after "..block_time.." s"
				logger.info(ngx_log)
				ngx.exit(444)
			else
				--uri access count + 1
				block_str_mem:incr(count_str,1)	
			end
		else
				--add request uri 
				block_str_mem:set(count_str,1,10)
		end
				
		local userAgent = ngx.req.get_headers()["User-Agent"]
		if ngx.re.match(userAgent,"Safari|MSIE 6.0") then
				if (ngx.var.arg_arg  == nil ) then
					if (ngx.var.arg_cid == nil) then
						ngx.exit(444)
					else
						random_select(ngx.var.arg_cid)
					end
				else
					random_select(ngx.var.arg_arg)
				end
		else
			--cookie+token values check normal request
			local random  = ngx.var.cookie_random_test
			if (random  == nil ) then
				local random = math.random(99999)
				local token = ngx.md5("test" .. ngx.var.remote_addr .. random)
				local expires = 3600 * 24  -- 1 day
				ngx.header["P3P"] = 'CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"'
				--ngx.header["Set-Cookie"] = {"token_test=" .. token..";expires=" .. ngx.cookie_time(ngx.time()+expires)..";path=/;domain=testcard.com","random_test=" .. random..";expires=" .. ngx.cookie_time(ngx.time()+expires)..";path=/;domain=testcard.com" }
				ngx.header["Set-Cookie"] = {"token_test=" .. token,"random_test=" .. random} 	--一次会话有效		
				return ngx.redirect(ngx.var.request_uri)
			end
			local token  = ngx.md5("test"..ngx.var.remote_addr .. random )
			if (ngx.var.cookie_token_test ~= token ) then
				ngx.exit(444)
			else
				ngx.exec(web_str)
			end
		end
end

local str_ip = string.match(ip,'(.+)%..+')
if white_ip[str_ip] == '1' then
local baduri = block_str_mem:get(block_mem_uri)
if baduri then
ngx.exit(444);
end

	--url count
	for k,v in pairs(list) do
		if ngx.re.match(uri,v) then
				block_str_list = eval(k)
				if  tonumber(block_str_list[4]) == 0 then
					block_count_url(request_mem_uri,block_str_list[2],block_uri_default_time)
				else
					block_count_url(request_mem_uri,block_str_list[2],block_str_list[4])
				end
		end	
	end
	ngx.exec(web_str)
end


if white_uri then
for k,v in pairs(white_uri) do
if string.find(uri,v) then
ngx.exec(web_str)
end
end
end

--in block list
local badip = block_str_mem:get(block_mem_ip)
if badip then
ngx.exit(444);
end

local baduri = block_str_mem:get(block_mem_uri)
if baduri then
ngx.exit(444);
end

--table sort by keys
function sortedpairs(t,comparator) 
	local sortedKeys = {}
	table.foreach(t,function(k,v) table.insert(sortedKeys,k) end)
	table.sort(sortedKeys,comparator)
	local i = 0
	local function _f(_s,_v) i = i + 1
		local k = sortedKeys[i]
		if (k) then 
			return k,t[k]
		end 
	end
	return _f,nil,nil
end

--url count
for k,v in sortedpairs(list) do
	if ngx.re.match(uri,v) then
			block_str_list = eval(k)
			--count ip access 
			if  tonumber(block_str_list[3]) == 0 then
				--count_str,limit_str,uri_str,block_time  
				block_count_ip(request_mem_ip,block_str_list[1],block_str_list[5],block_ip_default_time,10)
			else
				block_count_ip(request_mem_ip,block_str_list[1],block_str_list[5],block_str_list[3],10)
			end
			
			--count url access and go real request
			if  tonumber(block_str_list[4]) == 0 then
				--count_str,limit_str,block_time,store_time's
				block_count_url(request_mem_uri,block_str_list[2],block_uri_default_time)
			else
				block_count_url(request_mem_uri,block_str_list[2],block_str_list[4])
			end
	end	
end
