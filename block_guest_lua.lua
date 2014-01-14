--url's ip access count|url's access count |ip block time|url block time|ip count head
local param_list = {
test1_param = '20,400,0,0,001',
test2_param = '10,170,0,0,002',
test3_param  = '20,400,0,0,003',
test4_param = '90,3,0,0,004'
}
local  log_file = "/var/log/nginx/lua.log"
local php_post_filter = "28365365.chtz.net|document.createElement"
local web_str = "@websrv"
local list={test1_param='test1.php',test2_param='test2.php',test3_param='test3.php',test4_param='test4.php'}


local block_uri_default_time  = 7200  --2 hours
local block_ip_default_time  = 10800  --3 hours

local method   = ngx.var.request_method
local refer = ngx.var.http_referer
local ip = ngx.var.remote_addr 
local uri = ngx.var.request_uri 
local filename = ngx.var.request_filename 


local request_mem_ip = ngx.md5(table.concat({ip}))
local request_mem_uri = ngx.md5(table.concat({uri}))
local block_mem_ip = ngx.md5(table.concat({ip,"block"}))
local block_mem_uri = ngx.md5(table.concat({uri,"block"}))

--sql attack 
local filter_sql = '.*[;]?((or)|(insert)|(sleep)|(select)|(union)|(update)|(delete)|(replace)|(create)|(drop)|(alter)|(grant)|(load)|(show)|(exec))[\\s(]|\x3c|%3C|%3E|/bin/|union.*select|select.*from|information_schema|and.*substring|and.*length|etc/passwd|proc/self/environ'
--forbid upload filesuffix
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

-----------------------------------log -----------------------------
module("logger", package.seeall)
logger_handle = {}
logger_handle["info"] = io.open(log_file, "a+")
function info(msg)
	logger_handle["info"]:write(ngx.localtime() .. "|" .. ngx.req.get_method() .. "|" .. msg .. "\n")
	logger_handle["info"]:flush()
end
local logger = require("logger")
local args   = {}
if ngx.req.get_method() == "GET" then
	args = ngx.req.get_uri_args()
else
	ngx.req.read_body()
	args = ngx.req.get_post_args()
end
-----------------------------------log -----------------------------

if ngx.re.match(uri,".*.php") then
	local url = ngx.unescape_uri(uri)
	--sql attack
	if sql_filter and ngx.re.match(url,filter_sql,"i") then
		ngx_log = "sql attack: IP: "..ip.." URL: "..uri
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
			ngx_log = "file up deny: IP: "..ip.." URL: "..uri.." upload php shell "..data
			logger.info(ngx_log)
			ngx.exit(444)
		end	
		
		if (data == nil) then --post content is null 
			ngx.exec(web_str)
		end
		
		if ngx.re.match(data,php_post_filter) then 
			new_data = data.." IP :"..ip.." REFER :"..refer
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
				ngx_log = "access uri: "..uri.." release times after "..block_time.." s"
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
		ngx.exec(web_str)
end


local function block_count_ip(count_str,limit_str,uri_str,block_time)
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
			block_str_mem:set(request_ip,1,10)
		end
		ngx.exec(web_str)
end

local str_ip = string.match(ip,'(.+)%..+')
if white_ip[str_ip] == '1' then
	local baduri = block_str_mem:get(block_mem_uri)
	if baduri  then
		ngx.exit(444);
	end

	--url count
	for k,v in pairs(list) do
		if ngx.re.match(uri,v) then
				block_str_list = eval(k)
				if  block_str_list[4] == 0 then
					block_count_url(request_mem_uri,block_str_list[2],block_uri_default_time)
				else
					block_count_url(request_mem_uri,block_str_list[2],block_str_list[4])
				end
		end	
	end
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
if badip  then
	ngx.exit(444);
end

local baduri = block_str_mem:get(block_mem_uri)
if baduri  then
	ngx.exit(444);
end

--url count
for k,v in pairs(list) do
	if ngx.re.match(uri,v) then
			block_str_list = eval(k)
			--[[if ngx.re.match(uri,"/test3.php") then
				str_uri = string.match(uri,'.*fireauuidwall_uuid=(.+)&action=.*')
				request_img_uri = ngx.md5(table.concat({str_uri}))
				block_img_uri = ngx.md5(table.concat({str_uri,"block"}))
				badimguri = block_str_mem:get(block_img_uri)
				if badimguri  then
					ngx.exit(444);
				end
				block_img_url(request_img_uri,block_str_list[2],block_uri_default_time)
			end]]
			if  block_str_list[4] == 0 then
				block_count_url(request_mem_uri,block_str_list[2],block_uri_default_time)
			else
				block_count_url(request_mem_uri,block_str_list[2],block_str_list[4])
			end
			block_count_ip(request_mem_ip,block_str_list[1],block_str_list[3],block_str_list[5])
	end	
end

