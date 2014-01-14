lua-for-cc-attack
=================

lua for nginx cc  attack script shell


一、文件说明


1、block_global_str.lua

2、block_guest_lua.lua

block_global_str.lua 为初始化变量


block_guest_lua.lua 主要功能sql注入、上传文件类型控制、xss攻击类型防护、对于部分文件控制访问频率（IP、URL）

二、nginx配置文件


lua_shared_dict cc_dict 1024M;  

init_by_lua_file "/opt/nginx/conf/block_global_str.lua";

        location / {
        
                default_type  text/html;
                
                content_by_lua_file /opt/nginx/conf/block_guest_lua.lua ;
                
        }

        location @websrv {
        
                access_log  /var/log/nginx/access.log main buffer=512k;
                
                proxy_pass http://web_srv;
        }
        
	upstream web_srv {
	
			server 127.0.0.1:80;
			
	}
		
三、block_guest_lua.lua内容说明



1、param_list各项目控制参数


URL的IP访问频率，URL访问访问频率，IP访问控制时间，URL访问控制时间，IP访问前缀用于区分统计

kf.php的为：20,400,0,0,001


2、param_list的keys与list的表的keys一致


local param_list = {
test1_param = '20,400,0,0,001',
test2_param = '10,170,0,0,002',
test3_param  = '20,400,0,0,003',
test4_param = '90,3,0,0,004'
}

local list={test1_param='test1.php',test2_param='test2.php',test3_param='test3.php',test4_param='test4.php'}

日志文件


local  log_file = "/var/log/nginx/lua.log"

php过滤post内容


local php_post_filter = "28365365.chtz.net|document.createElement"

跳转的与nginx的配置文件跳转的一致


local web_str = "@websrv"

四、block_global_lua.lua内容说明


1、url白名单，%?转义?


white_uri={'/test1.php%?ag=10000007&le=1','/test2.php%?ag=10000007&le=1'}   


2、ip白名单


white_ip={
['192.168.111'] = '1',
['192.168.1'] = '1',
['10.1.1'] = '1'
}

五、lua for ngin模块下载

https://github.com/chaoslawful/lua-nginx-module


