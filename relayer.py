#-*- coding:utf-8 -*-  

'''
author: 张延飞

name: N3000 运维中心模块

Description: 主要负责转发客户端到管理中心的数据

'''

import os
from ctypes import *
import thread
import threading
import ConfigParser
from SocketServer import ThreadingTCPServer, StreamRequestHandler
import traceback
import struct
import binascii
import time
import socket

import urllib
import urllib2
import ssl

import base64
import json
import logging
import logging.config
from logging.handlers import RotatingFileHandler

# suds 调用webservice方法
#
from suds.client import Client


BLK_QUERY_SERVER = 0		# 客户端请求跳转服务器
BLK_SERVER_STATUS = 1		# 客户端提交服务器性能信息
BLK_CLIENT_STATUS = 2		# 客户端提交状态信息
BLK_CLIENT_HISTORY = 3		# 客户端提交历史记录信息
BLK_CLIENT_GATEWAY = 4		# 客户端提交网关信息
BLK_CLIENT_CHECK_UPDATE = 5	# 客户端检查文件更新
BLK_CLIENT_UPDATE_FILE = 6	# 客户端更新文件
BLK_CLIENT_PROC_LINK = 7	# 客户端提交进程链路信息
BLK_CLIENT_DOWNLOADFILE = 8	# 客户端下载指定的文件
BLK_CLIENT_SWITCHPROTOCOL = 9	# 客户端请求切换通信方式为加密方式

E_SERLIST_NO_SERVER = 301
E_SERLIST_INVALID_DATA = 302
E_SERLIST_BUILD_FAILED = 303
E_SERLIST_EXCEPRION = 304

WEBSERVICE_FILE = "webservice.json"


MAGIC = 0x334E								# 数据头Magic
g_hdr_struct = struct.Struct('@iii')					# 数据头结构

q_server_info_struct = struct.Struct('@iiiiiiiiiiiLL64s64s64s64s64s1024s')	# 跳转服务器结构

socket.setdefaulttimeout(120)						# 设置全局网络超时
ssl._create_default_https_context=ssl._create_unverified_context	# 取消SSL certificate验证

g_version_file_name = None						# 客户端检测升级用的配置文件名
g_webservice_url = None							# Webservice url
g_webservice_url_locker = None						# Webservice url locker
g_log_config_name = 'logging.conf'					# 日志引擎的配置文件
g_logger_name = 'server'						# 日志引擎logger名称
g_logfile_name = 'server.log'						# 日志文件名

g_start_monitor_event = threading.Event()				# 通知线程开始监控客户端版本
g_utils_dll = cdll.LoadLibrary("utils.dll")
g_webservice_file = os.getcwd() + "\\{}".format(WEBSERVICE_FILE)


def RC4(data, key):
    """RC4 algorithm"""
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = ''
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out += chr(ord(char) ^ box[(box[x] + box[y]) % 256])

    return out

def decrypt_data(data):

	dest = create_string_buffer(len(data))
	g_utils_dll.rc4(byref(dest), data, len(data))
	return dest.raw 

	#xor_key = '^78tj)&Q'
	#return RC4(data, xor_key)

	
def encrypt_data(data):
	return decrypt_data(data)

# 初始化日志
#
def init_log():

	try:
		config_file = os.getcwd() + "\\config\\{}".format(g_log_config_name)
		if os.path.exists(config_file) == False:
			print_log("file {} not exist, can not save log".format(config_file))
			return False

		log_file = os.getcwd() + "\\log"
		if os.path.exists(log_file) == False:
			os.makedirs(log_file)
		log_file += "\\{}".format(g_logfile_name)

		logging.config.fileConfig(config_file)
		logger = logging.getLogger(g_logger_name)

		# 日志回滚，当日志文件为2M时，生成新的日志文件，混滚次数为1024次
		#
		Rthandler = RotatingFileHandler(log_file, maxBytes=2 * 1024*1024, backupCount=1024)
		Rthandler.setLevel(logging.INFO)
		formatter = logging.Formatter('[%(asctime)s] [%(process)s:%(thread)s] %(message)s')
		Rthandler.setFormatter(formatter)
		logger.addHandler(Rthandler)

	except Exception as e:
		print_log("init log failed, error {}".format(e))
		return False

	return True

# 打印日志
#
def print_log(msg):
	
	logger = logging.getLogger(g_logger_name)
	try:
		logger.info(msg)

	except Exception as e:
		print("print_log log failed, error {}".format(e))

# 发送数据
#
def send_msg(msg, msg_len, ty, client):

	try:
		hdr = g_hdr_struct.pack(MAGIC, ty, msg_len)

		if client.protocol_type == 1:
			hdr = encrypt_data(hdr)
		client.wfile.write(hdr)

		if client.protocol_type == 1:
			msg = encrypt_data(msg)
		client.wfile.write(msg)

		#sended = 0
		#msgtmp = ""
		#while True:
		#	if msg_len < 1024 * 1024 * 1:
		#		if client.protocol_type == 1:
		#			msg = encrypt_data(msg)
		#		client.wfile.write(msg)
		#		break
		#	else:
		#		if msg_len - sended < 1024:
		#			msgtmp = msg[sended:]
		#		else:
		#			msgtmp = msg[sended:sended+8]

		#		if client.protocol_type == 1:
		#			msgtmp = encrypt_data(msgtmp)
		#		client.wfile.write(msgtmp)
		#		sended = sended + len(msgtmp)

		#		print("send {}:{}".format(sended, msg_len))

		#		if sended == msg_len:
		#			break
	
	except Exception as e:
		print_log("send msg failed, error {}".format(e))
		client.wfile.close()

# 初始化Webservice锁
#
def init_webservice_locker():
	try:
		global g_webservice_url_locker
		g_webservice_url_locker = thread.allocate_lock()
	except Exception as e:
		print_log("init webservice url locker failed, error {}".format(e))

# 更新Webservice URL
#
def update_webservice(url):
	
	web_c = None

	global g_webservice_url

	if g_webservice_url == url:
		print_log("new webservice == old webservice")
		return

	try:
		web_c = Client(url)
	except Exception as e:
		print_log("try to connect manager center failed, error {}".format(e))
		return
	if web_c == None:
		print_log("try to connect manager center failed, result is None")
		return

	g_webservice_url_locker.acquire()

	g_webservice_url = url
	print_log("new webservice url is {}".format(g_webservice_url))

	json_string = {"url":url}
	write_to_file(g_webservice_file, json.dumps(json_string))
	
	g_webservice_url_locker.release()

	# signal to start monitor new version of client
	g_start_monitor_event.set()

# 得到Webservice 对象
#
def get_webservice():

	web_c = None
	web_url = None

	if g_webservice_url == None:
		return None

	g_webservice_url_locker.acquire()
	web_url = g_webservice_url
	g_webservice_url_locker.release()

	try:
		web_c = Client(web_url)
	except Exception as e:
		print_log("get webservice failed, url {0}, error {1}".format(web_url, e))

	return web_c

# 请求服务器列表
#
def query_server_list(msg, msg_len, client):

	server_list = ""		
	try:
		keyid_offset, keyid_len = struct.unpack('ii', msg[0:struct.calcsize('ii')])
		keyid, = struct.unpack('{}s'.format(keyid_len), msg[keyid_offset:keyid_offset + keyid_len])		

		print_log("client keyid: {}".format(keyid))

		disc_content = {"keyid":keyid}
		js_request = json.dumps(disc_content)

		web_client = get_webservice()
		if web_client == None:
			server_list = q_server_info_struct.pack(0,0,0,0,0,0,0,0,0,0,E_SERLIST_NO_SERVER,0,0,"","","","","","get webservice failed!")
			send_msg(server_list, len(server_list), BLK_QUERY_SERVER, client)
			return
		result = web_client.service.getServerList(js_request)
		if result == '[]':
			server_list = q_server_info_struct.pack(0,0,0,0,0,0,0,0,0,0,E_SERLIST_NO_SERVER,0,0,"","","","","","There is no servers!")
			send_msg(server_list, len(server_list), BLK_QUERY_SERVER, client)
			return

		servers = json.loads(result, 'utf-8')
		print_log("jump servers count: {}".format(len(servers)))
		for ser in servers:
			try:
				if len(ser) == 0 or len(ser) != 19:
					server_list = q_server_info_struct.pack(0,0,0,0,0,0,0,0,0,0,E_SERLIST_INVALID_DATA,0,0,"","","","","","Invalid server struct, msg {}".format(result))
					break

				print_log("server country: {}".format(ser['server_country'].encode('gbk')))
				print_log("server province: {}".format(ser['server_province'].encode('gbk')))
				print_log("server city: {}".format(ser['server_city'].encode('gbk')))
				print_log("server note: {}".format(ser['server_note'].encode('gbk')))
				print_log("server line index {}".format(ser['server_line']))

				server_list += q_server_info_struct.pack(
					ser['server_type'],
					ser['server_status'],
					ser['server_limit'],
					ser['server_run_status'],
					ser['server_link_count'],
					ser['server_delay'],
					ser['server_up_flow'],
					ser['server_down_flow'],
					ser['server_node_type'],
					ser['server_line'],
					ser['server_error_code'],
					ser['server_invalid_time'],
					ser['server_updatetime'],
					ser['server_country'].encode('utf-8'),
					ser['server_province'].encode('utf-8'),
					ser['server_city'].encode('utf-8'),
					ser['server_range'].encode('utf-8'),
					ser['server_ip'].encode('utf-8'),
					ser['server_note'].encode('utf-8')
					)
			except Exception as e:
				print_log("build server list failed, error {}".format(e))
				server_list = q_server_info_struct.pack(0,0,0,0,0,0,0,0,0,0,E_SERLIST_BUILD_FAILED,0,0,"","","","","","build server list failed!")
				break
	except Exception as e:
		print_log("query server list failed, error {}".format(e))
		server_list = q_server_info_struct.pack(0,0,0,0,0,0,0,0,0,0,E_SERLIST_EXCEPRION,0,0,"","","","","","get server list failed!")
	
	send_msg(server_list, len(server_list), BLK_QUERY_SERVER, client)

# 提交服务器运行状态
#
def query_server_status(msg, msg_len, client):
	
	res_result = "failed"

	try:
		ip_offset, ip_len, runstatus, linkcount, delay, upflow, downflow, nodetype = struct.unpack('iiiiiiii', msg[0:struct.calcsize('iiiiiiii')])
		ip, = struct.unpack('{}s'.format(ip_len), msg[ip_offset:ip_offset + ip_len])

		print_log("server ip: {}".format(ip))
		disc_content = {
				"serverip":ip,
				"runstatus":runstatus,
				"linkcount":linkcount,
				"delay":delay,
				"upflow":upflow,
				"downflow":downflow,
				"nodetype":nodetype
				}
		js_request = json.dumps(disc_content)
		
		web_client = get_webservice()
		if web_client != None:
			result = web_client.service.updateServerStatus(js_request)
			res_result = "succeed"
		
		send_msg(res_result, len(res_result), BLK_SERVER_STATUS, client)

	except Exception as e:
		print_log("query server status failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_SERVER_STATUS, client)

# 提交客户端状态
#
def query_client_status(msg, msg_len, client):

	res_result = "failed"
	try:
		keyid_offset, keyid_len, mac_offset, mac_len, ip_offset, ip_len, url_offset, url_len, clientstatus, logintime = struct.unpack('iiiiiiiiiL', msg[0:struct.calcsize('iiiiiiiiiL')])
		keyid, = struct.unpack('{}s'.format(keyid_len), msg[keyid_offset:keyid_offset + keyid_len])
		mac, = struct.unpack('{}s'.format(mac_len), msg[mac_offset:mac_offset + mac_len])
		ip, = struct.unpack('{}s'.format(ip_len), msg[ip_offset:ip_offset + ip_len])
		manager_center_url, = struct.unpack('{}s'.format(url_len), msg[url_offset:url_offset + url_len])

		# 更新管理中心URL
		#
		print_log("update webservice url...")
		update_webservice(manager_center_url)
		
		print_log("query client status, client keyid or username: {}, MAC: {}, IP: {}, status: {}".format(keyid, mac, ip, clientstatus))
		disc_content = {
				"keyid":keyid,
				"ip":ip,
				"mac":mac,
				"clientstatus":clientstatus,
				"logintime":logintime
				}
		js_request = json.dumps(disc_content)
		
		web_client = get_webservice()
		if web_client != None:
			result = web_client.service.updateClientStatus(js_request)
			res_result = "succeed"

		send_msg(res_result, len(res_result), BLK_CLIENT_STATUS, client)

	except Exception as e:
		print_log("query client status failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_STATUS, client)

# 提交历史记录
#
def query_client_history(msg, msg_len, client):

	res_result = "failed"
	try:
		keyid_offset, keyid_len, mac_offset, mac_len, ip_offset, ip_len, domain_offset, domain_len, websiteip_offset, websiteip_len, browsertime_offset, browsertime_len = struct.unpack('iiiiiiiiiiii', msg[0:struct.calcsize('iiiiiiiiiiii')])

		keyid, = struct.unpack('{}s'.format(keyid_len), msg[keyid_offset:keyid_offset + keyid_len])
		mac, = struct.unpack('{}s'.format(mac_len), msg[mac_offset:mac_offset + mac_len])
		ip, = struct.unpack('{}s'.format(ip_len), msg[ip_offset:ip_offset + ip_len])
		domain, = struct.unpack('{}s'.format(domain_len), msg[domain_offset:domain_offset + domain_len])
		websiteip, = struct.unpack('{}s'.format(websiteip_len), msg[websiteip_offset:websiteip_offset + websiteip_len])
		browsertime, = struct.unpack('{}s'.format(browsertime_len), msg[browsertime_offset:browsertime_offset + browsertime_len])

		print_log("query client history, client keyid: {}".format(keyid))
		print_log("MAC address: {}".format(mac))
		print_log("IP address: {}".format(ip))
		print_log("doamin: {}".format(domain))
		print_log("website address: {}".format(websiteip))
		print_log("browser time: {}".format(browsertime))

		disc_content = {
				"keyid":keyid,
				"mac":mac,
				"ip":ip,
				"domainname":domain,
				"websiteip":websiteip,
				"browsertime":browsertime
				}
		js_request = json.dumps(disc_content)
		
		web_client = get_webservice()
		if web_client != None:
			result = web_client.service.updateClientWebsiteStatus(js_request)
			res_result = "succeed"

		send_msg(res_result, len(res_result), BLK_CLIENT_HISTORY, client)

	except Exception as e:
		print_log("query client history failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_HISTORY, client)

# 提交网关信息
#
def query_client_gateway(msg, msg_len, client):

	res_result = "failed"
	try:
		keyid_offset, keyid_len, guid_offset, guid_len = struct.unpack('iiii', msg[0:struct.calcsize('iiii')])
		keyid, = struct.unpack('{}s'.format(keyid_len), msg[keyid_offset:keyid_offset + keyid_len])
		guid, = struct.unpack('{}s'.format(guid_len), msg[guid_offset:guid_offset + guid_len])
		
		print_log("query client gateway, client keyid: {}".format(keyid))
		disc_content = {
				"keyid":keyid,
				"guid":guid
				}
		js_request = json.dumps(disc_content)
		
		web_client = get_webservice()
		if web_client != None:
			result = web_client.service.updateClientGateway(js_request)
			res_result = "succeed"
			
		send_msg(res_result, len(res_result), BLK_CLIENT_GATEWAY, client)

	except Exception as e:
		print_log("query client gateway failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_GATEWAY, client)

# 检查文件更新
#
def query_client_check_update(msg, msg_len, client):

	res_result = "failed"
	try:
		check_new_file, = struct.unpack("i", msg[0:struct.calcsize("i")])
		if check_new_file == 0:
			print_log("query check update failed, check_new_file is 0")
			send_msg(res_result, len(res_result), BLK_CLIENT_CHECK_UPDATE, client)
			return

		print_log("query client check update...")

		web_client = get_webservice()
		if web_client == None:
			print_log("query check update failed, get webservice failed")
			send_msg(res_result, len(res_result), BLK_CLIENT_CHECK_UPDATE, client)
			return

		result = web_client.service.getFile("client", g_version_file_name)
		if result == None:
			print_log("query check update failed, webservice result is None")
			send_msg(res_result, len(res_result), BLK_CLIENT_CHECK_UPDATE, client)
			return

		send_msg(result, len(result), BLK_CLIENT_CHECK_UPDATE, client)

	except Exception as e:
		print_log("query client check update exception, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_CHECK_UPDATE, client)
	

# 更新文件
#
def query_client_update_file(msg, msg_len, client):

	res_result = "failed"
	file_handle = None
	file_content = None
	try:
		filename_offset, filename_len = struct.unpack("ii", msg[0:struct.calcsize("ii")])
		filename, = struct.unpack("{}s".format(filename_len), msg[filename_offset:filename_offset + filename_len])

		print_log("query client update file, file name {}".format(filename))

		ver_file = os.getcwd() + "\\last_version"
		
		if os.path.exists(ver_file):
			jsd = json.load(open(ver_file))
			file_name = os.getcwd() + "\\{}".format(jsd['pack_name'])
			print_log("local update file {}".format(file_name))
			if os.path.exists(file_name):
				file_handle = open(file_name, 'rb')
				file_content = file_handle.read()
		else:
			web_client = get_webservice()
			if web_client == None:
				print_log("query client update file failed, get webservice failed")
				send_msg(res_result, len(res_result), BLK_CLIENT_UPDATE_FILE, client)
				return

			file_content = web_client.service.getFile("client", filename)
			if file_content == None:
				print_log("query client update file webservice result failed")
				send_msg(res_result, len(res_result), BLK_CLIENT_UPDATE_FILE, client)
				return

		send_msg(str(file_content), len(str(file_content)), BLK_CLIENT_UPDATE_FILE, client)

	except Exception as e:
		print_log("query client update file exception, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_UPDATE_FILE, client)

	if file_handle is not None:
		file_handle.close()

# 获取文件
#
def query_client_download_file(msg, msg_len, client):

	res_result = "failed"
	file_content = None
	try:
		filename_offset, filename_len = struct.unpack("ii", msg[0:struct.calcsize("ii")])
		filename, = struct.unpack("{}s".format(filename_len), msg[filename_offset:filename_offset + filename_len])

		print_log("query client file, file name {}".format(filename))

		web_client = get_webservice()
		if web_client == None:
			print_log("query client file failed, get webservice failed")
			send_msg(res_result, len(res_result), BLK_CLIENT_DOWNLOADFILE, client)
			return
		file_content = web_client.service.getFile("client", filename)
		if file_content == None:
			print_log("query client file failed, webservice result failed")
			send_msg(res_result, len(res_result), BLK_CLIENT_DOWNLOADFILE, client)
			return

		send_msg(str(file_content), len(str(file_content)), BLK_CLIENT_DOWNLOADFILE, client)

	except Exception as e:
		print_log("query client file exception, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_DOWNLOADFILE, client)

# 客户端提交进程链路信息
#
def query_client_proc_link(msg, msg_len, client):

	res_result = "failed"
	try:
		keyid_offset, keyid_len, dstip_offset, dstip_len, procname_offset, procname_len, dstaddr_offset, dstaddr_len, linkname_offset, linkname_len, seraddr_offset, seraddr_len, delay, reserved = struct.unpack('LLLLLLLLLLLLLL', msg[0:struct.calcsize('LLLLLLLLLLLLLL')])

		keyid, = struct.unpack('{}s'.format(keyid_len), msg[keyid_offset:keyid_offset + keyid_len])
		dstip, = struct.unpack('{}s'.format(dstip_len), msg[dstip_offset:dstip_offset + dstip_len])
		procname, = struct.unpack('{}s'.format(procname_len), msg[procname_offset:procname_offset + procname_len])
		dstaddr, = struct.unpack('{}s'.format(dstaddr_len), msg[dstaddr_offset:dstaddr_offset + dstaddr_len])
		linkname, = struct.unpack('{}s'.format(linkname_len), msg[linkname_offset:linkname_offset + linkname_len])
		seraddr, = struct.unpack('{}s'.format(seraddr_len), msg[seraddr_offset:seraddr_offset + seraddr_len])

		disc_content = {
				"user":keyid,
				"process_name":procname,
				"dest_ip":dstip,
				"dest_addr":dstaddr,
				"delay":delay,
				"link_info":linkname,
				"server_location":seraddr
				}
		js_request = json.dumps(disc_content)

		web_client = get_webservice()
		if web_client == None:
			print_log("query client proc link failed, get webservice failed")
			send_msg(res_result, len(res_result), BLK_CLIENT_PROC_LINK, client)
			return

		result = web_client.service.updateLinkStatus(js_request)

		res_result = "succeed"
		send_msg(res_result, len(res_result), BLK_CLIENT_PROC_LINK, client)

		print_log("submit client process link information succeed!!")

	except Exception as e:
		print_log("query proc link failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_PROC_LINK, client)

def query_switch_protocol(msg, msg_len, client):
	res_result = "failed"
	try:
		if msg == "encrypt":
			res_result = "encrypted"
			send_msg(res_result, len(res_result), BLK_CLIENT_SWITCHPROTOCOL, client)
			client.protocol_type = 1
			print_log("submit client switch protocol ok")

		# ...

	except Exception as e:
		print_log("query switch protocol failed, error {}".format(e))
		send_msg(res_result, len(res_result), BLK_CLIENT_SWITCHPROTOCOL, client)


# 解析客户端请求
#
def parse_msg(msg, msg_len, ty, client):

	if ty == BLK_QUERY_SERVER:

		print_log("query server list...")
		query_server_list(msg, msg_len, client)

	elif ty == BLK_SERVER_STATUS:

		print_log("submit server status...")
		query_server_status(msg, msg_len, client)

	elif ty == BLK_CLIENT_STATUS:

		print_log("submit client status...")
		query_client_status(msg, msg_len, client)

	elif ty == BLK_CLIENT_HISTORY:

		print_log("submit client history...")
		query_client_history(msg, msg_len, client)

	elif ty == BLK_CLIENT_GATEWAY:

		print_log("submit client gateway...")
		query_client_gateway(msg, msg_len, client)
	elif ty == BLK_CLIENT_CHECK_UPDATE:

		print_log("submit check update file...")
		query_client_check_update(msg, msg_len, client)
	elif ty == BLK_CLIENT_UPDATE_FILE:

		print_log("submit update file...")
		query_client_update_file(msg, msg_len, client)

	elif ty == BLK_CLIENT_PROC_LINK:

		print_log("submit process link info...")
		query_client_proc_link(msg, msg_len, client)

	elif ty == BLK_CLIENT_DOWNLOADFILE:

		print_log("submit client download file...")
		query_client_download_file(msg, msg_len, client)
	elif ty == BLK_CLIENT_SWITCHPROTOCOL:

		print_log("submit switch protocol...")
		query_switch_protocol(msg, msg_len, client)
	else:
		print_log("submit invalid type")
		send_msg("fail", 4, -1, client)



# 等待客户端连接请求
#
class client_handler(StreamRequestHandler):

	protocol_type = 0

	def handle(self):
		print_log("client from {}:{}".format(
			self.client_address[0], self.client_address[1]))

		while True:
			try:                                
				hdr = self.rfile.read(g_hdr_struct.size)
				if len(hdr) <= 0 or len(hdr) != g_hdr_struct.size:
					print_log("Client: {} closed connection!".format(self.client_address[0]))
					self.request.close()
					break

				enc_hdr = hdr
				if self.protocol_type == 1:
					hdr = decrypt_data(hdr)

				magic, ty, payload_len = g_hdr_struct.unpack(hdr)

				if magic != MAGIC:
					self.request.close()
					print_log("Client: {}, Invalid maigic number!".format(self.client_address[0]))
					break
				if payload_len == 0:
					self.request.close()
					print_log("Client: {}, Invalid length is 0".format(self.client_address(0)))
					break

				if payload_len != 0:
					msg = self.rfile.read(payload_len)
					if len(msg) == 0:
						break

				if self.protocol_type == 1:
					msg = decrypt_data(enc_hdr + msg)
					parse_msg(msg[len(hdr):], payload_len, ty, self)
				else:
					parse_msg(msg, payload_len, ty, self)


			except Exception as e:
				print_log("server handle error: {}".format(e))
				self.rfile.close()
				self.wfile.close()
				self.request.close()
				break
# 启动服务器
#
def start_server(host, port):

	try:
		addr = (host, port)
		server = ThreadingTCPServer(addr, client_handler)
		
		print_log("waitting connect...")
		print_log("Listen {}:{}".format("localhost", port))
		server.serve_forever()

	except Exception as e:
		print_log("threading tcp server error {}".format(e))

def write_to_file(file_full_name, file_data):
	ret = True
	fh = open(file_full_name, 'wb')
	try:
		fh.write(file_data)
	except Exception as e:
		print_log("write_to_file: write file failed, error {0}, file {1}".format(e, file_full_name))
		ret = False
	return ret

# 监控客户端新版本，并下载到本地
#
def monitor_version():

	ver_file = os.getcwd() + "\\" + g_version_file_name
	ver_old_num = 8
	ver_new_num = 0
	ver_target_file = None
	
	# wait start event
	print_log("monitor version waitting...")
	g_start_monitor_event.wait(None)
	g_start_monitor_event.clear()

	while True:
		if os.path.exists(ver_file):
			js_ver_data = json.load(open(ver_file))
			if js_ver_data is not None:
				ver_old_num = js_ver_data['version_num']
		else:
			ver_old_num = 0
			print_log("not exist file {}, need check out!!!".format(ver_file))

		while True:
			try:
				web_client = get_webservice()
				if web_client == None:
					print_log("monitor version: query check update failed, get webservice failed")
					break

				result = web_client.service.getFile("client", g_version_file_name)
				if result == None:
					print_log("monitor version: query check update failed, webservice result is None")
					break
				version_data = base64.b64decode(result)
				if version_data is None:
					break
				js_data = json.loads(version_data)
				ver_new_num = js_data['version_num']
				ver_target_file = js_data['pack_position'] + "\\" + js_data['pack_name']
				upgrade_file = os.getcwd() + "\\" + js_data['pack_name']

				print_log("monitor version: old num {0}, new num {1}, target file {2}".format(ver_old_num, ver_new_num, ver_target_file))

				if ver_old_num >= ver_new_num:
					print_log("monitor version: do not need update!!!")
					break

				print_log("monitor version: start download upgrade file...")
				upgrade_data = web_client.service.getFile("client", ver_target_file)
				if upgrade_data == None:
					print_log("monitor version: download upgrade file failed!!!")
					break

				print_log("monitor version: download upgrade file succeed!!!")
				upgrade_data_b64 = base64.b64decode(upgrade_data)

				# call base64 encode function in utils.dll (use AdkBase64EcodeEx)
				outlen = c_int(0)
				pdata = create_string_buffer(upgrade_data_b64)
				upgrade_data = g_utils_dll.b64encode(byref(pdata), len(upgrade_data_b64), byref(outlen))
				if upgrade_data == 0:
					print_log("monitor version: utils b64encode failed")
					break
				print_log("monitor version: utils b64encode out buffer length {}".format(outlen.value))
				pupgrade_data = c_char_p(upgrade_data)
				if write_to_file(upgrade_file, pupgrade_data.value) == False:
					break

				# free after use g_utils_dll.b64encode (AdkFree)
				g_utils_dll.b64free(pupgrade_data)

				if write_to_file(ver_file, version_data) == False:
					break

				# cover old version num
				ver_old_num = ver_new_num

			except Exception as e:
				print_log("monitor version: query check update failed, error {}".format(e))
			break
		
		time.sleep(60)
	pass

if __name__ == "__main__":

	try:
		init_log()
		init_webservice_locker()

		print_log("Initialize system...")

		config_file = os.getcwd() + "\\config\\sys.ini"
		assert(os.path.exists(config_file))
		cfgfile = open(config_file, 'r')

		config = ConfigParser.ConfigParser()
		config.readfp(cfgfile)
		port = config.getint("sys", "port")
		verfile = config.get("sys", "version_file")
		cfgfile.close()

		print_log("Config listen port:{}".format(port))
		print_log("Config version file: {}".format(verfile))
		
		g_version_file_name = verfile

		t = threading.Thread(target = monitor_version)
		t.start()

		# get last webservice URL from file
		if os.path.exists(g_webservice_file):
			jsd = json.load(open(g_webservice_file))
			update_webservice(jsd['url'])
		
		print_log("Start server...")
		start_server("", port)
	
	except Exception as e:
		print("Start server failed, error {}".format(e))
