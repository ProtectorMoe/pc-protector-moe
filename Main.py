# -*- coding: utf-8 -*-
import sys
import re
import threading
import datetime
import webbrowser
import time
import requests.exceptions
import json
import os
import random
import logging
import win32api
import shutil
import base64
import hashlib
import hmac
import urllib
import urllib3

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import PyQt5.sip

from Constant import *
from Function import *
from Frame_login import *
from Frame_main import *
from Frame_rw import *
from Frame_rw_detail import *
from Frame_add_battle import *
from Frame_add_pvp import *
from Frame_add_campaign import *
from Frame_count_ship import *
from Frame_user_login import *
from Frame_pay import *
from Frame_select_ship import *
from Frame_user_fleet import *
from Frame_mine import *
from TaryIcon import *


class WindowsUserLogin(QDialog, Ui_Frame_user_login):
    """
    用户输入帐号和密码进行登录
    """
    def __init__(self):
        super(WindowsUserLogin, self).__init__()
        self.setupUi(self)
        self.username = ""
        self.password = ""
        self.server = 0
        self.bt_close.clicked.connect(self.close)

        self.ed_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ed_username.setClearButtonEnabled(True)  # 设置清除
        self.ed_password.setClearButtonEnabled(True)  # 设置清除

        if os.path.exists("config/user.json"):
            with open("config/user.json") as f:
                user = json.loads(f.read())
                if "username" in user:
                    self.ed_username.setText(user["username"])
                if "password" in user:
                    self.ed_password.setText(user["password"])
                if "server" in user:
                    self.cb_server.setCurrentIndex(int(user["server"]))

    def closeEvent(self, *args, **kwargs):
        self.username = self.ed_username.text()
        self.password = self.ed_password.text()
        self.server = self.cb_server.currentIndex()
        with open("config/user.json", "w") as f:
            data = {"username": self.username, "password": self.password, "server": self.server}
            f.write(json.dumps(data))


class WindowsLogin(QMainWindow, Ui_Frame_login):
    first_login_signal = pyqtSignal(dict)
    second_login_signal = pyqtSignal(dict)
    statusBarSignal = pyqtSignal(str)

    def __init__(self):
        self.is_login_success = False
        super(WindowsLogin, self).__init__()
        self.setupUi(self)
        self.first_login_signal.connect(self.first_login_deal)
        self.second_login_signal.connect(self.second_login_deal)
        self.statusBarSignal.connect(self.onstatusBar)
        self.get_login_picture()
        # 状态寄存器
        self.first_finish = False
        self.second_finish = False
        self.is_sl_login = False

        # 暂存数据
        self.server_list = []

        # 取出数据
        self.username = ""
        self.password = ""
        self.server = 0
        self.host = ""

        # 得到数据
        self.channel = None
        self.cookie = None
        self.host = None
        self.version = None
        self.uid = ""

        # 绑定按钮方法
        self.bt_login.clicked.connect(self.second_login)
        self.bt_change_user.clicked.connect(self.first_login)
    
    def onstatusBar(self, data):
        try:
            self.statusBar.showMessage(data)
        except Exception as e:
            log.error(e)
    
    def closeEvent(self, *args, **kwargs):
        if not self.second_finish:
            ti.setVisible(False)
            os._exit(0)

    def re_login(self):
        """
        进行SL,重新登录游戏
        :return:
        """
        for i in range(5):
            result1 = gameLogin.first_login_usual(self.server, self.username, self.password)
            result2 = gameLogin.second_login(self.host, self.uid)
            if result1 and result2:
                break
            else:
                continue

    def get_login_picture(self):
        """
        获取登录图片
        """
        def th_get_pic():
            try:
                name = "{}.jpg".format(str(random.randint(0, 55)))
                if not os.path.exists("gamepaper"):
                    os.mkdir("gamepaper")

                pic = QPixmap()
                data = None
                need_download = False
                if os.path.exists("gamepaper/" + name):
                    with open("gamepaper/" + name, 'rb') as f:
                        data = f.read()
                        if len(data) < 1024 * 100:
                            need_download = True
                else:
                    need_download = True

                if need_download:
                    url = "http://www.simonkimi.top/gamepaper/" + name
                    data = requests.get(url).content
                    with open("gamepaper/" + name, 'wb') as f:
                        f.write(data)

                pic.loadFromData(data)

                pic.scaled(380, 281)
                self.tv_paper.setPixmap(pic)
            except:
                pass
        threading.Thread(target=th_get_pic, args=()).start()

    # 首次登录进行处理
    def first_login(self):
        # 先显示自己
        try:
            self.show()
            self.cb_server.clear()
            self.username, self.password, self.server = gameLogin.input_user_info()
            # 开启子线程进行数据请求
            if len(self.username) != 0 and len(self.password) != 0:
                gameData.login_name = self.username.upper()
                threading.Thread(target=gameLogin.first_login_usual,
                                 args=(self.server, self.username, self.password)).start()
        except Exception as e:
            log.error("windows第一次登录失败", e)

    # 首次登录回调函数
    def first_login_deal(self, data):
        try:
            # 如果登录出现了问题
            if "error" in data:
                self.statusBarSignal.emit("首次登录错误:" + data["errmsg"])
                self.first_finish = False
                return False

            # 如果登录成功,则初始化内容
            self.cookie = data["cookie"]
            self.version = data["version"]
            self.channel = data["channel"]
            self.server_list = data["server_list"]
            self.uid = data["uid"]
            default_server = data["default_server"]
            # 加入基本服务器
            self.cb_server.clear()
            index = 0
            for server in self.server_list:
                self.cb_server.addItem(server["name"])
                if int(server["id"]) == default_server:
                    self.cb_server.setCurrentIndex(index)
                index += 1
            self.statusBarSignal.emit("登录成功,请选择服务器")
            self.first_finish = True
            return True
        except Exception as e:
            log.error("第一次登录deal失败", str(e))
            self.statusBarSignal.emit("第一次登录deal失败" + str(e))

    # 按钮绑定实现,实现第二次登录
    def second_login(self):
        try:
            if self.first_finish:
                server_index = self.cb_server.currentIndex()
                self.host = self.server_list[server_index]["host"]
                log.info("第二次登录", self.host, self.uid)
                threading.Thread(target=gameLogin.second_login, args=(self.host, self.uid)).start()
            else:
                self.statusBarSignal.emit("游戏登录错误!无法进入游戏!")
        except Exception as e:
            self.statusBarSignal.emit("第二次登录失败" + str(e))
            log.error("第二次登录失败", str(e))

    def second_login_deal(self, data):
        try:
            # 如果第二次登录出现问题
            if "error" in data:
                self.statusBarSignal.emit("第二次登录错误:" + data["errmsg"])
                self.second_finish = False
                return False
            # 第二次登录完成
            self.statusBarSignal.emit("初始化信息...")
            gameFunction.start_game_function(version=self.version, channel=self.channel,
                                             cookies=self.cookie, server=self.host)
            self.statusBarSignal.emit("获取用户信息...")
            gameData.get_data(version=self.version, channel=self.channel, cookies=self.cookie,
                              server=self.host)
            self.second_finish = True
            if not self.is_sl_login:
                self.is_sl_login = True
                self.statusBarSignal.emit("初始化界面...")
                login()
            return True
        except urllib3.exceptions.ReadTimeoutError as e:
            self.statusBarSignal.emit("登录超时:" + str(e))
        except Exception as e:
            self.statusBarSignal.emit("第二次登录错误:" + str(e))


class GameLogin:
    """
    第一次: channal cookie version server_list
    的二次: 什么也不返回,用于初始化游戏数据
    """
    def __init__(self):
        self.pastport_headers = {
            "Accept-Encoding": "gzip",
            'User-Agent': 'okhttp/3.4.1',
            "Content-Type": "application/json; charset=UTF-8"
        }
        self.init_data_version = "0"
        self.hm_login_server = ""
        self.portHead = ""
        self.key = "kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe"
        self.login_server = ""
        self.res = ""

        # 第一次登录返回值
        self.version = "3.8.0"
        self.channel = '100016'
        self.cookies = None
        self.server_list = []  # 不同服务器的索引
        self.defaultServer = 0
        self.uid = None

        # 状态寄存器
    # 读取用户输入帐号密码, 返回
    def input_user_info(self):
        w = WindowsUserLogin()
        if w.exec_():
            pass
        return w.username, w.password, w.server

    # 第一次登录,获取cookies和服务器列表
    def first_login_usual(self, server, username, pwd):
        """
        第一次登录,获取cookies和服务器列表
        :return:
        """
        try:
            windows_login.tv_selfVersion.setText(str(VERSION))
            windows_login.tv_selfVersion.setFont(QFont("Roman times", 10, QFont.Bold))
            url_version = ""
            if server == 0:  # 安卓服
                url_version = 'http://version.jr.moefantasy.com/' \
                              'index/checkVer/4.1.0/100016/2&version=4.1.0&channel=100016&market=2'
                self.res = 'http://login.jr.moefantasy.com/index/getInitConfigs/'
                self.channel = "100016"
                self.portHead = "881d3SlFucX5R5hE"
                self.key = "kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe"
            elif server == 1:  # ios服
                url_version = 'http://version.jr.moefantasy.com/' \
                              'index/checkVer/4.1.0/100015/2&version=4.1.0&channel=100015&market=2'
                self.res = 'http://loginios.jr.moefantasy.com/index/getInitConfigs/'
                self.channel = "100015"
                self.portHead = "881d3SlFucX5R5hE"
                self.key = "kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe"
            elif server == 2:  # 台服
                url_version = 'http://version.jr.moepoint.tw/' \
                              'index/checkVer/4.0.3/100033/2&version=4.0.3&channel=100033&market=2'
                self.res = "http://login.jr.moepoint.tw/index/getInitConfigs/"
                self.channel = "100033"
                self.portHead = "6f67d7612241"
                self.key = "c918ae4f4a75464fa964093ae8a66dae"
            elif server == 3:  # 日服
                url_version = 'http://version.jp.warshipgirls.com/' \
                              'index/checkVer/4.0.3/100024/2&version=3.8.0&channel=100024&market=2'
                self.res = "https://loginand.jp.warshipgirls.com/index/getInitConfigs/"
                self.channel = "100024"
            elif server == 4:  # 国际服
                url_version = 'http://enversion.warshipgirls.com/' \
                              'index/checkVer/4.1.0/100060/2&version=4.1.0&channel=100060&market=2'
                self.res = "http://enlogin.warshipgirls.com/index/getInitConfigs/"
                self.channel = "100060"
                self.portHead = "krtestfrontend"
                self.key = "abcdef01234567890abcdef01234567890"
            # 请求version
            # -------------------------------------------------------------------------------------------
            # 拉取版本信息
            windows_login.statusBarSignal.emit("拉取版本信息...")
            response_version = session.get(url=url_version, headers=HEADER, timeout=10)
            response_version = response_version.text
            response_version = json.loads(response_version)
            init_data.new_init_version = response_version['DataVersion']
            error_find(response_version)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/version.json', 'w') as f:
                    f.write(json.dumps(response_version))

            # 获取版本号, 登录地址
            self.version = response_version["version"]["newVersionId"]
            self.login_server = response_version["loginServer"]
            self.hm_login_server = response_version["hmLoginServer"]
            windows_login.tv_gameVersion.setText(str(self.version))
            windows_login.tv_gameVersion.setFont(QFont("Roman times", 10, QFont.Bold))
            # -------------------------------------------------------------------------------------------
            # 进行登录游戏
            server_data = {}
            if server == 0 or server == 1 or server == 2 or server == 4:
                server_data = self.login_usual(server=server, username=username, pwd=pwd)
            else:
                server_data = self.login_japan(username=username, password=pwd)

            self.defaultServer = int(server_data["defaultServer"])
            self.server_list = server_data["serverList"]
            self.uid = server_data["userId"]

            return_data = {
                "version": self.version,
                "channel": self.channel,
                "cookie": self.cookies,
                "server_list": self.server_list,
                "default_server": self.defaultServer,
                "uid": self.uid
            }
            windows_login.first_login_signal.emit(return_data)
            return True

        except HmError as e:
            return_data = {
                "error": 0,
                "errmsg": e.message
            }
            windows_login.first_login_signal.emit(return_data)
            log.error("第一次登录出错:", e.message)
            return False
        except Exception as e:
            return_data = {
                "error": 0,
                "errmsg": str(e)
            }
            windows_login.first_login_signal.emit(return_data)
            log.error("第一次登录出错:", e)
            return False

    # 第二次登录,用于连接对应服务器
    def second_login(self, host, uid):
        try:
            # 生成随机设备码
            windows_login.statusBarSignal.emit("生成设备随机码...")
            now_time = str(int(round(time.time() * 1000)))
            random.seed(hashlib.md5(self.uid.encode('utf-8')).hexdigest())
            data_dict = {'client_version': self.version,
                         'phone_type': 'huawei tag-al00',
                         'phone_version': '5.1.1',
                         'ratio': '1280*720',
                         'service': 'CHINA MOBILE',
                         'udid': str(random.randint(100000000000000, 999999999999999)),
                         'source': 'android',
                         'affiliate': 'WIFI',
                         't': now_time,
                         'e': self.get_url_end(now_time),
                         'gz': '1',
                         'market': '2',
                         'channel': self.channel,
                         'version': self.version
                         }
            random.seed()
            # 获取欺骗数据
            windows_login.statusBarSignal.emit("连接服务器...")
            login_url_1 = host + 'index/login/' + uid + '?&' + urllib.parse.urlencode(data_dict)
            session.get(url=login_url_1, headers=HEADER, cookies=self.cookies, timeout=10)

            windows_login.statusBarSignal.emit("请求战役数据...")
            url_cheat = host + 'pevent/getPveData/' + self.get_url_end()
            pevent_getPveData = json.loads(
                zlib.decompress(session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/pevent_getPveData.json", 'w') as f:
                    f.write(json.dumps(pevent_getPveData))

            windows_login.statusBarSignal.emit("请求商店数据...")
            url_cheat = host + 'shop/canBuy/1/' + self.get_url_end()
            shop_canbuy = json.loads(
                zlib.decompress(session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/shop_canbuy.json", 'w') as f:
                    f.write(json.dumps(shop_canbuy))

            windows_login.statusBarSignal.emit("请求宿舍数据...")
            url_cheat = host + 'live/getUserInfo' + self.get_url_end()
            shop_canbuy = json.loads(zlib.decompress(
                session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/live_getUserInfo.json", 'w') as f:
                    f.write(json.dumps(shop_canbuy))

            windows_login.statusBarSignal.emit("请求背景音乐数据...")
            url_cheat = host + 'live/getMusicList/' + self.get_url_end()
            shop_canbuy = json.loads(zlib.decompress(
                session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/live_getMusicList.json", 'w') as f:
                    f.write(json.dumps(shop_canbuy))

            url_cheat = host + 'bsea/getData/' + self.get_url_end()
            windows_login.statusBarSignal.emit("请求海域数据...")
            bsea_getData = json.loads(
                zlib.decompress(session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/bsea_getData.json", 'w') as f:
                    f.write(json.dumps(bsea_getData))

            url_cheat = host + 'active/getUserData' + self.get_url_end()
            windows_login.statusBarSignal.emit("请求活动数据...")
            active_getUserData = json.loads(
                zlib.decompress(session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/active_getUserData.json", 'w') as f:
                    f.write(json.dumps(active_getUserData))

            url_cheat = host + 'pve/getUserData/' + self.get_url_end()
            windows_login.statusBarSignal.emit("请用用户海域数据...")
            pve_getUserData = json.loads(
                zlib.decompress(session.get(url=url_cheat, headers=HEADER, cookies=self.cookies, timeout=10).content))
            if is_write and os.path.exists('requestsData'):
                with open("requestsData/pve_getUserData.json", 'w') as f:
                    f.write(json.dumps(pve_getUserData))

            windows_login.statusBarSignal.emit("请求init数据...")
            self.get_init_data()
            windows_login.statusBarSignal.emit("初始化界面...")
            windows_login.second_login_signal.emit({})
            return True
        except HmError as e:
            log.e("第二次登录请求数据出错", e.message)
            windows_login.second_login_signal.emit({"error": 0, "errmsg": e.message})
            return False
        except Exception as e:
            log.e("第二次登录请求数据出错", e)
            windows_login.second_login_signal.emit({"error": 0, "errmsg": str(e)})
            return False

    # 普通登录实现方法
    def login_usual(self, username, pwd, server):
        try:
            def login_token():
                windows_login.statusBarSignal.emit("获取token...")
                url_login = self.hm_login_server + "1.0/get/login/@self"
                # 获取tokens
                data = {}
                if server == 0 or server == 1 or server == 4:  # 安卓服 ios服 国际服
                    data = {
                        "platform": "0",
                        "appid": "0",
                        "app_server_type": "0",
                        "password": pwd,
                        "username": username
                    }
                elif server == 2:  # 台服
                    data = {
                        "appId": "0",
                        "appServerType": "0",
                        "password": pwd,
                        "userName": username
                    }
                self.refresh_headers(url_login)
                login_response = session.post(url=url_login, data=json.dumps(data).replace(" ", ""),
                                              headers=self.pastport_headers, timeout=10).text
                login_response = json.loads(login_response)

                if "error" in login_response and int(login_response["error"]) != 0:
                    if "errmsg" in login_response:
                        raise HmError(-113, login_response["errmsg"])
                    else:
                        raise HmError(-113, "无法登录服务器")

                # 字段里是否存在存在token
                tokens = ""
                if "access_token" in login_response:
                    tokens = login_response["access_token"]
                if "token" in login_response:
                    tokens = login_response["token"]

                token_list = {}
                # 写入tokens
                if os.path.exists("config/token.json"):
                    with open("config/token.json", 'r') as f2:
                        token_list = json.loads(f2.read())
                token_list[username] = tokens
                with open("config/token.json", 'w') as f1:
                    f1.write(json.dumps(token_list))
                return tokens

            # 第一个意义不明
            windows_login.statusBarSignal.emit("请求initConfig...")
            url_init = self.hm_login_server + "1.0/get/initConfig/@self"
            self.refresh_headers(url_init)
            session.post(url=url_init, data="{}", headers=self.pastport_headers, timeout=10)
            time.sleep(1)

            # 获取token
            token = ""
            if os.path.exists("config/token.json"):
                with open("config/token.json", "r") as f:
                    token_json = json.loads(f.read())
                    if username in token_json:
                        token = token_json[username]

            while True:
                # 没有token,获取token
                if len(token) < 10:
                    token = login_token()
                    time.sleep(1)

                # 验证token
                windows_login.statusBarSignal.emit("验证token...")
                url_info = self.hm_login_server + "1.0/get/userInfo/@self"
                login_data = {}
                if server == 0 or server == 1:
                    login_data = json.dumps({"access_token": token})
                else:
                    login_data = json.dumps({"token": token})
                self.refresh_headers(url_info)
                user_info = session.post(url=url_info, data=login_data, headers=self.pastport_headers, timeout=10).text
                user_info = json.loads(user_info)
                if "error" in user_info and user_info["error"] != 0:  # 口令失效, 重新获取
                    token = ""
                    continue
                else:  # 口令正确
                    break

            # 获取用户信息
            windows_login.statusBarSignal.emit("获取用户信息...")
            login_url = self.login_server + "index/hmLogin/" + token + self.get_url_end()
            login_response = session.get(url=login_url, headers=HEADER, timeout=10)
            login_text = json.loads(zlib.decompress(login_response.content))

            if is_write and os.path.exists('requestsData'):
                with open("requestsData/login.json", 'w') as f:
                    f.write(json.dumps(login_text))
            self.cookies = login_response.cookies.get_dict()
            self.uid = str(login_text['userId'])
            return login_text
        except HmError as e:
            raise
        except Exception as e:
            log.error("登录游戏出错", e)

    # 日服登录实现方法
    def login_japan(self, username, password):
        """
        功能：登录游戏并返回cookies
        无返回值
        """
        # 生成登录字典  login_dict：登录密码字典  login_url:登录url
        login_dict = {'username': base64.b64encode(username.encode()), 'pwd': base64.b64encode(password.encode())}
        login_url = self.login_server + 'index/passportLogin/' + self.get_url_end()

        # 登录游戏
        login_response = session.post(url=login_url, data=login_dict, headers=HEADER, timeout=10)
        login_text = json.loads(zlib.decompress(login_response.content))
        # 检测帐号是否正常
        if 'eid' in login_text and int(login_text['eid']) == -113:
            raise HmError(-113, "错误代码:帐号或者密码错误")
        error_find(login_text)
        if is_write:
            with open("login.json", 'w') as f:
                f.write(json.dumps(login_text))
        # 得到cookie和uid
        self.cookies = login_response.cookies.get_dict()
        self.uid = str(login_text['userId'])
        return login_text

    def get_url_end(self, now_time=str(int(round(time.time() * 1000)))):
        """
        功能：返回url尾部
        返回值：文本型
        """
        url_time = now_time
        md5_raw = url_time + 'ade2688f1904e9fb8d2efdb61b5e398a'
        md5 = hashlib.md5(md5_raw.encode('utf-8')).hexdigest()
        url_end = '&t={time}&e={key}&gz=1&market=2&channel={channel}&version={version}'
        url_end_dict = {'time': url_time, 'key': md5, 'channel': self.channel, 'version': self.version}
        url_end = url_end.format(**url_end_dict)
        return url_end

    def encryption(self, url, method):
        times = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        data = ""
        data += str(method)
        data += "\n"
        data += times
        data += "\n"
        data += "/" + url.split("/", 3)[-1]
        mac = hmac.new(self.key.encode(), data.encode(), hashlib.sha1)
        data = mac.digest()
        return base64.b64encode(data).decode("utf-8"), times

    def refresh_headers(self, url):
        data, times = self.encryption(url=url, method="POST")
        self.pastport_headers["Authorization"] = "HMS {}:".format(self.portHead) + data
        self.pastport_headers["Date"] = times

    def get_init_data(self):
        print('Getting init data...')
        try:
            if not os.path.exists('data'):
                os.mkdir('data')

            need_upgrade = True
            if os.path.exists('data/init.json'):
                init_data.read_init()
                if int(init_data.new_init_version) <= int(init_data.init_version):
                    need_upgrade = False
            if init_data.res_url != self.res:
                need_upgrade = True
            if need_upgrade:
                user_data = gameFunction.get_init_data(self.res, self.get_url_end())
                if not os.path.exists('data'):
                    os.mkdir('data')
                with open('data/init.json', 'w') as f:
                    f.write(user_data)
                init_data.read_init()
            return True
        except HmError as e:
            print('Get init data FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get init data FAILED! Reason:', e)
            raise


class WindowsRw(QMainWindow, Ui_Frame_Rw):
    def __init__(self):
        super(WindowsRw, self).__init__()
        self.setupUi(self)


class WindowsAddBattle(QMainWindow, Ui_Frame_add_battle):
    def __init__(self):
        super(WindowsAddBattle, self).__init__()
        self.setupUi(self)
        self.repair_data = [{}, {}, {}, {}, {}, {}]
        self.ship = []
        self.signal_connect()
        self.rb_random_change.setChecked(True)
        self.bt_ship_add.clicked.connect(self.add_ship)
        self.bt_ship_del.clicked.connect(self.del_ship)
        self.bt_re.clicked.connect(self.re_b)
        self.bt_setFleet.clicked.connect(windows_user_fleet.i)

        self.cb_fleet.currentIndexChanged.connect(self.upgrade_add_battle_fleet)

        # 临时数据
        self.user_fleet = {}

    def add_ship(self):
        w = WindowsSelectShip()
        w.can_select = -1
        w.select_ship = self.ship
        w.refresh_select_ship()
        if w.exec_():
            self.ship = w.select_ship

        self.lt_ship.clear()
        for ship in self.ship:
            self.lt_ship.addItem("Lv." + str(gameData.allShip[ship]['level']) + "  " + init_data.ship_cid_wu[gameData.allShip[ship]['shipCid']]['title'])

    def del_ship(self):
        self.ship = []
        self.lt_ship.clear()

    def initialize(self):
        try:
            self.repair_data[0] = {'type': 0, 'rule': 0, 'data': {}}
            self.repair_data[1] = {'type': 0, 'rule': 0, 'data': {}}
            self.repair_data[2] = {'type': 0, 'rule': 0, 'data': {}}
            self.repair_data[3] = {'type': 0, 'rule': 0, 'data': {}}
            self.repair_data[4] = {'type': 0, 'rule': 0, 'data': {}}
            self.repair_data[5] = {'type': 0, 'rule': 0, 'data': {}}
            self.cb_1.setChecked(True)
            self.cb_2.setChecked(True)
            self.cb_3.setChecked(True)
            self.cb_4.setChecked(True)
            self.cb_5.setChecked(True)
            self.cb_6.setChecked(True)
            self.rb_fast_repair.setChecked(True)
            self.rb_change.setChecked(False)
            self.rb_repair.setChecked(False)
            self.rb_random_change.setChecked(True)
            self.rb_arrow_change.setChecked(False)
            self.upgrade_list()
            self.upgrade_fleet_list()
        except Exception as e:
            log.error('Initialize Error:', e)

    def upgrade_list(self):
        try:
            self.lt_rule.clear()
            for ship in range(len(self.repair_data)):
                data = self.repair_data[ship]
                speak = "位" + str(ship) + " "
                if data['rule'] == 0:
                    speak += "同全局 "
                elif data['rule'] == 1:
                    speak += "中破修 "
                elif data['rule'] == 2:
                    speak += "大破修 "

                if data['type'] == 0:
                    speak += "用快修 "
                elif data['type'] == 1:
                    speak += "去泡澡 "
                    if g.repair_time:
                        speak += "修理阈值:" + str(g.repair_time_limit) + "小时"
                elif data['type'] == 2:
                    speak += "换船 "
                    if data['data']['random'] is True:  # 模糊匹配
                        speak += '等级' + str(data['data']['min']) + "~" + str(data['data']['max'])
                    else:
                        speak += '船:' + " ".join(
                            [init_data.ship_cid_wu[gameData.allShip[int(ids)]['shipCid']]['title'] for ids in
                             data['data']['ship']])
                self.lt_rule.addItem(speak)
        except Exception as e:
            log.error("Upgrade list Error", e)

    def upgrade_rule(self):
        ship = []
        ship.clear()
        if self.cb_1.isChecked() is True:
            ship.append(0)
        if self.cb_2.isChecked() is True:
            ship.append(1)
        if self.cb_3.isChecked() is True:
            ship.append(2)
        if self.cb_4.isChecked() is True:
            ship.append(3)
        if self.cb_5.isChecked() is True:
            ship.append(4)
        if self.cb_6.isChecked() is True:
            ship.append(5)

        if len(ship) != 0:
            if self.rb_fast_repair.isChecked() is True:  # 增加快修
                for x in ship:
                    self.repair_data[x] = {
                        'type': 0,
                        'rule': self.comboBox.currentIndex(),
                        'data': {}
                    }
            elif self.rb_repair.isChecked() is True:  # 增加泡澡
                for x in ship:
                    self.repair_data[x] = {
                        'type': 1,
                        'rule': self.comboBox.currentIndex(),
                        'data': {
                        }
                    }
                    g.repair_time_limit = self.ed_repairMaxTime.text()
                    g.repair_time = self.cb_repair_time.isChecked()
            elif self.rb_change.isChecked() is True:  # 增加换船
                for x in ship:
                    self.repair_data[x] = {
                        'type': 2,
                        'rule': self.comboBox.currentIndex(),
                        'data': {
                            'equipment': self.cb_equipment.isChecked(),
                            'random': self.rb_random_change.isChecked(),
                            'min': self.ed_level_min.value(),
                            'max': self.ed_level_max.value(),
                            'accurate': self.rb_arrow_change.isChecked(),
                            "isG": self.cb_only_g.isChecked(),
                            'ship': self.ship
                        }
                    }
        self.upgrade_list()

    def signal_connect(self):
        self.bt_rule_add.clicked.connect(self.upgrade_rule)
        self.bt_rule_del.clicked.connect(self.initialize)

    def re_b(self):
        try:
            fleet = windows_add_battle.cb_fleet.currentIndex()
            if not fleet <= 3:
                return
            w = WindowsSelectShip()
            w.can_select = 6
            w.select_ship = gameData.fleet[fleet]
            w.refresh_select_ship()
            data = None
            if w.exec_():
                data = other_function.change_fleet(fleet=fleet, ships=w.select_ship)
            if data is not None:
                gameData.upgrade_fleet(data)
        except HmError as e:
            QMessageBox.information(self, "护萌宝-编队-错误", e.message, QMessageBox.Yes)
        except Exception as e:
            QMessageBox.information(self, "护萌宝-编队-错误", str(e), QMessageBox.Yes)

    def upgrade_fleet_list(self):
        self.cb_fleet.clear()
        self.cb_fleet.addItem("一队")
        self.cb_fleet.addItem("二队")
        self.cb_fleet.addItem("三队")
        self.cb_fleet.addItem("四队")
        windows_user_fleet.read_config()
        for md5, data in windows_user_fleet.user_fleet.items():
            self.cb_fleet.addItem(data["name"])

    def upgrade_add_battle_fleet(self):
        try:
            index = self.cb_fleet.currentIndex()
            if index <= 3:
                fleet = gameData.fleet[index]
            else:
                md5 = windows_user_fleet.list_index[index - 4]
                fleet = windows_user_fleet.user_fleet[md5]['ship']

            if len(fleet) > 0:
                self.lt_fleet.clear()
                for each_ship in fleet:
                    self.lt_fleet.addItem(
                        'Lv.' + str(gameData.allShip[int(each_ship)]['level']) + ' ' + str(
                            gameData.allShip[int(each_ship)]['title']))
        except Exception as e:
            log.error('Upgrade start fleet ERROR:', str(e))



class WindowsAddPVP(QMainWindow, Ui_Frame_add_pvp):
    add_signal = pyqtSignal(dict)

    def __init__(self):
        super(WindowsAddPVP, self).__init__()
        self.setupUi(self)
        self.add_signal.connect(self.upgrade_list)

    def upgrade_list(self, data):
        try:
            if "cls" in data:
                self.lt_pvp.clear()
                return True
            print(data)
            user_name = data['user_name']
            user_level = data['user_level']
            user_pj = data['user_pj']
            # 创建列表对象
            widget = QWidget()
            ly_main = QHBoxLayout()
            # 显示用户信息
            ly_user = QVBoxLayout()
            l_user = QLabel(user_name)
            l_user.setFixedSize(50, 15)
            ly_user.addWidget(l_user)
            l_level = QLabel(user_level)
            l_level.setFixedSize(50, 15)
            ly_user.addWidget(l_level)
            l_pj = QLabel(user_pj)
            ly_user.addWidget(l_pj)
            ly_main.addLayout(ly_user)
            # 显示用户船只信息
            user_ship = data['user_ship']
            for ship in user_ship:
                ship_name = ship['ship_name']
                ship_level = ship['ship_level']
                ship_path = ship['ship_path']
                ly_ship = QVBoxLayout()
                l_photo = QLabel()
                if os.path.exists(ship_path):
                    maps = QPixmap(ship_path).scaled(40, 25)
                    l_photo.setPixmap(maps)
                    l_photo.setFixedSize(50, 25)
                else:
                    l_photo.setText("无图像")
                l_name = QLabel(ship_name)
                l_name.setFixedSize(50, 15)
                l_level = QLabel(ship_level)
                l_level.setFixedSize(40, 15)
                ly_ship.addWidget(l_photo)
                ly_ship.addWidget(l_name)
                ly_ship.addWidget(l_level)
                ly_main.addLayout(ly_ship)
            widget.setLayout(ly_main)
            item = QListWidgetItem()
            item.setSizeHint(QSize(40, 77))
            self.lt_pvp.addItem(item)
            self.lt_pvp.setItemWidget(item, widget)
        except Exception as e:
            print(e)


class WindowsAddCampaign(QMainWindow, Ui_Frame_add_campaign):
    def __init__(self):
        super(WindowsAddCampaign, self).__init__()
        self.setupUi(self)


class WindowsRwDetail(QMainWindow, Ui_Frame_rw_detail):
    def __init__(self):
        super(WindowsRwDetail, self).__init__()
        self.setupUi(self)


class WindowsMain(QMainWindow, Ui_Frame_main):
    our_ship = pyqtSignal(list)
    foe_ship = pyqtSignal(list)

    def __init__(self):
        super(WindowsMain, self).__init__()
        self.setupUi(self)
        self.setWindowTitle('护萌宝 Beta' + str(VERSION) + " 本软件永久免费, 任意售卖均未经许可")
        self.menu_event()
        self.our_ship.connect(self.refresh_our_ship)
        self.foe_ship.connect(self.refresh_foe_ship_data)
        self.lt_rw.clicked.connect(self.show_rw_detail)
        self.cb_run.setChecked(True)

    def menu_event(self):
        action_set_mine = QAction(QIcon('icon/mine.png'), '我的', self)
        action_set_mine.triggered.connect(lambda: OtherFunction.show_mine(self))

        action_set_collection = QAction(QIcon('icon/boat.png'), '图鉴', self)
        action_set_collection.triggered.connect(OtherFunction.show_mine_collection)

        action_set_main = QAction(QIcon('icon/zt.png'), '状态', self)
        action_set_main.triggered.connect(lambda: self.sw_mian.setCurrentIndex(0))

        action_set_dis = QAction(QIcon('icon/del.png'), '分解/强化', self)
        action_set_dis.triggered.connect(lambda: self.sw_mian.setCurrentIndex(1))

        action_set_build = QAction(QIcon('icon/jz.png'), '建造', self)
        action_set_build.triggered.connect(lambda: self.sw_mian.setCurrentIndex(2))

        action_set_exit = QAction(QIcon('icon/login.png'), '退出', self)
        action_set_exit.triggered.connect(lambda: os._exit(0))

        set_menu = self.menuBar.addMenu('功能')
        set_menu.addAction(action_set_mine)
        set_menu.addAction(action_set_collection)
        set_menu.addAction(action_set_main)
        set_menu.addAction(action_set_dis)
        set_menu.addAction(action_set_build)
        set_menu.addAction(action_set_exit)

        # 实用功能
        action_other_rename = QAction("名称反和谐", self)
        action_other_rename.triggered.connect(lambda: other_function.change_name(0))

        action_other_equipment = QAction("分解低级装备", self)
        action_other_equipment.triggered.connect(lambda: other_function.dismantle_equipment(0))

        other_menu = self.menuBar.addMenu("实用功能")
        other_menu.addAction(action_other_rename)
        other_menu.addAction(action_other_equipment)

        # 关于页面
        action_about_author = QAction('关于', self)
        action_about_author.triggered.connect(lambda: QMessageBox.information(self, '护萌宝-关于',
                                                                              '版本:Beta-' + str(VERSION)
                                                                              + '\n作者: Simon菌'
                                                                              + '\nQ'
                                                                              + '\n本软件免费,任何售卖均未授权!', QMessageBox.Yes))
        action_about_version = QAction('检测更新', self)
        def c_u():
            if not OtherFunction.check_upgrade():
                QMessageBox.information(windows_main, "检测更新", "当前已是最新!", QMessageBox.Yes)

        action_about_version.triggered.connect(c_u)

        action_about_log = QAction('导出日志', self)
        action_about_log.triggered.connect(lambda: OtherFunction.get_log(windows_main))

        about_menu = self.menuBar.addMenu('帮助')
        about_menu.addAction(action_about_author)
        about_menu.addAction(action_about_version)
        about_menu.addAction(action_about_log)


    def show_rw_detail(self):
        """
        timer = {
                             'name': rw_function.rw_list[windows_add_battle.cb_rw.currentIndex()],
                             'num': 0,
                             'num_max': windows_add_battle.ed_startNum.value(),
                             'type': 0,
                             'time': str(windows_add_battle.te_time.text()),
                             'last_time': 0,
                             'data': {
                                      'fleet': windows_add_battle.cb_fleet.currentIndex(),
                                      'repair_data': windows_add_battle.repair_data
                                     }
                            }
        """
        try:
            index = self.lt_rw.row(self.lt_rw.selectedItems()[0])
            self.lt_rw_detail.clear()
            if index <= len(th_main.classical_list) - 1:
                data = th_main.classical_list[index]
            else:
                data = th_main.timer_list[index - len(th_main.classical_list)]
            if 'name' in data:
                self.lt_rw_detail.addItem("名称: " + data['name'])
            # 队伍显示增加

            if 'data' in data:
                if 'fleet' in data['data']:
                    fleet = data['data']['fleet']
                    d = ""
                    if len(fleet) == 1:
                        d = "队伍: " + str(int(fleet) + 1)
                    else:
                        d = "队伍: " + windows_user_fleet.user_fleet[fleet]["name"] + ' → 队伍:' + str(
                            int(windows_user_fleet.user_fleet[fleet]["fleet"]) + 1)
                    self.lt_rw_detail.addItem(d)

            if 'num' in data:
                self.lt_rw_detail.addItem("次数: " + str(data['num']))
            if 'num_max' in data:
                self.lt_rw_detail.addItem("设定: " + str(data['num_max']))
            if 'type' in data:
                self.lt_rw_detail.addItem("类型: " + str(data['type']))
            if 'time' in data:
                self.lt_rw_detail.addItem("定时: " + str(data['time']))
            if 'last_time' in data:
                self.lt_rw_detail.addItem("冻结: " + str(data['last_time']))
        except Exception as e:
            print(e)

    def hideEvent(self, *args, **kwargs):
        config_function.main_save()
        self.hide()

    def closeEvent(self, event):
        r = QMessageBox.question(self, '确认退出', "是否退出程序?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        config_function.main_save()
        if r == QMessageBox.No:
            event.ignore()
        else:
            ti.setVisible(False)
            os._exit(0)

    def refresh_our_ship(self, data):
        self.lt_our.clear()
        try:
            for ship in data:
                wight = QWidget()
                title = ship['title'][:3]
                level = ship['level']
                hp = ship['hp']
                path = ship['path']
                # 头像显示
                ly_main = QHBoxLayout()
                map_l = QLabel()
                map_l.setFixedSize(40, 25)
                if os.path.exists(path):
                    maps = QPixmap(path).scaled(40, 25)
                    map_l.setPixmap(maps)
                else:
                    map_l.setText("None")
                ly_main.addWidget(map_l)
                # 信息显示
                ly_right = QGridLayout()
                ly_right.setSpacing(2)
                ly_right.addWidget(QLabel(title), 0, 0)
                ly_right.addWidget(QLabel("  HP"), 0, 1)
                ly_right.addWidget(QLabel(level), 1, 0)
                ly_right.addWidget(QLabel(hp), 1, 1)
                # 添加显示
                ly_main.addLayout(ly_right)
                wight.setLayout(ly_main)

                item = QListWidgetItem()
                item.setSizeHint(QSize(42, 45))
                self.lt_our.addItem(item)
                self.lt_our.setItemWidget(item, wight)
        except Exception as e:
            print('Refresh our ship ERROR:', e)

    def refresh_foe_ship_data(self, data):
        self.lt_our_2.clear()
        try:

            for ship in data:
                wight = QWidget()
                name = ship['title']
                hp = ship['hp']
                ly = QVBoxLayout()
                ly.addWidget(QLabel(name))
                ly.addWidget(QLabel(hp))
                wight.setLayout(ly)
                item = QListWidgetItem()
                item.setSizeHint(QSize(42, 45))
                self.lt_our_2.addItem(item)
                self.lt_our_2.setItemWidget(item, wight)
        except Exception as e:
            print('Refresh foe ship ERROR:', e)


class WindowsCountShip(QMainWindow, Ui_Frame_count_ship):
    def __init__(self):
        super(WindowsCountShip, self).__init__()
        self.setupUi(self)
        self.count_list = []
        self.bt_claen.clicked.connect(self.clean_count)

    def clean_count(self):
        rep = QMessageBox.question(self, '出货统计', '是否清空列表?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if rep == QMessageBox.No:
            return False
        self.count_list = []
        with open('count/ship.json', 'w') as f:
            f.write(json.dumps(self.count_list))
        self.table_count_ship.clear()
        self.close()


    def ready(self):
        self.count_list = []
        if not os.path.exists('count'):
            os.mkdir('count')
        if os.path.exists('count/ship.json'):
            with open('count/ship.json', 'r') as f:
                self.count_list = json.loads(f.read())
        self.table_count_ship.setColumnCount(5)
        self.table_count_ship.setHorizontalHeaderLabels(['时间', '名称', '星级', '位置', '评价'])
        self.table_count_ship.setColumnWidth(1, 150)
        self.table_count_ship.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.cb_count_2.setChecked(True)
        self.cb_count_3.setChecked(True)
        self.cb_count_4.setChecked(True)
        self.cb_count_5.setChecked(True)
        self.cb_count_2.clicked.connect(self.upgrade_list)
        self.cb_count_3.clicked.connect(self.upgrade_list)
        self.cb_count_4.clicked.connect(self.upgrade_list)
        self.cb_count_5.clicked.connect(self.upgrade_list)
        self.ed_point.textChanged.connect(self.upgrade_list)
        self.ed_ship.textChanged.connect(self.upgrade_list)
        self.upgrade_list()

    def showEvent(self, *args, **kwargs):
        self.upgrade_list()

    def upgrade_list(self):
        self.table_count_ship.clear()
        self.table_count_ship.setColumnCount(5)
        self.table_count_ship.setHorizontalHeaderLabels(['时间', '名称', '星级', '位置', '评价'])
        ships = list(reversed(self.count_list))
        num = 0
        list_ship = []
        for ship in ships:
            try:
                if init_data.ship_cid_wu[ship['cid']]['star'] <= 2 and self.cb_count_2.isChecked() is False:
                    continue
                elif init_data.ship_cid_wu[ship['cid']]['star'] == 3 and self.cb_count_3.isChecked() is False:
                    continue
                elif init_data.ship_cid_wu[ship['cid']]['star'] == 4 and self.cb_count_4.isChecked() is False:
                    continue
                elif init_data.ship_cid_wu[ship['cid']]['star'] == 5 and self.cb_count_5.isChecked() is False:
                    continue
                if len(windows_count_ship.ed_point.text()) != 0:
                    if windows_count_ship.ed_point.text() not in ship['path']:
                        continue
                if len(windows_count_ship.ed_ship.text()) != 0:
                    if windows_count_ship.ed_ship.text() not in init_data.ship_cid_wu[ship['cid']]['title']:
                        continue
                list_ship.append(ship)
            except Exception as e:
                log.error(e)
        self.table_count_ship.setRowCount(len(list_ship))
        for ship in list_ship:
            try:
                row = [str(x) for x in list(range(len(list_ship)))]
                self.table_count_ship.setVerticalHeaderLabels(row)
                name_item = QWidget()
                path = 'icon/photo/' + str(int(init_data.ship_cid_wu[ship['cid']]['shipIndex'])) + ".png"
                ly = QHBoxLayout()
                if os.path.exists(path):
                    maps = QPixmap(path).scaled(40, 25)
                    label = QLabel()
                    label.setPixmap(maps)
                else:
                    label = QLabel("None")
                ly.addWidget(label)
                ly.addWidget(QLabel(init_data.ship_cid_wu[ship['cid']]['title']))
                name_item.setLayout(ly)
                star_item = QTableWidgetItem('⭐' * init_data.ship_cid_wu[ship['cid']]['star'])
                time_item = QTableWidgetItem(time.strftime('%m/%d %H:%M:%S', time.localtime(int(ship['time']))))
                path_item = QTableWidgetItem(ship['path'])
                access_item = QTableWidgetItem(ship['access'])
                self.table_count_ship.setRowHeight(num, 40)
                self.table_count_ship.setItem(num, 0, time_item)
                self.table_count_ship.setCellWidget(num, 1, name_item)
                self.table_count_ship.setItem(num, 2, star_item)
                self.table_count_ship.setItem(num, 3, path_item)
                self.table_count_ship.setItem(num, 4, access_item)
                num += 1
            except Exception as e:
                log.error(e)

    def add_ship(self, cid, access, path):
        self.count_list.append({'cid': cid, 'access': access, 'path': path, 'time': time.time()})
        with open('count/ship.json', 'w') as f:
            f.write(json.dumps(self.count_list))


class WindowsMineShip(QMainWindow, Ui_FrameMine):
    exist_signal = pyqtSignal(dict)
    not_exist_signal = pyqtSignal(dict)

    def __init__(self):
        super(WindowsMineShip, self).__init__()
        self.setupUi(self)
        self.exist = []
        self.not_exist = []
        self.exist_signal.connect(self.add_exist)
        self.not_exist_signal.connect(self.add_not_exist)
        self.lt_exist_ship.clicked.connect(lambda: self.show_detail(
            self.exist[self.lt_exist_ship.row(self.lt_exist_ship.selectedItems()[0])]['ship_cid']))
        self.lt_not_exist_ship.clicked.connect(lambda: self.show_detail(
            self.not_exist[self.lt_not_exist_ship.row(self.lt_not_exist_ship.selectedItems()[0])]['ship_cid']))
        self.cb_count_1.clicked.connect(self.refresh_list)
        self.cb_count_2.clicked.connect(self.refresh_list)
        self.cb_count_3.clicked.connect(self.refresh_list)
        self.cb_count_4.clicked.connect(self.refresh_list)
        self.cb_count_5.clicked.connect(self.refresh_list)
        self.cb_count_6.clicked.connect(self.refresh_list)
        self.ed_name.textChanged.connect(self.refresh_list)
        self.cb_type.currentIndexChanged.connect(self.refresh_list)
        self.bt_detail.clicked.connect(self.open_detail)
        self.select_ship = -1

    def refresh_list(self):
        try:
            self.exist.clear()
            self.not_exist.clear()
            self.lt_exist_ship.clear()
            self.lt_not_exist_ship.clear()
            for cid, ship in init_data.ship_cid_wu.items():
                if cid > 20000000:
                    continue
                types_list = ['其他', "航母", '轻母', '装母', '战列', '航战', '战巡', '重巡', '航巡', '雷巡',
                              '轻巡', '重炮', '驱逐', '潜母', '潜艇', '炮潜', '补给', '导驱', '防驱']
                country_list = {8: 'C国', 3: "E国", 6: "F国", 2: "G国", 5: "I国", 1: "J国", 7: "S国", 4: "U国"}

                ship_name = ship['title']
                ship_photo = "icon/photo/" + str(int(ship['shipIndex'])) + ".png"
                ship_index = "No." + str(int(ship['shipIndex']))
                ship_star = ship['star']

                if ship['type'] < len(types_list):
                    ship_type = types_list[int(ship['type'])]
                else:
                    ship_type = "其他"

                if ship['country'] in country_list:
                    ship_country = country_list[int(ship['country'])]
                else:
                    ship_country = "其他"
                data = {'ship_name': ship_name, 'ship_photo': ship_photo, 'ship_index': ship_index,
                        'ship_star': ship_star,
                        'ship_type': ship_type, 'ship_country': ship_country, 'ship_cid': int(cid)}
                if int(ship['shipIndex']) > 8000:
                    continue
                if not self.cb_count_1.isChecked() and ship_star == 1:
                    continue
                if not self.cb_count_2.isChecked() and ship_star == 2:
                    continue
                if not self.cb_count_3.isChecked() and ship_star == 3:
                    continue
                if not self.cb_count_4.isChecked() and ship_star == 4:
                    continue
                if not self.cb_count_5.isChecked() and ship_star == 5:
                    continue
                if not self.cb_count_6.isChecked() and ship_star == 6:
                    continue
                if self.cb_type.currentIndex() != 0 and ship['type'] != self.cb_type.currentIndex():
                    continue
                if self.ed_name.text() != "" and self.ed_name.text() not in ship_name:
                    continue
                if int(cid) in gameData.unlockShip or str(cid) in gameData.unlockShip:
                    self.exist.append(data)
                else:
                    self.not_exist.append(data)

            self.tv_exist.setText("共" + str(len(self.exist)) + "个")
            self.tv_not_exist.setText("共" + str(len(self.not_exist)) + "个")
            for ship_data in self.exist:
                self.exist_signal.emit(ship_data)

            for ship_data in self.not_exist:
                self.not_exist_signal.emit(ship_data)

        except Exception as e:
            log.error("图鉴出错1", e)

    def add_exist(self, ship_data):
        try:
            item = QListWidgetItem()
            item.setSizeHint(QSize(50, 50))
            widget = self.get_list_item(ship_data)
            self.lt_exist_ship.addItem(item)
            self.lt_exist_ship.setItemWidget(item, widget)
        except Exception as e:
            log.error("图鉴出错2", e)

    def add_not_exist(self, ship_data):
        try:
            item = QListWidgetItem()
            item.setSizeHint(QSize(200, 50))
            widget = self.get_list_item(ship_data)
            self.lt_not_exist_ship.addItem(item)
            self.lt_not_exist_ship.setItemWidget(item, widget)
        except Exception as e:
            log.error("图鉴出错3", e)

    @staticmethod
    def get_list_item(data):
        try:
            # 读取属性
            ship_name = data['ship_name']
            ship_photo = data['ship_photo']
            ship_index = data['ship_index']
            ship_type = data['ship_type']
            ship_country = data['ship_country']
            ship_star = data['ship_star']
            # 创建页面
            wight = QWidget()
            # 头像显示
            ly_main = QHBoxLayout()
            map_l = QLabel()
            map_l.setFixedSize(40, 25)
            if os.path.exists(ship_photo):
                maps = QPixmap(ship_photo).scaled(40, 25)
                map_l.setPixmap(maps)
            else:
                map_l.setText("None")
            ly_main.addWidget(map_l)
            # 信息显示
            ly_right = QVBoxLayout()
            ly_right.addWidget(QLabel(ship_name))
            ly_right_down = QHBoxLayout()
            ly_right_down.addWidget(QLabel(ship_type))
            ly_right_down.addWidget(QLabel(ship_country))
            ly_right_down.addWidget(QLabel(str(ship_star) + "星"))
            ly_right_down.addWidget(QLabel(ship_index))
            ly_right.addLayout(ly_right_down)
            ly_main.addLayout(ly_right)
            wight.setLayout(ly_main)
            return wight
        except Exception as e:
            log.error("图鉴出错4", e)

    def show_detail(self, cid):
        try:
            hp = init_data.ship_cid_wu[cid]['hp']
            speed = init_data.ship_cid_wu[cid]['speed']
            luck = init_data.ship_cid_wu[cid]['luck']
            index = str(int(init_data.ship_cid_wu[cid]['shipIndex']))
            self.select_ship = index

            radar = init_data.ship_cid_wu[cid]['radar']
            radar_max = init_data.ship_cid_wu[cid]['radarMax']

            antisub = init_data.ship_cid_wu[cid]['antisub']
            antisub_max = init_data.ship_cid_wu[cid]['antisubMax']

            fire = init_data.ship_cid_wu[cid]['atk']
            fire_max = init_data.ship_cid_wu[cid]['atkMax']

            def_n = init_data.ship_cid_wu[cid]['def']
            def_max = init_data.ship_cid_wu[cid]['defMax']

            torpedo = init_data.ship_cid_wu[cid]['torpedo']
            torpedo_max = init_data.ship_cid_wu[cid]['torpedoMax']

            miss = init_data.ship_cid_wu[cid]['miss']
            miss_max = init_data.ship_cid_wu[cid]['missMax']

            air_def = init_data.ship_cid_wu[cid]['airDef']
            air_def_max = init_data.ship_cid_wu[cid]['airDefMax']

            self.tw_detail.setColumnCount(4)
            self.tw_detail.setRowCount(9)
            for i in range(4):
                self.tw_detail.setColumnWidth(i, 50)

            self.tw_detail.setEditTriggers(QAbstractItemView.NoEditTriggers)

            self.tw_detail.horizontalHeader().setVisible(False)
            self.tw_detail.verticalHeader().setVisible(False)

            self.tw_detail.setSpan(0, 0, 9, 2)

            gameFunction.get_icon(index)
            map_path = 'icon/big/{}.png'.format(str(index))
            if os.path.exists(map_path):
                maps = QLabel()
                pix_map = QPixmap(map_path).scaled(96, 240)
                maps.setPixmap(pix_map)
                self.tw_detail.setCellWidget(0, 0, maps)
            else:
                self.tw_detail.setItem(0, 0, QTableWidgetItem("无图像"))
            i = 0
            self.tw_detail.setItem(i, 2, QTableWidgetItem("耐久"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(hp)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("航速"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(speed) + "节"))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("幸运"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(luck)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("火力"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(fire) + "/" + str(fire_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("鱼雷"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(torpedo) + "/" + str(torpedo_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("装甲"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(def_n) + "/" + str(def_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("防空"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(air_def) + "/" + str(air_def_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("闪避"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(miss) + "/" + str(miss_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("索敌"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(radar) + "/" + str(radar_max)))
            i += 1
            self.tw_detail.setItem(i, 2, QTableWidgetItem("反潜"))
            self.tw_detail.setItem(i, 3, QTableWidgetItem(str(antisub) + "/" + str(antisub_max)))
        except Exception as e:
            log.error(e)

    def open_detail(self):
        if self.select_ship != -1:
            url = "http://js.ntwikis.com/jsp/apps/cancollezh/charactors/detail.jsp?detailid=" + str(self.select_ship)
            webbrowser.open_new_tab(url)


class WindowsPay(QMainWindow, Ui_Frame_pay):
    def __init__(self):
        super(WindowsPay, self).__init__()
        self.setupUi(self)

    def onShow(self):


        try:
            data = gameFunction.get_pay_icon()
            wx_pay = QPixmap()
            zfb_pay = QPixmap()
            hb_pay = QPixmap()
            wx_pay.loadFromData(data[0])
            zfb_pay.loadFromData(data[1])
            hb_pay.loadFromData(data[2])
            wx_pay.scaled(211, 281)
            zfb_pay.scaled(211, 281)
            hb_pay.scaled(211, 281)
            self.label.setPixmap(zfb_pay)
            self.label_2.setPixmap(wx_pay)
            self.label_4.setPixmap(hb_pay)
            self.show()
        except Exception as e:
            log.error(e)


class WindowsSelectShip(QDialog, Ui_Frame_select_ship):
    ship_signal = pyqtSignal(dict)
    def __init__(self):
        super(WindowsSelectShip, self).__init__()
        self.setupUi(self)
        self.can_select = -1
        self.select_ship = []
        self.ship = []
        self.ship_signal.connect(self.refresh_ship_def)
        self.lt_all_ship.doubleClicked.connect(self.add_select_ship)
        self.lt_select_ship.clicked.connect(self.del_ship)
        self.cb_type.currentIndexChanged.connect(self.refresh_ship)
        self.cb_level.clicked.connect(self.refresh_ship)
        self.cb_level_max.valueChanged.connect(self.refresh_ship)
        self.cb_level_min.valueChanged.connect(self.refresh_ship)
        self.ed_name.textChanged.connect(self.refresh_ship)
        self.refresh_ship()
        self.refresh_select_ship()

    def refresh_ship(self):
        """
        功能: 刷新显示船只数据
        :return:
        """
        try:
            self.lt_all_ship.clear()
            self.ship.clear()
            for ship, data in gameData.allShip.items():
                if self.cb_type.currentIndex() != 0 and int(data['type']) != self.cb_type.currentIndex():
                    continue
                if self.cb_level.isChecked() is True:
                    if int(data['level']) > max(self.cb_level_max.value(), self.cb_level_min.value()) or int(data['level']) < min(
                            self.cb_level_max.value(), self.cb_level_min.value()):
                        continue
                if self.ed_name.text() != "" and self.ed_name.text() not in data['title']:
                    continue
                self.ship.append(int(ship))
                ship_name = init_data.ship_cid_wu[data['shipCid']]['title'][: 4]
                ship_level = 'Lv.' + str(data['level'])
                ship_hp = str(data['battleProps']['hp']) + "/" + str(data['battlePropsMax']['hp'])
                ship_fleet = '队伍:' + str(data['fleet_id'])
                ship_photo = "icon/photo/" + str(
                    int(init_data.handbook_id[gameData.allShip[int(ship)]['shipCid']])) + ".png"
                self.ship_signal.emit(
                    {'ship_name': ship_name, 'ship_level': ship_level, 'ship_hp': ship_hp,
                     'ship_fleet': ship_fleet, 'ship_photo': ship_photo})
        except Exception as e:
            print("Add select Error", e)

    def refresh_select_ship(self):
        """
        功能:刷新选择船只数据
        :return:
        """
        self.lt_select_ship.clear()
        for ship in self.select_ship:
            name = init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['title']
            level = "Lv." + str(gameData.allShip[int(ship)]['level'])
            self.lt_select_ship.addItem(level + ' ' + name)

    def add_select_ship(self):
        """
        功能: 添加一个船只
        :return:
        """
        if len(self.lt_all_ship.selectedItems()) != 0:
            if (self.can_select != -1 and len(self.select_ship) < self.can_select) or self.can_select == -1:
                self.select_ship.append(self.ship[int(self.lt_all_ship.row(self.lt_all_ship.selectedItems()[0]))])
                self.select_ship = sorted(set(self.select_ship), key=self.select_ship.index)
        self.refresh_select_ship()

    def del_ship(self):
        if len(self.lt_select_ship.selectedItems()) != 0:
            del self.select_ship[int(self.lt_select_ship.row(self.lt_select_ship.selectedItems()[0]))]
        self.refresh_select_ship()

    def refresh_ship_def(self, data):
        # 读取属性
        ship_name = data['ship_name']
        ship_level = data['ship_level']
        ship_photo = data['ship_photo']
        ship_hp = data['ship_hp']
        ship_fleet = data['ship_fleet']
        # 创建页面
        wight = QWidget()
        # 头像显示
        ly_main = QHBoxLayout()
        map_l = QLabel()
        map_l.setFixedSize(40, 25)
        if os.path.exists(ship_photo):
            maps = QPixmap(ship_photo).scaled(40, 25)
            map_l.setPixmap(maps)
        else:
            map_l.setText("None")
        ly_main.addWidget(map_l)
        # 信息显示
        ly_right = QGridLayout()
        ly_right.setSpacing(2)
        ly_right.addWidget(QLabel(ship_name), 0, 0)
        ly_right.addWidget(QLabel("  HP"), 0, 1)
        ly_right.addWidget(QLabel(ship_level), 1, 0)
        ly_right.addWidget(QLabel(ship_hp), 1, 1)
        # 舰队显示
        ly_main.addWidget(QLabel(ship_fleet))
        # 添加显示
        ly_main.addLayout(ly_right)
        wight.setLayout(ly_main)
        item = QListWidgetItem()
        item.setSizeHint(QSize(42, 45))
        self.lt_all_ship.addItem(item)
        self.lt_all_ship.setItemWidget(item, wight)


class WindowsUserFleet(QMainWindow, Ui_UserFleet):
    """
    数据格式 dict
    md5{
        name:名称
        fleet:生效队伍-1
        ship:[]
    }
    """
    def __init__(self):
        super(WindowsUserFleet, self).__init__()
        self.setupUi(self)
        # 创建工作目录
        if not os.path.exists("config"):
            os.mkdir("config")
        # 读取数据
        self.user_fleet = {}
        self.list_index = []

        # 临时数据
        self.now_ship = []

        # 绑定事件
        self.bt_read.clicked.connect(self.read_fleet)
        self.bt_write.clicked.connect(self.write_fleet)
        self.bt_editFleet.clicked.connect(self.set_member)
        self.bt_del.clicked.connect(self.del_fleet)
        self.read_config()
        self.refresh_fleet_list()


    def closeEvent(self, event):
        windows_add_battle.initialize()
        event.accept()

    def i(self):
        self.read_config()
        self.refresh_fleet_list()
        self.show()

    def read_config(self):
        """
        读取数据
        """
        try:
            if os.path.exists("config/user_fleet.json"):
                with open("config/user_fleet.json", 'r') as f:
                    self.user_fleet = json.loads(f.read())
            else:
                self.user_fleet = {}
        except Exception as e:
            log.e(str(e))

    def write_config(self):
        """
        写入数据数据
        """
        with open("config/user_fleet.json", 'w') as f:
            f.write(json.dumps(self.user_fleet))

    def refresh_fleet_list(self):
        self.lt_fleetList.clear()
        self.list_index.clear()
        for md5, data in self.user_fleet.items():
            name = data["name"]
            fleet = int(data["fleet"]) + 1
            self.list_index.append(md5)
            print("%s  → 队伍%d" % (name, fleet))
            self.lt_fleetList.addItem("%s  → 队伍%d" % (name, fleet))

    def del_fleet(self):
        try:
            index = self.lt_fleetList.currentRow()
            md5 = self.list_index[index]
            del self.list_index[index]
            del self.user_fleet[md5]
            self.write_config()
            self.refresh_fleet_list()
        except Exception as e:
            log.e(str(e))

    def refresh_member_list(self, ships):
        # 刷新船只名单
        self.lt_fleetMember.clear()
        for ship in ships:
            d = "Lv.%d %s" % (
                int(gameData.allShip[ship]['level']), init_data.ship_cid_wu[gameData.allShip[ship]['shipCid']]['title'])
            self.lt_fleetMember.addItem(d)

    def read_fleet(self):
        # 读取队伍列表
        try:
            index = self.lt_fleetList.currentRow()
            md5 = self.list_index[index]
            data = self.user_fleet[md5]
            name = data["name"]
            fleet = int(data["fleet"])
            ships = data["ship"]

            # 储存临时数据
            self.now_ship = ships

            self.ed_name.setText(name)
            self.cb_fleet.setCurrentIndex(fleet)
            self.refresh_member_list(ships)
        except Exception as e:
            log.e(str(e))

    def write_fleet(self):
        # 写入队伍列表
        try:
            name = self.ed_name.text()
            if name == "":
                return
            fleet = self.cb_fleet.currentIndex()
            ships = self.now_ship
            md5 = gameFunction.get_md5(name)
            data = {
                "name": name,
                "fleet": fleet,
                "ship": list(ships)
            }
            self.user_fleet[md5] = data
            print(self.user_fleet)
            self.write_config()
            self.refresh_fleet_list()
        except Exception as e:
            log.e(str(e))

    def set_member(self):
        w = WindowsSelectShip()
        w.can_select = 6
        w.select_ship = self.now_ship
        w.refresh_select_ship()
        if w.exec_():
            self.now_ship = w.select_ship
            self.refresh_member_list(self.now_ship)


class RwFunction:
    """
    任务设置,保存,读取
    """
    def __init__(self):
        # 配置文件
        self.map = ''
        self.name = ''
        self.point = ''
        self.format = 0
        self.spyFail = False
        self.skip = False
        self.skipDeal = 0
        self.hmChange = False
        self.qmChange = False
        self.qtChange = False
        self.reward = False
        self.nightFight = False
        self.resource = False
        # 传送数据
        self.rw_list = []
        # 临时保存
        self.config = dict()
        self.config['allDetail'] = dict()
        self.detail_flag = None
        self.each_detail = {}
        self.all_detail = {}

    def save_detail(self):
        """
        功能:保存单独点配置
        :return: None
        """
        if windows_rw_detail.cb_openDetail.isChecked():
            detail = dict()
            detail['foe1Switch'] = windows_rw_detail.cb_foe1Switch.isChecked()
            detail['foe2Switch'] = windows_rw_detail.cb_foe2Switch.isChecked()

            detail['foe1Format'] = windows_rw_detail.cb_foe1Format.currentIndex()
            detail['foe2Format'] = windows_rw_detail.cb_foe2Format.currentIndex()

            detail['foe1Compare'] = windows_rw_detail.cb_foe1Compare.currentIndex()
            detail['foe2Compare'] = windows_rw_detail.cb_foe2Compare.currentIndex()

            detail['foe1Num'] = windows_rw_detail.ed_foe1Num.text()
            detail['foe2Num'] = windows_rw_detail.ed_foe2Num.text()

            detail['foe1Deal'] = windows_rw_detail.cb_foe1Deal.currentIndex()
            detail['foe2Deal'] = windows_rw_detail.cb_foe2Deal.currentIndex()

            detail['spy'] = windows_rw_detail.cb_spy.isChecked()
            detail['spyDeal'] = windows_rw_detail.cb_spyDeal.currentIndex()

            detail['nightFight'] = windows_rw_detail.cb_nightFight.isChecked()

            detail['isFormat'] = windows_rw_detail.cb_format.isChecked()
            detail['format'] = windows_rw_detail.cb_formatS.currentIndex()

            self.each_detail[self.detail_flag] = detail

            self.config['allDetail'] = self.each_detail
        else:
            if self.detail_flag in self.config['allDetail']:
                del self.config['allDetail'][self.detail_flag]
        windows_rw_detail.close()

    def show_detail(self):
        """
        功能:显示详细设置
        :return: None
        """
        self.detail_flag = windows_rw.sender().text()

        if self.detail_flag in self.config['allDetail']:
            windows_rw_detail.cb_openDetail.setChecked(True)
            windows_rw_detail.cb_foe1Switch.setChecked(self.config['allDetail'][str(self.detail_flag)]['foe1Switch'])
            windows_rw_detail.cb_foe2Switch.setChecked(self.config['allDetail'][str(self.detail_flag)]['foe2Switch'])

            windows_rw_detail.cb_foe1Format.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe1Format']))
            windows_rw_detail.cb_foe2Format.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe2Format']))

            windows_rw_detail.cb_foe1Compare.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe1Compare']))
            windows_rw_detail.cb_foe2Compare.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe2Compare']))

            windows_rw_detail.ed_foe1Num.setText(str(self.config['allDetail'][str(self.detail_flag)]['foe1Num']))
            windows_rw_detail.ed_foe2Num.setText(str(self.config['allDetail'][str(self.detail_flag)]['foe2Num']))

            windows_rw_detail.cb_foe1Deal.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe1Deal']))
            windows_rw_detail.cb_foe2Deal.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['foe2Deal']))

            windows_rw_detail.cb_spy.setChecked(self.config['allDetail'][str(self.detail_flag)]['spy'])
            windows_rw_detail.cb_spyDeal.setCurrentIndex(
                int(self.config['allDetail'][str(self.detail_flag)]['spyDeal']))
            windows_rw_detail.cb_nightFight.setChecked(self.config['allDetail'][str(self.detail_flag)]['nightFight'])

            if "isFormat" in self.config['allDetail'][str(self.detail_flag)]:
                windows_rw_detail.cb_format.setChecked(self.config['allDetail'][str(self.detail_flag)]['isFormat'])
            if "format" in self.config['allDetail'][str(self.detail_flag)]:
                windows_rw_detail.cb_formatS.setCurrentIndex(self.config['allDetail'][str(self.detail_flag)]['format'])
        else:
            windows_rw_detail.cb_foe1Switch.setChecked(False)
            windows_rw_detail.cb_foe2Switch.setChecked(False)

            windows_rw_detail.cb_foe1Format.setCurrentIndex(0)
            windows_rw_detail.cb_foe2Format.setCurrentIndex(0)

            windows_rw_detail.cb_foe1Compare.setCurrentIndex(0)
            windows_rw_detail.cb_foe2Compare.setCurrentIndex(0)

            windows_rw_detail.ed_foe1Num.setText('1')
            windows_rw_detail.ed_foe2Num.setText('1')

            windows_rw_detail.cb_foe1Deal.setCurrentIndex(0)
            windows_rw_detail.cb_foe2Deal.setCurrentIndex(0)

            windows_rw_detail.cb_spy.setChecked(False)
            windows_rw_detail.cb_spyDeal.setCurrentIndex(0)
            windows_rw_detail.cb_nightFight.setChecked(False)
            windows_rw_detail.cb_openDetail.setChecked(False)

            windows_rw_detail.cb_format.setChecked(False)
            windows_rw_detail.cb_formatS.setCurrentIndex(0)

            windows_rw_detail.cb_format.setChecked(False)
            windows_rw_detail.cb_formatS.setCurrentIndex(0)

        if self.detail_flag in [chr(i) for i in range(65, 91)]:
            windows_rw_detail.tv_flag.setText(str(self.detail_flag))
            windows_rw_detail.show()

    def read_config(self):
        """
        功能:读取配置信息
        :return: None
        """
        map_index = ['101', '102', '103', '104',
                     '201', '202', '203', '204', '205', '206',
                     '301', '302', '303', '304',
                     '401', '402', '403', '404',
                     '501', '502', '503', '504', '505',
                     '601', '602', '603', '604',
                     '701', '702', '703', '704', '705',
                     '801',
                     "9913", "9914", "9915", "9916", "9917", "9918", "9919", "9920", "9921", "9922"]
        with open('path\\' + windows_rw.list_Rw.currentItem().text(), 'r') as file:
            self.config = file.read()
        self.config = json.loads(self.config)

        self.map = self.config['map']
        self.name = self.config['name']
        self.point = self.config['point']
        self.format = self.config['format']
        self.spyFail = self.config['spyFail']
        self.skip = self.config['skip']
        self.skipDeal = self.config['skipDeal']
        self.hmChange = self.config['hmChange']
        self.qmChange = self.config['qmChange']
        self.qtChange = self.config['qtChange']
        self.reward = self.config['reward']
        self.nightFight = self.config['nightFight']
        self.resource = self.config['resource']
        windows_rw.cb_map.setCurrentIndex(int(map_index.index(str(self.map))))

        windows_rw.cb_format.setCurrentIndex(int(self.format))
        windows_rw.cb_spyFail.setCurrentIndex(int(self.spyFail))
        windows_rw.cb_skipDeal.setCurrentIndex(int(self.skipDeal))

        windows_rw.cb_resource.setChecked(self.resource)
        windows_rw.cb_skip.setChecked(self.skip)
        windows_rw.cb_nightFight.setChecked(self.nightFight)
        windows_rw.cb_hmChange.setChecked(self.hmChange)
        windows_rw.cb_qmChange.setChecked(self.qmChange)
        windows_rw.cb_qtChange.setChecked(self.qtChange)
        windows_rw.cb_reward.setChecked(self.reward)
        windows_rw.ed_name.setText(str(self.name))
        windows_rw.ed_point.setText(str(self.point))

    def write_config(self):
        """
        功能:写入配置信息
        :return:None
        """
        try:
            map_name = ['101', '102', '103', '104',
                        '201', '202', '203', '204', '205', '206',
                        '301', '302', '303', '304',
                        '401', '402', '403', '404',
                        '501', '502', '503', '504', '505',
                        '601', '602', '603', '604',
                        '701', '702', '703', '704', '705', '801',
                        "9913", "9914", "9915", "9916", "9917", "9918", "9919", "9920", "9921", "9922"]
            self.config['map'] = map_name[windows_rw.cb_map.currentIndex()]
            self.config['name'] = windows_rw.ed_name.text()
            self.config['point'] = windows_rw.ed_point.text()
            self.config['format'] = windows_rw.cb_format.currentIndex()
            self.config['spyFail'] = windows_rw.cb_spyFail.currentIndex()
            self.config['skip'] = windows_rw.cb_skip.isChecked()
            self.config['skipDeal'] = windows_rw.cb_skipDeal.currentIndex()
            self.config['hmChange'] = windows_rw.cb_hmChange.isChecked()
            self.config['qmChange'] = windows_rw.cb_qmChange.isChecked()
            self.config['qtChange'] = windows_rw.cb_qtChange.isChecked()
            self.config['reward'] = windows_rw.cb_reward.isChecked()
            self.config['nightFight'] = windows_rw.cb_nightFight.isChecked()
            self.config['resource'] = windows_rw.cb_resource.isChecked()

            del_point = []
            for flag, detail in self.config['allDetail'].items():
                # 剔除不在点的
                if flag not in list(self.config['point']):
                    del_point.append(flag)
            log.debug(del_point)
            if len(del_point) != 0:
                for eachFlag in del_point:
                    del self.config['allDetail'][eachFlag]

            if not os.path.exists('path'):
                os.mkdir('path')
            with open('path\\' + str(self.config['name']) + ".json", 'w') as files:
                files.write(json.dumps(self.config))
            self.refresh_rw()
            self.show_rw()
        except Exception as e:
            log.error('Save ERROR:', str(e))
            raise

    def del_config(self):
        """
        功能:删除配置
        :return:
        """
        if windows_rw.list_Rw.currentItem() != "":
            if os.path.exists('path\\' + windows_rw.list_Rw.currentItem().text()):
                os.remove('path\\' + windows_rw.list_Rw.currentItem().text())
            self.refresh_rw()

    @staticmethod
    def point_change():
        """
            功能:点改变时刷新下面数据
            无返回值
        """
        point_dict = list(windows_rw.ed_point.text().upper())
        point_dict2 = sorted(set(point_dict), key=point_dict.index)
        point_text = "".join(point_dict2)
        if windows_rw.ed_point.text() != point_text:
            windows_rw.ed_point.setText(point_text)

        for num in range(1, 14):
            if num <= len(point_dict2):
                if num == 1:
                    windows_rw.bt_detail_1.setText(point_dict[num - 1])
                elif num == 2:
                    windows_rw.bt_detail_2.setText(point_dict[num - 1])
                elif num == 3:
                    windows_rw.bt_detail_3.setText(point_dict[num - 1])
                elif num == 4:
                    windows_rw.bt_detail_4.setText(point_dict[num - 1])
                elif num == 5:
                    windows_rw.bt_detail_5.setText(point_dict[num - 1])
                elif num == 6:
                    windows_rw.bt_detail_6.setText(point_dict[num - 1])
                elif num == 7:
                    windows_rw.bt_detail_7.setText(point_dict[num - 1])
                elif num == 8:
                    windows_rw.bt_detail_8.setText(point_dict[num - 1])
                elif num == 9:
                    windows_rw.bt_detail_9.setText(point_dict[num - 1])
                elif num == 10:
                    windows_rw.bt_detail_10.setText(point_dict[num - 1])
                elif num == 11:
                    windows_rw.bt_detail_11.setText(point_dict[num - 1])
                elif num == 12:
                    windows_rw.bt_detail_12.setText(point_dict[num - 1])
                elif num == 13:
                    windows_rw.bt_detail_13.setText(point_dict[num - 1])
            else:
                if num == 1:
                    windows_rw.bt_detail_1.setText('')
                elif num == 2:
                    windows_rw.bt_detail_2.setText('')
                elif num == 3:
                    windows_rw.bt_detail_3.setText('')
                elif num == 4:
                    windows_rw.bt_detail_4.setText('')
                elif num == 5:
                    windows_rw.bt_detail_5.setText('')
                elif num == 6:
                    windows_rw.bt_detail_6.setText('')
                elif num == 7:
                    windows_rw.bt_detail_7.setText('')
                elif num == 8:
                    windows_rw.bt_detail_8.setText('')
                elif num == 9:
                    windows_rw.bt_detail_9.setText('')
                elif num == 10:
                    windows_rw.bt_detail_10.setText('')
                elif num == 11:
                    windows_rw.bt_detail_11.setText('')
                elif num == 12:
                    windows_rw.bt_detail_12.setText('')
                elif num == 13:
                    windows_rw.bt_detail_13.setText('')

    @staticmethod
    def map_change():
        """
        功能:更换地图
        无返回值
        :return:
        """
        windows_rw.ed_name.setText('自定义')
        map_name = ['101.png', '102.png', '103.png', '104.png',
                    '201.png', '202.png', '203.png', '204.png', '205.png', '206.png',
                    '301.png', '302.png', '303.png', '304.png',
                    '401.png', '402.png', '403.png', '404.png',
                    '501.png', '502.png', '503.png', '504.png', '505.png',
                    '601.png', '602.png', '603.png', '604.png',
                    '701.png', '702.png', '703.png', '704.png', '705.png', '801.png',
                    "9913.png", "9914.png", "9915.png", "9916.png", "9917.png", "9918.png", "9919.png", "9920.png", "9921.png", "9922.png"]
        if windows_rw.cb_map.currentIndex() < len(map_name) and os.path.exists("icon/map/" + map_name[windows_rw.cb_map.currentIndex()]):
            png = QPixmap("icon/map/" + map_name[windows_rw.cb_map.currentIndex()])
            windows_rw.tv_map.setPixmap(png)
        else:
            windows_rw.tv_map.setText("无图像")

    @staticmethod
    def refresh_rw():
        """
        功能:刷新任务界面
        无返回值
        """
        if not os.path.exists('path'):
            os.mkdir('path')
        windows_rw.list_Rw.clear()
        for root, dirs, file in os.walk('path', topdown=False):
            for name in file:
                windows_rw.list_Rw.addItem(name)

    def show_rw(self):
        """
        功能:初始化任务界面
        无返回值
        """
        self.refresh_rw()
        windows_rw.show()

    def refresh_start_battle_rw_list(self):
        windows_add_battle.cb_rw.clear()
        if not os.path.exists('path'):
            os.mkdir('path')
        windows_rw.list_Rw.clear()
        rw_list = []
        for root, dirs, file in os.walk('path', topdown=False):
            for name in file:
                windows_add_battle.cb_rw.addItem(name)
                rw_list.append(name)
        self.rw_list = rw_list


class BattleMain:
    """
    出征各种处理,远征检测等
    """
    def __init__(self):
        self.config_name = ''
        self.fleet = 0
        self.skip_num = 0

        self.config = dict()
        self.point = ""
        self.pointNode = 0
        self.pointNextNode = 0
        self.map = ''
        self.format = 0
        self.spyFail = False
        self.skip = False
        self.skipDeal = 0
        self.hmChange = False
        self.qmChange = False
        self.qtChange = False
        self.reward = False
        self.nightFight = False
        self.resource = False
        self.detail_flag = None
        self.rwList = {}
        self.nowPoint = '0'
        self.name = ""
        # 常量信息
        self.END_500_SHIP = 0
        self.END_SL = 1
        self.END_FINISH = 3
        self.END_SPECIAL_SHIP = 4
        self.END_ERROR = 5

        # 保存信息
        self.repair_format = 0
        self.is_dismantle = False
        self.run_num = 0
        self.run_max_num = 0

    def login_config(self):
        self.rwList = rw_function.rw_list
        if os.path.exists('path\\' + self.config_name):
            with open('path\\' + self.config_name, 'r') as file:
                config = file.read()
                self.config = json.loads(config)
                self.map = self.config['map']
                self.name = self.config['name']
                self.point = list(self.config['point'])
                self.format = self.config['format']
                self.spyFail = self.config['spyFail']
                self.skip = self.config['skip']
                self.skipDeal = self.config['skipDeal']
                self.hmChange = self.config['hmChange']
                self.qmChange = self.config['qmChange']
                self.qtChange = self.config['qtChange']
                self.reward = self.config['reward']
                self.nightFight = self.config['nightFight']
                self.resource = self.config['resource']
                return True
        else:
            return False

    def main(self, config_name, fleet, repair, other_data):
        # 检测传过来的队伍
        if len(fleet) == 1:
            self.fleet = int(fleet)
        else:
            if fleet in windows_user_fleet.user_fleet:
                data = windows_user_fleet.user_fleet[fleet]
                f = int(data["fleet"])
                self.fleet = int(f)
                result, msg = other_function.change_fleet(fleet=f, ships=data['ship'])
                if result is False:
                    return result, msg
            else:
                return False, '队伍不存在'
        self.config_name = config_name
        head = 'pve'
        if self.login_config() is False:
            return False, '读取配置失败'
        try:

            # ---活动定义文件----
            # if int(self.map) >= 1000:
            #     ocean_data = gameData.get_ocean_data(node=self.map)
            #     time.sleep(3)
            #     gameData.get_ocean_level()
            #     for node in ocean_data['nodeList']:
            #         gameData.allPoint[int(node["id"])] = node
            # # ----港口页面----
            time.sleep(5)
            log.info('-=-=-=-=-=-=START=-=-=-=-=-=-')
            gameData.get_rank_list()
            windows_main.lt_our_2.clear()
            log.info("====Now at port====")
            other_function.refresh_base_data()
            other_function.refresh_our_ship_data(fleet=gameData.fleet[self.fleet], name=gameData.fleetName[self.fleet])
            # 任务条更新
            log.info('Upgrade progressBar...')
            count.refresh_table()
            # 检测建造
            while other_function.check_build_ship():
                pass
            # 检测上榜
            rank_data = other_function.check_rank(gameData.fleet[self.fleet])
            if windows_main.cb_rank.isChecked() is True:
                if len(rank_data) != 0:
                    ship = [str(gameData.allShip[int(x)]['title']) for x in rank_data]
                    set_log("本队船只上榜" + " ".join(ship) + ' 停止任务', 3)
                    log.cri('CRITICAL!! RANK WARNING!!!')
                    return False, '上榜监测未通过'
            # 检测任务
            log.info('Checking task...')
            set_log('检测任务...', 1)
            # 进行强化
            if gameData.shipNumTop <= len(gameData.allShip):
                self.check_strengthen()
            # 检查是否满仓
            log.info("Checking warehouse...")
            set_log('检测是否满仓...', 1)
            dis_result = True
            if gameData.shipNumTop <= len(gameData.allShip):
                if windows_main.cb_dismantle.isChecked() is True:
                    log.info('Ready to dismantle')
                    set_log('准备分解...', 1)
                    dis_result = self.dismantle()
                else:
                    return False, '未打开分解开关'
            if dis_result is False:
                return False, '分解失败'

            # 任务和远征检测
            log.info('Checking task...')
            set_log('检测远征...', 1)
            self.check_task()
            self.check_explore()
            self.check_task()
            # ----选图页面----

            # ----战前准备页面----

            # ----补给检测-----
            other_function.check_support(gameData.fleet[self.fleet])
            # ----修理检测-----
            other_function.repair_complete()
            repair_result, left_time = self.check_repair(repair)
            if repair_result == -1:  # 被冻结
                return -1, left_time
            elif repair_result is False:
                return False, left_time
            # ----修理复检----------
            fleet_hp = []
            fleet_max_hp = []
            for ship in gameData.fleet[self.fleet]:
                fleet_hp.append(gameData.allShip[int(ship)]['battleProps']['hp'])
                fleet_max_hp.append(gameData.allShip[int(ship)]['battlePropsMax']['hp'])
            fleet_four_hp = [int(hp * 4) for hp in fleet_hp]
            for i in range(0, len(fleet_hp)):
                if int(fleet_max_hp[i]) > int(fleet_four_hp[i]):
                    log.info('Some ship was terribly broken...Back to the port')
                    set_log('有船大破，准备回港...', 1)
                    return False, "有大破船只,无法出征"
            # ----检测是否有泡澡----
            for dock in gameData.repairDock:
                if "shipId" in dock and int(dock["shipId"]) in gameData.fleet[self.fleet]:
                    print(other_function.get_min_repair_time())
                    return -1, other_function.get_min_repair_time()
            # ----开始出征----
            time.sleep(2)
            set_log('开始出征...', 1)
            other_function.refresh_our_ship_data(fleet=gameData.fleet[self.fleet], name=gameData.fleetName[self.fleet])

            if int(self.map) >= 1000:
                gameData.set_ocean_fleet(fleet=self.fleet + 1, node=self.map)
                time.sleep(1)

            battle_result = self.one_battle(head=head, other_data=other_data)
            count.refresh_table()
            if battle_result is self.END_FINISH:  # 完成一次出征,返回true,并进行+1
                log.info("Eed battle")
                set_log('完成出征...', 1)
                return True, ''
            elif battle_result == self.END_SL:  # 本次出征未完成,返回0,不计算
                return self.END_SL, ''
            elif battle_result == self.END_500_SHIP:  # 满500船
                return False, "满500船,停止任务"
            elif battle_result == self.END_SPECIAL_SHIP:  # 出特定船只
                return False, "出特定船只,停止任务"
            elif battle_result is self.END_ERROR:  # 本任务无法继续进行,返回false并删除任务
                return False, '其他问题导致任务无法继续进行'
        except HmError as e:
            log.error('Battle ERROR:', e.message)
            raise
        except Exception as e:
            log.error('Battle ERROR:', str(e))
            raise
        set_log('任务结束...', 1)

    def one_battle(self, head, other_data):
        log.info('Start battle')
        is_last_point = False
        gameFunction.challenge_start(maps=self.map, team=int(self.fleet) + 1, head=head)  # battle加1
        time.sleep(4)
        log.info('Start while')
        try:
            while True:  # 出征总循环
                now_format = self.format
                log.info("---Start battle while---")
                # ----选路页面----
                log.info("====Now at path====")
                path_data = gameFunction.challenge_new_next(head=head)  # 进行下一点
                count.add_items(count.PATH_COUNT, 1)
                log.info("New next data", path_data)
                error_find(path_data)
                # 读取当前页面代号
                node = path_data['node']
                now_flag = gameData.allPoint[int(node)]['flag']
                count_point = self.map + "-" + now_flag
                # 判断当前点是否为最后一点
                if len(gameData.allPoint[int(node)]['nextNode']) == 0:
                    is_last_point = True
                else:
                    last = True
                    if node in gameData.allPoint:
                        for point in gameData.allPoint[int(node)]['nextNode']:
                            if gameData.allPoint[int(point)]['flag'] in self.point:
                                last = False
                        if is_last_point is False and last is True:
                            is_last_point = True
                log.info("Check point..." + now_flag)
                if now_flag not in self.point:  # 不在点里面准备SL
                    set_log("进点 " + now_flag + "→ SL", 1)
                    log.info('Point', now_flag, "→ SL")
                    is_sl = True  # 设置SL
                else:
                    set_log("进点 " + now_flag + "→ 继续", 1)
                    log.info('Point', now_flag, "→ Continue")
                    is_sl = False  # 设置不SL
                if is_sl is True:  # 需要SL
                    other_function.re_login()
                    log.info('Wrong Path,ready to SL')
                    count.add_items(count.SL_COUNT, 1)
                    return self.END_SL
                node_type = int(gameData.allPoint[int(node)]['nodeType'])
                roundabout = int(gameData.allPoint[int(node)]['roundabout'])
                log.info('Now point', now_flag, node_type)
                # 1:普通点, 2:BOSS点, 3:资源点 4:待机点, 5:收费站
                if node_type == 1 or node_type == 2:
                    # 普通点需要索敌
                    time.sleep(3)
                    # ----开始索敌----
                    log.info("====Now at spy====")
                    is_skip = False
                    now_format = self.format + 1  # 重置阵形
                    spy_data = gameFunction.challenge_spy(head=head)
                    other_function.refresh_foe_ship_data(spy_data['enemyVO']['enemyShips'])
                    if spy_data['enemyVO']['isFound'] == 0:  # 索敌失败
                        log.info("Spy failed...")
                        set_log('进行索敌...失败', 1)
                        if now_flag in self.config['allDetail']:  # 如果这个点有详细配置
                            log.info(now_flag, 'Read Detail')
                            log.debug(self.config['allDetail'][now_flag])
                            is_spy = self.config['allDetail'][now_flag]['spy']
                            spy_deal = self.config['allDetail'][now_flag]['spyDeal']
                            if is_spy is True:  # 这个点的确是失败SL
                                if spy_deal == 0:  # 为SL
                                    is_sl = True
                                else:
                                    now_format = spy_deal

                            else:  # 这个点为全局配置
                                if self.spyFail != 0:
                                    if self.spyFail == 1:  # 为SL
                                        is_sl = True
                                    else:
                                        now_format = spy_deal
                        else:
                            if self.config['spyFail'] == 1:  # SL
                                is_sl = True
                            else:
                                now_format = self.config['spyFail'] + 1

                        if is_sl is True:  # 索敌失败只能重启SL
                            log.info("Spy fail or path error ready to reLogin")
                            other_function.re_login()
                            count.add_items(count.SL_COUNT, 1)
                            return self.END_SL
                    else:  # 索敌成功
                        log.info("Spy success...")
                        set_log('进行索敌...成功', 1)
                        if self.skip is True and roundabout == 1:  # 可以进行迂回
                            is_skip = True
                    # ----敌人页面----
                    log.info("====Now at enemy====")
                    foe_num = {'CV': 0, 'CVL': 0, 'BB': 0, 'BC': 0, 'CA': 0, 'CLT': 0, 'CL': 0, "DD": 0, 'SS': 0, 'AD': 0}
                    foe_type_relationship = {1: 'CV', 2: 'CVL', 4: 'BB', 6: "BC", 7: "CA",
                                             9: "CLT", 10: "CL", 12: "DD", 14: "SS", 16: "AD"}
                    foe_ui = ['DD', 'CL', "CA", 'BB', 'BC', 'CV', 'CVL', 'SS', 'AD', 'CLT']
                    # 1:CV, 2:CVL, 4:BB, 6:BC, 7:CA, 9:CLT, 10:CL, 12:DD, 14:SS, 16:AD

                    for foe_ship in spy_data['enemyVO']['enemyShips']:  # 进行敌舰数量分析
                        if foe_ship['type'] in foe_type_relationship:
                            if foe_type_relationship[foe_ship['type']] not in foe_num:
                                foe_num[foe_type_relationship[foe_ship['type']]] = 0
                            foe_num[foe_type_relationship[foe_ship['type']]] += 1
                    print(foe_num)
                    # 敌舰数量判断
                    log.info('Recognition enemy number')
                    if self.config['hmChange'] is True and 'CV' in foe_num and foe_num["CV"] != 0:  # 有航母换轮型
                        now_format = 3
                    if self.config['qmChange'] is True and 'CVL' in foe_num and foe_num["CVL"] != 0:  # 有轻母换轮型
                        now_format = 3
                    if self.config['qtChange'] is True and 'SS' in foe_num and foe_num["SS"] != 0:  # 有潜艇换单横
                        now_format = 5
                    if is_skip is True and self.config['reward'] is True and 'AD' in foe_num and foe_num["AD"] != 0:
                        log.info("Find AD...Stop skip and fight")
                        is_skip = False
                    #  检测补给并迂回
                    if is_skip is True:
                        log.info('Try to skip the war...')
                        data = gameFunction.challenge_skip_war(head=head)
                        log.info('Skip success!')
                        if data["isSuccess"] != 0:  # 迂回成功
                            set_log("进行迂回...", 1)
                            continue  # 退出本次循环，进行下一点
                        else:
                            self.skip_num += 1
                            set_log("迂回失败", 1)
                            if self.skip_num != 0 and self.skip_num >= self.config["skipDeal"]:
                                set_log("迂回失败次数到达, 进行SL", 1)
                                return self.END_SL
                    log.info('Recognition enemy config')
                    if now_flag in self.config['allDetail']:  # 这个点有特殊配置
                        detail = self.config['allDetail'][now_flag]
                        log.info(detail)
                        foe_1_switch = detail['foe1Switch']
                        foe_1_compare = detail['foe1Compare']
                        foe_1_now_ship = int(foe_num[foe_ui[detail['foe1Format']]])
                        foe_1_set_ship = int(detail['foe1Num'])
                        foe_1_deal = detail['foe1Deal']

                        foe_2_switch = detail['foe2Switch']
                        foe_2_compare = detail['foe2Compare']
                        foe_2_now_ship = int(foe_num[foe_ui[detail['foe2Format']]])
                        foe_2_set_ship = int(detail['foe2Num'])
                        foe_2_deal = detail['foe2Deal']
                        if 'isFormat' in detail and detail['isFormat']:
                            now_format = int(detail['format']) + 1
                        if foe_1_switch is True:  # 敌舰检测1启动
                            if foe_1_compare == 0:  # 敌舰检测1比较方式为大于等于
                                if foe_1_now_ship >= foe_1_set_ship:  # 检测结果的确大于
                                    if foe_1_deal == 0:  # SL
                                        is_sl = True
                                    else:  # 换阵形
                                        now_format = foe_1_deal
                            else:  # 敌舰检测1比较方式为小于
                                if foe_1_now_ship < foe_1_set_ship:  # 检测结果的确大于
                                    if foe_1_deal == 0:  # SL
                                        is_sl = True
                                    else:  # 换轮型
                                        now_format = foe_1_deal

                        if foe_2_switch is True:  # 敌舰检测2启动
                            if foe_2_compare == 0:  # 敌舰检测2比较方式为大于等于
                                if foe_2_now_ship >= foe_2_set_ship:  # 检测结果的确大于
                                    if foe_2_deal == 0:  # SL
                                        is_sl = True
                                    else:  # 换阵形
                                        now_format = foe_2_deal
                            else:  # 敌舰检测1比较方式为小于
                                if foe_2_now_ship < foe_2_set_ship:  # 检测结果的确大于
                                    if foe_2_deal == 0:  # SL
                                        is_sl = True
                                    else:  # 换阵形
                                        now_format = foe_2_deal
                    if is_sl is True:  # 如果需要SL的话，直接退出
                        set_log('需要SL,返回港口...', 1)
                        log.info("Need SL...Back to port")
                        gameData.get_refresh_data()
                        count.add_items(count.SL_COUNT, 1)
                        return self.END_SL
                # ----开始战斗----
                time.sleep(5)
                log.info("====Now at fight====")
                log.info("Start fight", node, now_flag)
                fight_data = gameFunction.challenge_fight(maps=node, team=self.fleet + 1, formats=now_format,
                                                          head=head)
                if node_type == 1 or node_type == 2:  # 正常出征，需要延迟
                    count.add_items(count.FIGHT_COUNT, 1)
                    random_time = other_function.ai_delay(fight_data['warReport'])
                    set_log("战斗延迟..." + str(random_time) + '秒', 1)
                    log.info('Battle wait...' + str(random_time) + "s")
                    time.sleep(random_time)
                elif node_type == 3 or node_type == 5:  # 资源点
                    reward_type = [0, 0, "获得:", "损失:"]
                    reward_final = ["", "", 0]
                    if self.resource is True:  # 如果有资源点SL则进行SL
                        is_sl = True
                    if node_type == 3:  # 资源点
                        for gain_type, gain_num in gameData.allPoint[int(node)]['gain'].items():
                            reward_final[0] = reward_type[2]  # 获取奖励类型
                            count.add_other(str(gain_type), gain_num)  # 记录获取资源数目
                            reward_final[1] = RES[int(gain_type)]
                            reward_final[2] = int(gain_num)  # 获取奖励数量
                    elif node_type == 5:  # 收费站
                        for gain_type, gain_num in gameData.allPoint[int(node)]['loss'].items():
                            reward_final[0] = reward_type[2]
                            reward_final[1] = RES[int(gain_type)]
                            reward_final[2] = int(gain_num)
                    log.info('Finish gain or lost', reward_final[1], reward_final[2])
                    set_log('资源点,' + str(reward_final[0]) + str(reward_final[1]) + str(reward_final[2]), 0)
                    if is_sl is True:  # 资源点进行重启SL，否则进入下一个点
                        gameData.get_refresh_data()
                        count.add_items(count.SL_COUNT, 1)
                        return self.END_FINISH
                    else:
                        if is_last_point:
                            return self.END_FINISH
                        else:
                            continue
                elif node_type == 4:
                    log.info(now_flag, "Nothing...next node")
                    continue
                # ----夜战页面----
                log.info("====Now at night====")
                log.info('Analysis before night fight HP')
                is_night_fight = self.nightFight

                if now_flag in self.config['allDetail']:
                    is_night_fight = self.config['allDetail'][now_flag]['nightFight']
                if fight_data['warReport']['canDoNightWar'] == 1 and is_night_fight is True:
                    result_data = gameFunction.challenge_get_result(is_night_fight=1, head=head)
                    random_time = other_function.ai_delay_night(result_data['extraProgress'])
                    set_log("准备夜战..." + str(random_time) + '秒', 1)
                    log.info('Battle wait...' + str(random_time) + "s")
                    time.sleep(random_time)
                else:
                    set_log('准备结算...', 1)
                    result_data = gameFunction.challenge_get_result(is_night_fight=0, head=head)
                # ----结算页面----
                windows_main.lt_our_2.clear()
                count.add_items(count.FINISH_COUNT, 1)
                log.info("====Now at result====")
                # 更新人物信息
                log.info('Upgrade self information')
                for each_war_ship in result_data['shipVO']:
                    gameData.upgrade_ship(ids=each_war_ship['id'], jsons=each_war_ship)
                # 更新任务信息
                if 'updateTaskVo' in result_data:
                    log.info('Upgrade task information')
                    for eachTask in result_data['updateTaskVo']:
                        gameData.taskInfo[eachTask['taskCid']]['condition'] = eachTask['condition']
                # 更新详细信息
                if "detailInfo" in result_data:
                    gameData.userDetail = result_data["detailInfo"]
                # 更新评价信息
                log.info('Upgrade MVP information')
                assess = ['-', 'SS', 'S', 'A', 'B', 'C', 'D']
                # 更新MVP信息
                num = 0
                mvp_name = ''
                for eachShip in result_data['warResult']['selfShipResults']:
                    if eachShip['isMvp'] == 1:
                        mvp_name = gameData.allShip[gameData.fleet[self.fleet][num]]['title']
                    num += 1
                # ----出船页面----
                log.info("====Now at new ship====")
                log.info('Analysis new ship information')
                new_ship = "-"
                if 'dropSpoils' in result_data and result_data['dropSpoils'] == 1:
                    count.add_items(count.SPOILS, 1)
                    set_log("获得战利品 * 1", 0)
                has_new_ship = False
                count_access = "-"
                if 'newShipVO' in result_data:
                    has_new_ship = True
                    count_access = assess[result_data['warResult']['resultLevel']]
                    windows_count_ship.add_ship(cid=result_data['newShipVO'][0]['shipCid'],
                                                access=count_access, path=count_point)  # 进行出货统计
                    new_ship = init_data.ship_cid_wu[int(result_data['newShipVO'][0]['shipCid'])]['title']
                    new_ship_row_name = result_data['newShipVO'][0]['shipCid']
                    ship_id = result_data['newShipVO'][0]['id']
                    # 改名
                    if windows_main.cb_changeName.isChecked() and ship_id != new_ship_row_name:
                        try:
                            gameFunction.rename(ids=ship_id, name=new_ship)
                            set_log("改名%s → %s" % (new_ship_row_name, new_ship), 1)
                        except:
                            pass
                    gameData.add_ship(id=ship_id, data=result_data['newShipVO'][0])
                    count.add_items(count.SHIP_COUNT, 1)
                    if gameData.main_data['systime'] > th_main.set_time_unix:
                        raise HmError(code=-99999, message="已经过期...")
                    if result_data['newShipVO'][0]['shipCid'] not in gameData.unlockShip:  # 如果出了新船
                        log.info('New ship! name:' + result_data['newShipVO'][0]['title'], 'Lock her')
                        set_log('出新船:' + new_ship + " 锁船...", 3)
                        time.sleep(3)
                        gameFunction.lock_ship(result_data['newShipVO'][0]['id'])
                        gameData.unlockShip.append(result_data['newShipVO'][0]['shipCid'])
                    # 检测是否出了特定船只
                    if "special" in other_data:
                        # 先正向查询
                        ship_need_name_list = str(other_data['special']).split("-")
                        for name in ship_need_name_list:
                            if name in new_ship or name in new_ship_row_name:
                                map_name = gameData.allLevel[int(str(node)[: -2])]['title']
                                set_log(
                                    "完成 " + map_name + '的' + now_flag + '点 评价:' + assess[
                                        result_data['warResult'][
                                            'resultLevel']] + " MVP:" + mvp_name + " 打捞:" + new_ship,
                                    0)
                                return self.END_SPECIAL_SHIP
                map_name = gameData.allLevel[int(str(node)[: -2])]['title']
                set_log(
                    "完成 " + map_name + '的' + now_flag + '点 评价:' + assess[
                        result_data['warResult']['resultLevel']] + " MVP:" + mvp_name + " 打捞:" + new_ship, 0)
                log.info("Finish battle " + now_flag + '..' + assess[
                    result_data['warResult']['resultLevel']] + " MVP:" + mvp_name)
                # 判断人物血量
                log.info('Analysis ship left HP information')
                fleet_hp = []
                fleet_max_hp = []
                is_go = True
                for fleet_member in result_data['shipVO']:
                    fleet_hp.append(fleet_member['battleProps']['hp'])
                    fleet_max_hp.append(fleet_member['battlePropsMax']['hp'])
                fleet_four_hp = [int(hp * 4) for hp in fleet_hp]
                for i in range(0, len(fleet_hp)):
                    if int(fleet_max_hp[i]) > int(fleet_four_hp[i]):
                        is_go = False
                        log.info('Some ship was terribly broken...Back to the port')
                        set_log('有船大破，准备回港...', 1)
                # 判断500船
                if windows_main.cb_500stop.isChecked():
                    pj = result_data['warResult']['resultLevel']
                    if (pj == 1 or pj == 2) and not has_new_ship:
                        return self.END_500_SHIP
                # 判断是否继续前进
                log.info("====Now at is next====")
                if is_last_point is True:
                    set_log('本次出征完成...', 1)
                    gameData.get_refresh_data()
                    return self.END_FINISH
                if is_go is False or is_last_point is True:
                    set_log('不能前进,返回港口...', 1)
                    log.info("Analysis can't continue...Back to port")
                    gameData.get_refresh_data()
                    return self.END_SL
                else:
                    log.info('Analysis is go next...Continue')
                    continue  # 准备前进的话，结束循环
        except HmError as e:
            log.error('Main ERROR:', e.message)
            raise
        except Exception as e:
            log.error('Main ERROR:', str(e))
            raise

    def check_repair(self, repair):
        """
        功能:检测修理
        :return: 布尔值, 信息
        """
        log.info('Check Repair')
        set_log('检测修理', 1)
        repair_ship_item = []
        repair_ship_left_hp = []

        fast_repair_format = []
        repair_ship = []
        change_ship = []
        try:
            for eachShip in gameData.fleet[self.fleet]:
                now_hp = int(gameData.allShip[eachShip]['battleProps']['hp'])
                max_hp = int(gameData.allShip[eachShip]['battlePropsMax']['hp'])
                repair_ship_left_hp.append((now_hp / max_hp) * 100)
            log.debug(repair_ship_left_hp)
            # 中破停止:
            # 0  大破停止:1  中破修理:2  大破修理:3 90:4
            # 0: 全局设置 1: 中破修理 2: 大破修理 3: 90%
            for num in range(len(gameData.fleet[self.fleet])):
                repair_all_format = windows_main.cb_repair.currentIndex()
                repair_format = repair_all_format
                if repair[num]['rule'] == 0:  # 使用全局设置
                    repair_format = repair_all_format
                elif repair[num]['rule'] == 1:  # 中破
                    repair_format = 2
                elif repair[num]['rule'] == 2:  # 大破
                    repair_format = 3
                elif repair[num]['rule'] == 3:  # 90%
                    repair_format = 4
                if repair_format == 0 and repair_ship_left_hp[num] < 50:  # 中破停止
                    return False, "修理检测不通过,请在全局设置修改"
                elif repair_format == 1 and repair_ship_left_hp[num] < 25:  # 大破停止
                    return False, "修理检测不通过,请在全局设置修改"
                elif repair_format == 2 and repair_ship_left_hp[num] < 50:  # 中破修理
                    if repair[num]['type'] == 0:  # 使用快修
                        fast_repair_format.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 1:  # 泡澡
                        repair_ship.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 2:  # 换船
                        change_ship.append({'ship': gameData.fleet[self.fleet][num], 'path': num, 'data': repair[num]})
                elif repair_format == 3 and repair_ship_left_hp[num] < 25:  # 大破修理
                    if repair[num]['type'] == 0:  # 使用快修
                        fast_repair_format.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 1:  # 泡澡
                        repair_ship.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 2:  # 换船
                        change_ship.append({'ship': gameData.fleet[self.fleet][num], 'path': num, 'data': repair[num]})
                elif repair_format == 4 and repair_ship_left_hp[num] < 90:  # 90%修理
                    if repair[num]['type'] == 0:  # 使用快修
                        fast_repair_format.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 1:  # 泡澡
                        repair_ship.append(gameData.fleet[self.fleet][num])
                    elif repair[num]['type'] == 2:  # 换船
                        change_ship.append({'ship': gameData.fleet[self.fleet][num], 'path': num, 'data': repair[num]})
            # 进行快速修理
            if len(fast_repair_format) != 0:  # 修理船只
                repair_name = [init_data.ship_cid_wu[gameData.allShip[int(ship_id)]['shipCid']]['title'] for ship_id in
                               fast_repair_format]
                set_log('修理船只:' + " ".join(repair_name), 0)
                log.info('Repair ship ' + " ".join(repair_name))
                repair_ship_item.clear()
                repair_ship_item = [str(int_ship) for int_ship in fast_repair_format]
                repair_data = gameFunction.repair(repair_ship_item)
                # 更新船只信息
                if "shipVOs" in repair_data:
                    for ship in repair_data['shipVOs']:
                        gameData.upgrade_ship(ship['id'], ship)
                # 更新快修信息
                other_function.refresh_base_data()
                # 更新资源信息
                if 'userVo' in repair_data and len(repair_data['userVo']) != 0:
                    gameData.oil = repair_data['userVo']['oil']
                    gameData.ammo = repair_data['userVo']['ammo']
                    gameData.steel = repair_data['userVo']['steel']
                    gameData.aluminium = repair_data['userVo']['aluminium']
                    other_function.refresh_base_data()
                # 更新任务信息
                if "updateTaskVo" in repair_data and len(repair_data["updateTaskVo"]) != 0:
                    for task in repair_data['updateTaskVo']:
                        gameData.taskInfo[task['taskCid']]['condition'] = task['condition']
                log.info('Finish Repair')
                time.sleep(3)

            # 进行换船处理
            if len(change_ship) != 0:
                for ship_data in change_ship:
                    change_result, new_ship = self.change_ship(ship=ship_data['ship'], path=ship_data['path'],
                                                               fleet=self.fleet,
                                                               data=ship_data['data'])
                    log.debug(change_result, new_ship)
                    if change_result is False:
                        min_time = other_function.get_min_repair_time()
                        if min_time == -1:
                            return False, "没有可用船只!"
                        else:
                            return -1, min_time
                    else:
                        set_log("换船:" + init_data.ship_cid_wu[gameData.allShip[ship_data['ship']]['shipCid']]['title'] + " → " + init_data.ship_cid_wu[gameData.allShip[new_ship]['shipCid']]['title'], 0)

            # 进行泡澡
            if len(repair_ship) != 0:
                result, left_time = other_function.shower(repair_ship, g.repair_time_limit)
                if left_time == -1:
                    return False, "无法处理空位!"
                return -1, left_time
            return True, 0
        except HmError as e:
            log.error('Repair Error', e.message)
            raise
        except Exception as e:
            log.error('Repair Error', e)
            raise

    @staticmethod
    def check_strengthen():
        have_ship = True
        if windows_main.cb_strengthen.isChecked() is True and len(config_function.qh_ship) != 0:
            num = 0
            while len(config_function.qh_ship) != 0 and num < len(config_function.qh_ship) and have_ship is True:
                now_ship = config_function.qh_ship[num]
                ship_stuff = []
                # 生成星级数据
                accept_star = "123456"
                if windows_main.cb_s_save.currentIndex() != 0:
                    accept_star = [int(x) for x in list(accept_star[: 0 - windows_main.cb_s_save.currentIndex()])]
                else:
                    accept_star = [1, 2, 3, 4, 5, 6]
                # 读取最大数据
                atk_max = init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['strengthenTop']['atk']
                torpedo_max = init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['strengthenTop'][
                    'torpedo']
                air_def_max = init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['strengthenTop'][
                    'air_def']
                def_max = init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['strengthenTop']['def']
                # 获取已有数据
                atk = gameData.allShip[int(now_ship)]['strengthenAttribute']['atk']
                torpedo = gameData.allShip[int(now_ship)]['strengthenAttribute']['torpedo']
                air_def = gameData.allShip[int(now_ship)]['strengthenAttribute']['air_def']
                defence = gameData.allShip[int(now_ship)]['strengthenAttribute']['def']
                print(atk_max, atk, torpedo, torpedo_max, air_def, air_def_max, defence, def_max)
                while atk < atk_max or torpedo < torpedo_max or air_def < air_def_max or defence < def_max:
                    ship_stuff_wait = []
                    for ids, data in gameData.allShip.items():
                        # 剔除数据
                        if ids in ship_stuff:  # 剔除已选数据
                            continue
                        if int(init_data.ship_cid_wu[data['shipCid']]['star']) not in accept_star:  # 剔除不接受的星级
                            continue
                        if data['isLocked'] == 1:  # 剔除锁定船只
                            continue
                        if data['fleet_id'] != 0:  # 剔除在队伍的船只
                            continue
                        if windows_main.cb_s_unusualShip.isChecked() is True:
                            if init_data.ship_cid_wu[data['shipCid']]['title'] in windows_main.ed_s_unusualShip.text():
                                continue  # 反和谐名称
                            if data['title'] in windows_main.ed_s_unusualShip.text():  # 和谐名称
                                continue
                            if "-" in windows_main.ed_s_unusualShip.text():
                                unusual_ship = windows_main.ed_s_unusualShip.text().split("-")
                                for ship in unusual_ship:
                                    if ship in init_data.ship_cid_wu[data['shipCid']]['title'] or ship in data['title']:
                                        continue
                        # --------计算权重----------
                        # 火力权重计算
                        atk_weight = 0
                        if atk_max != 0 and atk_max > atk and windows_main.cb_s_f.isChecked() is True:
                            atk_support = init_data.ship_cid_wu[data['shipCid']]['strengthenSupplyExp']['atk']
                            atk_need = atk_max - atk
                            if atk_support > atk_need:  # 如果经验溢出
                                atk_weight = 1  # 权重设置为最大
                                atk_out = atk_support - atk_need  # 计算溢出经验值
                                atk_weight -= atk_out / atk_need / 100  # 减去溢出权重
                                if atk_weight < 0:  # 如果溢出过于过分,则设为0
                                    atk_weight = 0
                            else:
                                atk_weight = atk_support / atk_need
                        # 鱼雷权重计算
                        torpedo_weight = 0
                        if torpedo_max != 0 and torpedo_max > torpedo and windows_main.cb_s_t.isChecked() is True:
                            torpedo_support = init_data.ship_cid_wu[data['shipCid']]['strengthenSupplyExp']['torpedo']
                            torpedo_need = torpedo_max - torpedo
                            if torpedo_support > torpedo_need:  # 如果经验溢出
                                torpedo_weight = 1  # 权重设置为最大
                                torpedo_out = torpedo_support - torpedo_need  # 计算溢出经验值
                                torpedo_weight -= torpedo_out / torpedo_need / 100  # 减去溢出权重
                                if torpedo_weight < 0:  # 如果溢出过于过分,则设为0
                                    torpedo_weight = 0
                            else:
                                torpedo_weight = torpedo_support / torpedo_need
                        # 防空权重
                        air_def_weight = 0
                        if air_def_max != 0 and air_def_max > air_def and windows_main.cb_s_a.isChecked() is True:
                            air_def_support = init_data.ship_cid_wu[data['shipCid']]['strengthenSupplyExp']['air_def']
                            air_def_need = atk_max - air_def
                            if air_def_support > air_def_need:  # 如果经验溢出
                                air_def_weight = 1  # 权重设置为最大
                                air_def_out = air_def_support - air_def_need  # 计算溢出经验值
                                air_def_weight -= air_def_out / air_def_need / 100  # 减去溢出权重
                                if air_def_weight < 0:  # 如果溢出过于过分,则设为0
                                    air_def_weight = 0
                            else:
                                air_def_weight = air_def_support / air_def_need
                        # 装甲权重计算
                        def_weight = 0
                        if def_max != 0 and def_max > defence and windows_main.cb_s_d.isChecked() is True:
                            def_support = init_data.ship_cid_wu[data['shipCid']]['strengthenSupplyExp']['def']
                            def_need = def_max - defence
                            if def_support > def_need:  # 如果经验溢出
                                def_weight = 1  # 权重设置为最大
                                def_out = def_support - def_need  # 计算溢出经验值
                                def_weight -= def_out / def_need / 100  # 减去溢出权重
                                if def_weight < 0:  # 如果溢出过于过分,则设为0
                                    def_weight = 0
                            else:
                                def_weight = def_support / def_need
                        all_weight = atk_weight + def_weight + air_def_weight + torpedo_weight
                        ship_stuff_wait.append({'id': ids, 'weight': all_weight})
                    log.debug(ship_stuff_wait)
                    if len(ship_stuff_wait) == 0.0:
                        have_ship = False
                        break
                    # 首次计算权重完成,对权重进行排序
                    ship_stuff_wait.sort(key=lambda x: x['weight'], reverse=True)
                    # 添加船只数据,并重新计算权重
                    if ship_stuff_wait[0]['weight'] > 0:
                        ship_stuff.append(ship_stuff_wait[0]['id'])
                        atk += init_data.ship_cid_wu[gameData.allShip[ship_stuff_wait[0]['id']]['shipCid']]['strengthenSupplyExp']['atk']
                        defence += init_data.ship_cid_wu[gameData.allShip[ship_stuff_wait[0]['id']]['shipCid']]['strengthenSupplyExp']['def']
                        torpedo += init_data.ship_cid_wu[gameData.allShip[ship_stuff_wait[0]['id']]['shipCid']]['strengthenSupplyExp']['torpedo']
                        air_def += init_data.ship_cid_wu[gameData.allShip[ship_stuff_wait[0]['id']]['shipCid']]['strengthenSupplyExp']['air_def']
                    else:
                        break
                # 当前船只选择完成
                if atk >= atk_max and defence >= def_max and torpedo >= torpedo_max and air_def >= air_def_max:
                    set_log("完成强化:" + init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['title'], 0)
                    del config_function.qh_ship[0]
                if len(ship_stuff) > 0:
                    stuff_name = [init_data.ship_cid_wu[gameData.allShip[int(x)]['shipCid']]['title'] for x in ship_stuff]
                    ship_name = init_data.ship_cid_wu[gameData.allShip[int(now_ship)]['shipCid']]['title']
                    set_log("强化:" + ship_name + ' 使用' + str(len(ship_name)) + "个:" + " ".join(stuff_name), 0)
                    time.sleep(2)
                    gameFunction.strengthen(ids=now_ship, ship=ship_stuff)
                    gameData.remove_ship(ship_stuff)
                num += 1

    @staticmethod
    def check_explore():
        """
        功能:检测远征
        :return: None
        """
        explore_list = {}
        for eachExplore in gameData.exploreInfo:
            if eachExplore['endTime'] < int(time.time()):
                explore_list[eachExplore['fleetId']] = eachExplore['exploreId']
        if len(explore_list) != 0:
            explore_new = {}
            for fleet, exploreId in explore_list.items():
                explore_result = gameFunction.get_explore(exploreId)  # 取远征结果
                if explore_result['bigSuccess'] == 1:
                    result = ["大成功", ' big success']
                else:
                    result = ["成功", ' success']
                map_name = re.sub(pattern="000", repl="-", string=str(exploreId))
                # 获取奖励
                reward = ",获得:"
                if 'newAward' in explore_result and len('newAward') != 0:
                    for cid, num in explore_result['newAward'].items():
                        count.add_other(str(cid), num)
                        if int(cid) in RES:
                            reward += RES[int(cid)] + str(num) + " "
                # 更新任务信息
                if 'updateTaskVo' in explore_result and len(explore_result['updateTaskVo']) != 0:
                    for task in explore_result['updateTaskVo']:
                        gameData.taskInfo[task['taskCid']]['condition'] = task['condition']
                # 更新资源信息
                if 'userVo' in explore_result and len(explore_result['userResVo']) != 0:
                    gameData.oil = explore_result['userResVo']['oil']
                    gameData.ammo = explore_result['userResVo']['ammo']
                    gameData.steel = explore_result['userResVo']['steel']
                    gameData.aluminium = explore_result['userResVo']['aluminium']
                # 更新详细信息
                if "detailInfo" in explore_result:
                    gameData.userDetail = explore_result["detailInfo"]
                set_log('远征' + map_name + result[0] + reward, 0)
                log.info('Explored ' + map_name + result[1])
                log.info('Start explore ' + map_name)
                time.sleep(2)
                set_log("开始远征 " + map_name, 1)
                explore_new = gameFunction.start_explore(maps=exploreId, team=fleet)  # 开启新远征
                time.sleep(2)
            gameData.exploreInfo.clear()
            for eachExplore in explore_new['pveExploreVo']['levels']:
                gameData.exploreInfo.append(eachExplore)

    @staticmethod
    def check_task():
        """
        功能:检测任务
        :return: None
        """
        try:
            task_finish = []
            task_add = {}
            for cid, task in gameData.taskInfo.items():
                if task['condition'][0]['finishedAmount'] >= task['condition'][0]['totalAmount']:
                    task_finish.append(cid)
            if len(task_finish) != 0:
                for taskCid in task_finish:
                    task_data = gameFunction.get_task(cid=taskCid)
                    # 更新资源信息
                    if 'userResVo' in task_data:
                        gameData.oil = task_data['userResVo']['oil']
                        gameData.ammo = task_data['userResVo']['ammo']
                        gameData.steel = task_data['userResVo']['steel']
                        gameData.aluminium = task_data['userResVo']['aluminium']
                        other_function.refresh_base_data()
                    # 获取资源
                    reward = ',获得:'
                    if len(task_data['attach']) != 0:
                        for cid, num in task_data['attach'].items():
                            count.add_other(str(cid), num)
                            if int(cid) in RES:
                                reward += RES[int(cid)] + str(num) + " "
                    log.info('Complete task ' + gameData.taskInfo[taskCid]['title'])
                    set_log("完成任务:" + gameData.taskInfo[taskCid]['title'] + reward, 0)
                    del gameData.taskInfo[taskCid]
                    if 'taskVo' in task_data:
                        for newTask in task_data['taskVo']:
                            task_add[newTask['taskCid']] = newTask
                    time.sleep(3)
                gameData.taskInfo.update(task_add)
        except Exception as e:
            log.error("Check Task ERROR:", str(e))
            raise

    @staticmethod
    def dismantle():
        """
        功能:分解船只
        :return: None
        """
        try:
            dismantle_ship = []
            # 筛选出所有未锁船只和不在编队的船只
            for ids, detail in gameData.allShip.items():
                if detail['isLocked'] == 0 and detail['fleetId'] == 0:
                    types = detail['type']
                    if windows_main.cb_d_dd.isChecked() is True and types == 12:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_cl.isChecked() is True and types == 10:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_ca.isChecked() is True and types == 7:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_bb.isChecked() is True and types == 4:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_bc.isChecked() is True and types == 6:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_cvl.isChecked() is True and types == 2:
                        dismantle_ship.append(str(ids))
                    if windows_main.cb_d_cv.isChecked() is True and types == 1:
                        dismantle_ship.append(str(ids))
            # 剔除不符合条件的船只
            if len(dismantle_ship) > 0:
                if windows_main.cb_d_unusualShip.isChecked() is True:  # 剔除特定船只
                    if windows_main.ed_d_unusualShip.text() != '':
                        # 精确匹配
                        if "-" in windows_main.ed_d_unusualShip.text():
                            ship_save_name = windows_main.ed_d_unusualShip.text().split('-')
                            for eachName in ship_save_name:
                                for ship in dismantle_ship:
                                    if eachName in init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['title']:
                                        dismantle_ship.remove(str(ship))
                        else:
                            for ship in dismantle_ship:
                                if windows_main.ed_d_unusualShip.text() in init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['title']:
                                    dismantle_ship.remove(str(ship))

                if windows_main.cb_d_save.currentIndex() >= 1:  # 剔除6星
                    for eachShip in dismantle_ship:
                        if init_data.ship_cid[gameData.allShip[int(eachShip)]['shipCid']]['star'] == 6:
                            dismantle_ship.remove(str(eachShip))
                if windows_main.cb_d_save.currentIndex() >= 2:  # 剔除5星
                    for eachShip in dismantle_ship:
                        if init_data.ship_cid[gameData.allShip[int(eachShip)]['shipCid']]['star'] == 5:
                            dismantle_ship.remove(str(eachShip))
                if windows_main.cb_d_save.currentIndex() >= 3:  # 剔除4星
                    for eachShip in dismantle_ship:
                        if init_data.ship_cid[gameData.allShip[int(eachShip)]['shipCid']]['star'] == 4:
                            dismantle_ship.remove(str(eachShip))
                if windows_main.cb_d_save.currentIndex() >= 4:  # 剔除3星
                    for eachShip in dismantle_ship:
                        if init_data.ship_cid[gameData.allShip[int(eachShip)]['shipCid']]['star'] == 3:
                            dismantle_ship.remove(str(eachShip))
                dismantle_ship = dismantle_ship[: 20]
                ship_name = [str(init_data.ship_cid_wu[gameData.allShip[int(ids)]['shipCid']]['title']) for ids in dismantle_ship]
                log.debug(dismantle_ship)
                set_log('分解船只:' + str(len(dismantle_ship)) + '个:' + " ".join(ship_name), 0)
                log.info('Dismantle ship', len(dismantle_ship))
                if windows_main.cb_d_equipment.isChecked() is True:
                    dismantle_data = gameFunction.dismantle(ship=dismantle_ship, is_save=0)
                else:
                    dismantle_data = gameFunction.dismantle(ship=dismantle_ship, is_save=1)
                error_find(dismantle_data)
                # 清除分解数据
                print("清除分解数据,", dismantle_data)
                left_ship = gameData.remove_ship(fleet=dismantle_data['delShips'])
                # 更新装备信息
                gameData.upgrade_equipment(data=dismantle_data)
                # 更新详细信息
                if "detailInfo" in dismantle_data:
                    gameData.userDetail = dismantle_data["detailInfo"]
                other_function.refresh_base_data()
                if left_ship < gameData.shipNumTop:
                    return True
                else:
                    return False
        except HmError as e:
            print('Dismantle Error', str(e.message))
        except Exception as e:
            log.error('Dismantle Error', str(e))

    @staticmethod
    def change_ship(ship, fleet, path, data):
        """
        data数据
        --type: 0
        --rule: 0
        --data
        'equipment' 装备继承
        'random': bol 是否为粗略匹配
        'min': 最小等级
        'max': 最大等级
        'accurate': 精确匹配
        'ship': 船只数据
        'isG'
        """
        # 第一步 更换船只
        log.info("Start change ship:", ship, fleet, path, data)
        new_ship = -1
        change_data = data['data']
        repair = data['rule']
        # 粗略匹配
        if change_data['random'] is True:
            old_ship_type = init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['type']
            for ship_id, ship_data in gameData.allShip.items():
                log.debug(ship_id, init_data.ship_cid_wu[gameData.allShip[int(ship_id)]['shipCid']]['type'], ship_data['level'], ship_data['fleet_id'])
                # 排除本体
                if ship_id == ship:
                    continue
                # 排除不同类型
                if init_data.ship_cid_wu[gameData.allShip[int(ship_id)]['shipCid']]['type'] != old_ship_type:
                    continue
                # 排除等级
                if not(change_data['min'] < ship_data['level'] < change_data['max']) and not(change_data['max'] < ship_data['level'] < change_data['min']):
                    continue
                # 排除其他队伍
                if ship_data['fleetId'] != 0:
                    continue
                # 剔除未改造的
                if change_data['isG'] is True:
                    if int(init_data.ship_cid_wu[ship_data['shipCid']]['shipIndex']) < 1000:
                        continue
                # 排除血量
                left_hp = ship_data['battleProps']['hp'] / ship_data['battlePropsMax']['hp'] * 100
                fin_repair = -1
                if repair == 0:
                    fin_repair = windows_main.cb_repair.currentIndex()
                elif repair == 1:
                    fin_repair = 2
                elif repair == 2:
                    fin_repair = 3
                if fin_repair == 2 and left_hp >= 50:
                    new_ship = ship_id
                elif fin_repair == 3 and left_hp >= 25:
                    new_ship = ship_id
                elif fin_repair == 4 and left_hp >= 90:
                    new_ship = ship_id
                else:
                    continue
                if new_ship != -1:
                    break

        # 精确匹配
        if change_data['accurate'] is True:
            if len(change_data['ship']) != 0:
                for ship in change_data['ship']:
                    # 排除本队
                    if ship in gameData.fleet[fleet]:
                        continue
                    # 检测是否在池子里
                    if ship not in gameData.allShip:
                        continue
                    # 检测血量
                    ship_data = gameData.allShip[ship]
                    left_hp = ship_data['battleProps']['hp'] / ship_data['battlePropsMax']['hp'] * 100
                    fin_repair = -1
                    if repair == 0:
                        fin_repair = windows_main.cb_repair.currentIndex()
                    elif repair == 1:
                        fin_repair = 2
                    elif repair == 2:
                        fin_repair = 3
                    if fin_repair == 2 and left_hp >= 50:
                        new_ship = ship
                    elif fin_repair == 3 and left_hp >= 25:
                        new_ship = ship
                    elif fin_repair == 4 and left_hp >= 90:
                        new_ship = ship
                    else:
                        continue
                    if new_ship != -1:
                        break
        log.debug("Change ship find", new_ship)
        if new_ship != -1:  # 有新船只了
            log.info("Change ship", new_ship, ship)
            # 装备继承
            change_ship_data = {}
            if change_data['equipment'] is True:
                old_equipment = []
                equipment_path = 0
                if type(gameData.allShip[ship]['equipment']) == list:
                    for equipment_cid in gameData.allShip[ship]['equipment']:
                        if int(equipment_cid) == -1:
                            continue
                        gameFunction.remove_equipment(ids=ship, path=equipment_path)
                        old_equipment.append(int(equipment_cid))
                        log.info("Change equipment", ship, equipment_path)
                        set_log("卸下装备:" + gameData.allShip[int(ship)]['title'] + '的' + str(equipment_path), 1)
                        equipment_path += 1
                        time.sleep(3)
                elif type(gameData.allShip[ship]['equipment']) == dict:
                    for index, equipment_cid in gameData.allShip[ship]['equipment'].items():
                        if int(equipment_cid) == -1:
                            continue
                        gameFunction.remove_equipment(ids=ship, path=equipment_path)
                        old_equipment.append(int(equipment_cid))
                        log.info("Change equipment", ship, equipment_path)
                        set_log("卸下装备:" + gameData.allShip[int(ship)]['title'] + '的' + str(equipment_path), 1)
                        equipment_path += 1
                        time.sleep(3)

                if len(old_equipment) != 0:
                    for i in range(min(len(old_equipment),
                                       len(gameData.allShip[ship]['equipment0']))):
                        gameFunction.change_equipment(ids=new_ship, cid=old_equipment[i], path=i)
                        set_log("更换装备:" + gameData.allShip[int(new_ship)]['title'] + '的' + str(i), 1)
                        time.sleep(3)
            # 更换船只
            change_ship_data = gameFunction.change_ship(fleet=fleet + 1, ids=new_ship, path=path)
            gameData.upgrade_fleet(change_ship_data)
            time.sleep(3)
            # 旧船进行维修
            other_function.shower([ship], -1)
            return True, new_ship
        else:
            log.info("Change ship no find")
            return False, 0

    def qh_add_ship(self):
        w = WindowsSelectShip()
        w.can_select = -1
        w.select_ship = config_function.qh_ship
        w.refresh_select_ship()
        if w.exec_():
            config_function.qh_ship = w.select_ship
        self.qh_upgrade_list()

    @staticmethod
    def qh_upgrade_list():
        windows_main.lt_qh_ship_list.clear()
        for ship in config_function.qh_ship:
            name = init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['title']
            level = "Lv." + str(gameData.allShip[int(ship)]['level'])
            windows_main.lt_qh_ship_list.addItem(level + ' ' + name)
            config_function.main_save()


class CampaignMain:
    """
    战役战斗
    """
    def __init__(self):
        self.campaignTotal = 0
        self.remainNum = 0
        self.map = '101'
        self.isNightFight = False
        self.difficult = 0
        self.campaignMap = []
        self.repair = 0
        self.format = 0
        self.fleet = []

    def main(self, maps, repair, formats, night, sl):
        """
        战役主要
        :return:None
        """
        self.campaignTotal = gameData.campaignTotal
        self.campaignMap = gameData.campaignMap  # 储存着战役的对应关系
        self.remainNum = gameData.campaignRemainNum
        self.repair = repair
        self.isNightFight = night
        self.format = formats + 1
        if gameData.campaignRemainNum == 0:  # 战役完成,删除任务
            return False
        if int(maps) >= len(self.campaignMap):  # 检测是否能打这个点
            return False
        else:
            self.map = self.campaignMap[int(maps)]

        try:
            log.info('=-=-=-=-=-=-Start-=-=-=-=-=-=')
            # 选图页面
            windows_main.lt_our_2.clear()
            time.sleep(3)
            map_data = gameFunction.campaign_get_fleet(maps=self.map)
            self.fleet.clear()
            for each_ship in map_data['campaignLevelFleet']:
                if each_ship != 0 and each_ship != '0':
                    self.fleet.append(int(each_ship))
            other_function.refresh_our_ship_data(fleet=self.fleet, name='战役队伍')
            # 进行修理检测
            self.check_repair(fleet=self.fleet, repair=self.repair)
            # 进行补给
            gameFunction.supply(ship=self.fleet)
            time.sleep(2)
            # 进行索敌
            log.info('Campaign spy')
            set_log('进行战役索敌...', 1)
            spy_data = gameFunction.campaign_get_spy(maps=self.map)
            other_function.refresh_foe_ship_data(spy_data['enemyVO']['enemyShips'])
            time.sleep(2)
            # 开始战斗
            log.info('Campaign fight start')
            campaign_data = gameFunction.campaign_fight(maps=self.map, formats=self.format)
            fight_time = other_function.ai_delay(campaign_data['warReport'])
            set_log('开始战役...等待' + str(fight_time) + '秒', 1)
            # 判断是否进行SL
            if sl is True:
                set_log("战役SL..执行完成", 0)
                time.sleep(5)
                return True
            time.sleep(fight_time)
            # 判断是否需要夜战
            if campaign_data['warReport']['canDoNightWar'] == 1 and self.isNightFight is True:
                # 可以进行夜战
                set_log('开始战役夜战...', 1)
                log.info('Campaign night fight...')
                campaign_result = gameFunction.campaign_get_result(is_night_fight=1)
                fight_time = other_function.ai_delay_night(campaign_result['extraProgress'])
                time.sleep(fight_time)
            else:
                # 不进行夜战
                campaign_result = gameFunction.campaign_get_result(is_night_fight=0)
                log.info('Finish campaign')
            campaign_name = ['驱逐简单战役', '驱逐困难战役', '巡洋简单战役', '巡洋困难战役', '战列简单战役',
                             '战列困难战役', '航母简单战役', '航母困难战役', '潜艇简单战役', '潜艇困难战役']
            reward = ""
            for index, num in campaign_result['newAward'].items():
                if int(index) in RES:
                    count.add_other(str(index), num)
                    reward += RES[int(index)] + ":" + str(num) + " "
            set_log(campaign_name[int(maps)] + '  获得:' + reward, 0)
            other_function.refresh_base_data()
            # 更新人物血量信息
            windows_main.lt_our_2.clear()
            for ship in campaign_result['shipVO']:
                gameData.upgrade_ship(ids=ship['id'], jsons=ship)
            # 更新资源信息
            time.sleep(3)
            # 完成战役并刷新战役数据
            gameData.get_campaign_data()
        except Exception as e:
            log.error('Campaign ERROR:', str(e))
            raise
        return True

    @staticmethod
    def check_repair(fleet, repair):
        need_repair = []
        if len(fleet) != 0:
            for each_ship in fleet:
                if repair == 0:  # 中破修理
                    if gameData.allShip[each_ship]['battleProps']['hp'] * 2 < \
                            gameData.allShip[each_ship]['battlePropsMax']['hp']:
                        need_repair.append(each_ship)
                elif repair == 1:  # 大破修理
                    if gameData.allShip[each_ship]['battleProps']['hp'] * 4 < \
                            gameData.allShip[each_ship]['battlePropsMax']['hp']:
                        need_repair.append(each_ship)
        if len(need_repair) != 0:
            time.sleep(3)
            repair_data = gameFunction.repair(ship=need_repair)
            ship = [init_data.ship_cid_wu[gameData.allShip[int(ids)]['shipCid']]['title'] for ids in need_repair]
            ship = " ".join(ship)
            log.info('修理船只:' + str(len(need_repair)) + "个:" + ship)
            set_log('修理船只:' + str(len(need_repair)) + "个:" + ship, 0)
            # 更新船只信息
            if "shipVOs" in repair_data:
                for ship in repair_data['shipVOs']:
                    gameData.upgrade_ship(ship['id'], ship)
            # 更新快修信息
            if 'packageVo' in repair_data and repair_data['packageVo'][0]['itemCid'] == 541:
                gameData.fastRepair = repair_data['packageVo'][0]['num']
                other_function.refresh_base_data()
            # 更新资源信息
            if 'userVo' in repair_data and len(repair_data['userVo']) != 0:
                gameData.oil = repair_data['userVo']['oil']
                gameData.ammo = repair_data['userVo']['ammo']
                gameData.steel = repair_data['userVo']['steel']
                gameData.aluminium = repair_data['userVo']['aluminium']
                other_function.refresh_base_data()
            # 更新任务信息
            if "updateTaskVo" in repair_data and len(repair_data["updateTaskVo"]) != 0:
                for task in repair_data['updateTaskVo']:
                    gameData.taskInfo[task['taskCid']]['condition'] = task['condition']
            log.info('Finish Repair')
            time.sleep(3)


class PvpMain:
    def __init__(self):
        self.team = 0
        self.format = 0
        self.night = False
        self.cv = False
        self.ss = False

    def main(self, team, formats, night, cv, ss):
        self.team = team + 1
        self.format = formats + 1
        self.night = night
        self.cv = cv
        self.ss = ss
        log.debug('Refresh PVP list')
        list_data = gameFunction.pvp_get_list()
        self.upgrade_list(list_data)
        fight_td = []  # 0uid, 1user_name, 2fleet_name
        other_function.refresh_our_ship_data(fleet=gameData.fleet[self.team - 1],
                                             name=gameData.fleetName[self.team - 1])
        log.debug('Start PVP')
        try:
            for each_td in list_data['list']:
                if each_td['resultLevel'] == 0:
                    fight_td.append([each_td['uid'], each_td['username'], each_td['fleetName']])
            if len(fight_td) == 0:
                return False
            # 开始索敌
            fight_td = fight_td[0]
            log.info('PVP spy...')
            set_log('演习...索敌...', 1)
            spy_data = gameFunction.pvp_spy(uid=fight_td[0], fleet=self.team)
            other_function.refresh_foe_ship_data(spy_data['enemyVO']['enemyShips'])
            time.sleep(2)
            # 开始战斗
            random_time = random.randint(15, 30)
            log.info('PVP fight...wait', random_time, '秒')
            set_log('演习开始战斗,等待...' + str(random_time) + "秒", 1)
            fight_data = gameFunction.pvp_fight(uid=fight_td[0], fleet=self.team, formats=self.format)
            time.sleep(random_time)
            # 进行夜战
            if fight_data['warReport']['canDoNightWar'] == 1 and self.night is True:
                log.info('PVP night fight...')
                set_log('演习...夜战...', 1)
                result_data = gameFunction.pvp_get_result(is_night_fight=1)
                time.sleep(random_time)
            else:
                result_data = gameFunction.pvp_get_result(is_night_fight=0)
            # 进行结算
            windows_main.lt_our_2.clear()
            pj = ['-', 'SS', 'S', 'A', 'B', 'C', 'D']
            set_log(
                '演习..' + str(fight_td[1]) + '-' + str(fight_td[2]) + '--' + pj[result_data['warResult']['resultLevel']],
                0)
            log.info('PVP',
                        str(fight_td[1]) + '-' + str(fight_td[2]) + '--' + pj[result_data['warResult']['resultLevel']])
        except Exception as e:
            log.error('PVP ERROR:', str(e))
            raise

    @staticmethod
    def upgrade_list(data):
        try:
            pj = ['-', 'SS', 'S', 'A', 'B', 'C', 'D']
            windows_add_pvp.add_signal.emit({'cls': 'cls'})
            for user in data['list']:
                # 显示用户信息
                user_name = user['username'][: 4]
                uesr_level = "Lv." + str(user['level'])
                user_pj = "评价:" + pj[user['resultLevel']]
                user_ship = []
                for ship in user['ships']:

                    ship_cid = ship['shipCid']
                    ship_data = init_data.ship_cid_wu[ship_cid]
                    ship_path = ""
                    if "shipIndex" in ship_data:
                        ship_path = 'icon/photo/' + str(int(ship_data['shipIndex'])) + ".png"
                    if "picId" in ship_data:
                        ship_path = 'icon/photo/' + str(int(ship_data['picId'])) + ".png"
                    ship_name = ship['title'][: 4]
                    ship_level = "Lv." + str(ship['level'])
                    user_ship.append({'ship_name': ship_name, 'ship_level': ship_level, 'ship_path': ship_path})
                data = {'user_name': user_name, 'user_level': uesr_level, 'user_pj': user_pj, 'user_ship': user_ship}
                windows_add_pvp.add_signal.emit(data)

        except Exception as e:
            log.error('Upgrade pvp list ERROR:', str(e))
            raise


class OtherFunction:
    def __init__(self):
        self.wait_shower = []
        self.wait_shower_low = []
        self.on_rank = False

    @staticmethod
    def change_fleet(fleet, ships):
        data = {}
        s = [-1, -1, -1, -1, -1, -1]
        n = [-1, -1, -1, -1, -1, -1]

        # 检测船只是否出现变动
        for ship in ships:
            if ship not in gameData.allShip:
                return False, "船只不存在"
        # 循环检测添加船只进入列表

        index = 0
        for ship in ships:
            s[index] = int(ship)
            index += 1

        index = 0
        fleet_ship = gameData.fleet[fleet]
        for ship in fleet_ship:
            n[index] = int(ship)
            index += 1


        remove_index = -1
        is_operate = False
        for i in range(6):
            if s[i] == -1 and n[i] != -1:
                is_operate = True
                if remove_index == -1:
                    remove_index = i
                data = gameFunction.remove_ship(fleet=fleet + 1, path=remove_index)
                gameData.fleet[fleet] = data["fleetVo"][0]["ships"]
                time.sleep(2)
            elif int(s[i]) != int(n[i]) and int(s[i]) != -1:
                is_operate = True
                data = gameFunction.change_ship(fleet=fleet + 1, ids=s[i], path=i)
                gameData.fleet[fleet] = data["fleetVo"][0]["ships"]
                time.sleep(2)
        if is_operate:
            name = [init_data.ship_cid_wu[gameData.allShip[x]["shipCid"]]["title"] for x in ships if
                    x in gameData.allShip]
            set_log("编队:队伍%d %s" % (fleet + 1, " ".join(name)), 0)
            log.i("编队:队伍%d %s" % (fleet + 1, " ".join(name)))

        return True, ""

    @staticmethod
    def show_mine(windows):
        try:
            QMessageBox.information(windows, '护萌宝-我的',
                                    "等级:" + str(gameData.userDetail["level"])
                                    + "\n经验:" + str(gameData.userDetail["exp"])
                                    + "\n距离下一级:" + str(gameData.userDetail["lastLevelExpNeed"])
                                    + "\n收集率:" + str(gameData.userDetail["collection"])

                                    + "\n\n总出征:" + str(gameData.userDetail["pveNum"])
                                    + "\n出征成功:" + str(gameData.userDetail["pveWin"])
                                    + "\n出征失败:" + str(gameData.userDetail["pveLost"])
                                    + "\n胜率:" + str(
                                        int(gameData.userDetail["pveWin"]) / int(gameData.userDetail["pveNum"]) * 100)[
                                                : 4] + "%"


                                    + "\n\n演习次数:" + str(gameData.userDetail["pvpNum"])
                                    + "\n演习成功:" + str(gameData.userDetail["pvpWin"])
                                    + "\n演习失败:" + str(gameData.userDetail["pvpLost"])
                                    + "\n胜率:" + str(
                                        int(gameData.userDetail["pvpWin"]) / int(gameData.userDetail["pvpNum"]) * 100)[
                                                : 4] + "%"

                                    + "\n\n远征数量:" + str(gameData.userDetail["exploreNum"])
                                    + "\n远征大成功:" + str(
                                        gameData.userDetail["exploreBigSuccessNum"])
                                    , QMessageBox.Yes)
        except Exception as e:
            print(e)

    @staticmethod
    def get_log(windows):
        log.get_log()
        QMessageBox.information(windows, "护萌宝", "已将日志输出至桌面!", QMessageBox.Yes)

    @staticmethod
    def show_mine_collection():
        windows_mine.select_ship = -1
        windows_mine.tw_detail.clear()
        windows_mine.refresh_list()
        windows_mine.show()

    @staticmethod
    def free_shower():
        OtherFunction.repair_complete()

        repairring_data = []
        # 遍历船只数据
        for dock in gameData.repairDock:
            if "shipId" in dock and dock["endTime"] > time.time():
                repairring_data.append(int(dock["shipId"]))

        wait_shower = []
        for ids, ship in gameData.allShip.items():
            if "fleet_id" in ship and ship["fleet_id"] != 0:
                continue
            if "fleetId" in ship and ship["fleetId"] != 0:
                continue
            if ids in repairring_data:
                continue
            if ship["battleProps"]["hp"] != ship["battlePropsMax"]["hp"]:
                wait_shower.append(int(ship["id"]))

        repair_data = {}
        for dock in gameData.repairDock:
            if dock["locked"] == 0:
                if "endTime" not in dock:
                    if len(wait_shower) > 0:
                        gameFunction.shower(ship=wait_shower[0])
                        set_log(
                            "泡澡船只:" + init_data.ship_cid_wu[gameData.allShip[wait_shower[0]]["shipCid"]]['title'], 0)
                        time.sleep(3)
                        repair_data = gameFunction.rubdown(ship=wait_shower[0])
                        set_log(
                            "搓澡船只:" + init_data.ship_cid_wu[gameData.allShip[wait_shower[0]]["shipCid"]]['title'], 1)
                        del wait_shower[0]
        if repair_data != {}:
            if 'repairDockVo' in repair_data:
                gameData.repairDock = repair_data['repairDockVo']

    @staticmethod
    def repair_complete():
        data = {}
        for dock in gameData.repairDock:
            if "endTime" in dock and dock["endTime"] < time.time():
                ids = int(dock["shipId"])
                data = gameFunction.repair_complete(ids=dock["id"], ship=dock["shipId"])
                gameData.allShip[ids] = data["shipVO"]
                set_log("出浴:" + init_data.ship_cid_wu[gameData.allShip[ids]["shipCid"]]["title"], 0)
                time.sleep(3)
        if "repairDockVo" in data:
            gameData.repairDock = data["repairDockVo"]

    def shower(self, repair_ship, limit_time):
        OtherFunction.repair_complete()
        able_dock = 0
        # 正在泡澡的船只
        showering = []
        for dock in gameData.repairDock:
            if "shipId" in dock:
                showering.append(int(dock["shipId"]))
        for ship in repair_ship:
            if gameData.allShip[int(ship)]["battleProps"]['hp'] != gameData.allShip[int(ship)]["battlePropsMax"]['hp'] and int(ship) not in showering:
                self.wait_shower.append(ship)
        left_time = -1
        # 获取空位数量
        for i in range(4):
            if gameData.repairDock[i]['locked'] == 0 and ('endTime' not in gameData.repairDock[i] or (
                    'endTime' in gameData.repairDock[i] and gameData.repairDock[i]['endTime'] < time.time())):
                able_dock += 1
        # 没有没有空位了
        if able_dock == 0:
            return -1, other_function.get_min_repair_time()
        repair_data = None
        # 将船只添加入
        while able_dock > 0 and len(self.wait_shower) > 0:
            gameFunction.shower(ship=self.wait_shower[0])
            set_log("泡澡船只:" + init_data.ship_cid_wu[gameData.allShip[self.wait_shower[0]]["shipCid"]]['title'], 0)
            time.sleep(3)
            repair_data = gameFunction.rubdown(ship=self.wait_shower[0])
            set_log("搓澡船只:" + init_data.ship_cid_wu[gameData.allShip[self.wait_shower[0]]["shipCid"]]['title'], 1)
            able_dock -= 1
            # 检查是否有超时的
            for dock in repair_data['repairDockVo']:
                if 'endTime' in dock:
                    if limit_time != -1 and float(limit_time) * 60 * 60 < dock['endTime'] - dock['startTime']:
                        repair_data = gameFunction.repair([dock['shipId']])
                        able_dock += 1
                        time.sleep(3)
            del self.wait_shower[0]
            time.sleep(3)
        # 刷新船只数据
        if repair_data is not None:
            if 'repairDockVo' in repair_data:
                gameData.repairDock = repair_data['repairDockVo']
            left_time = other_function.get_min_repair_time()
            return -1, left_time

    @staticmethod
    def dismantle_equipment(item):
        if item == 0:
            rep = QMessageBox.question(windows_main, '护萌宝', '将会自动分解三星以下的装备\n请提前上锁重要装备\n如:绿声呐,绿投弹\n是否继续?', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if rep == QMessageBox.Yes:
                th_main.classical_list.insert(0, {'name': "分解低级装备", 'type': 4, 'num': 0, 'num_max': 0, 'data': {}})
                th_main.upgrade_list()
                th_main.list_save()
        else:
            log.info("分解装备")
            wait_dis = []
            for cid, equipment in gameData.allEquipment.items():
                if init_data.ship_equipmnt[cid]["star"] <= 2 and equipment["locked"] == 0 and equipment["num"] != 0:
                    wait_dis.append([cid, equipment['num']])
            index = 0
            if len(wait_dis) != 0:
                for data in wait_dis:
                    index += 1
                    set_log("分解装备:{} 数量:{}".format(init_data.ship_equipmnt[int(data[0])]["title"],
                                                   str(data[1])) + " " + str(index / len(wait_dis) * 100)[: 4] + "%", 0)
                    try:
                        gameFunction.dismantle_equipment(data[0], data[1])
                    except Exception as e:
                        print(e)
                    time.sleep(3)
            set_log('分解成功! 结束任务', 0)
            return False

    @staticmethod
    def re_login():
        try:
            log.info("Try to relogin")
            session.new_session()
            windows_login.re_login()
            config_function.main_save()
            other_function.refresh_base_data()
            other_function.refresh_our_ship_data(gameData.fleet[battle_main.fleet],
                                                 gameData.fleetName[battle_main.fleet])
            other_function.continue_login_award()
        except HmError as e:
            log.error('Re login ERROR:', e.message)
            raise
        except Exception as e:
            log.error('Re login ERROR:', str(e))

    @staticmethod
    def check_support(fleet):
        """
        功能:进行补给检测
        :return:None
        """
        set_log('补给检测', 1)
        log.info('Check support')
        # 检测是否需要补给
        need_support = False
        for ship in fleet:
            if gameData.allShip[int(ship)]['battleProps']['oil'] != \
                    gameData.allShip[int(ship)]['battlePropsMax']['oil']:
                need_support = True
            if gameData.allShip[int(ship)]['battleProps']['ammo'] != \
                    gameData.allShip[int(ship)]['battlePropsMax']['ammo']:
                need_support = True
            if gameData.allShip[int(ship)]['battleProps']['aluminium'] != \
                    gameData.allShip[int(ship)]['battlePropsMax']['aluminium']:
                need_support = True
        if need_support is False:
            log.info("Support--needn't support")
            set_log('无需补给', 1)
            return True
        # 补给全部
        try:
            supply_ship_str = [str(x) for x in fleet]
            supply_data = gameFunction.supply(supply_ship_str)
            try:
                if 'userVo' in supply_data:
                    gameData.oil = supply_data['userVo']['oil']
                    gameData.ammo = supply_data['userVo']['ammo']
                    gameData.steel = supply_data['userVo']['steel']
                    gameData.aluminium = supply_data['userVo']['aluminium']
                    other_function.refresh_base_data()
                if "shipVO" in supply_data:
                    for ship in supply_data["shipVO"]:
                        gameData.upgrade_ship(ship["id"], ship)
            except Exception as e:
                log.error('Support Error:', str(e))
                raise
        except Exception as e:
            print('Support Error:', str(e))
        time.sleep(3)
        log.info('Check support finish')
        return True

    def check_rank(self, fleet):
        """
        功能:上榜监测
        :param fleet: 船只
        :return: dict(上榜船只)
        """
        try:
            rank_in_fleet = []
            rank_data = gameData.get_rank_list()
            # 击沉榜
            if rank_data['destroyRank']['my'] != 0:
                self.on_rank = True
                for rank_ship in rank_data['destroyRank']['list']:
                    if str(rank_ship['uid']) == str(gameData.uid):
                        cid = rank_ship['shipCid']
                        lev = rank_ship['level']
                        for ids, ship_data in gameData.allShip.items():
                            if int(ship_data['shipCid']) == int(cid) and int(ship_data['level']) == int(lev):
                                if ids in fleet:
                                    rank_in_fleet.append(ids)
            #  收集榜
            for rank in rank_data['handbookRank']['list']:
                if str(rank['uid']) == str(gameData.uid):
                    self.on_rank = True
                    break
            # 实力榜
            if rank_data['fleetRank']['my']['rank'] != 0:
                self.on_rank = True
            # 功勋榜
            if rank_data['exploitRank']['my']['rank'] != 0:
                self.on_rank = True
            return rank_in_fleet
        except HmError as e:
            log.error('Rank Error::', e.message)
            raise
        except Exception as e:
            log.error('Rank Error:', e)
            raise

    @staticmethod
    def continue_login_award():
        """
        功能:领取签到奖励
        :return:
        """
        if gameData.login_award != -1:
            gameFunction.login_award()
            # reward = ['油 * 500', '钢 * 400', '快修 * 2', '弹 * 500', '铝 * 300', '快建 * 2', '箱子 * 1']
            # set_log('签到获得' + reward[gameData.login_award + 1], 0)
            # log.info('Login award', reward[gameData.login_award + 1])

    @staticmethod
    def refresh_base_data():
        # 基础数据导入

        log.info('Refreshing base data...')
        windows_main.tv_shipNum.setText(str(len(gameData.allShip)) + "/" + str(gameData.shipNumTop))
        windows_main.tv_oil.setText(str(gameData.oil))
        windows_main.tv_ammo.setText(str(gameData.ammo))
        windows_main.tv_steel.setText(str(gameData.steel))
        windows_main.tv_aluminium.setText(str(gameData.aluminium))
        windows_main.tv_fastRepair.setText(str(gameData.fastRepair))

        gameData.oilChange = gameData.oil - gameData.oilFirst
        if gameData.oilChange >= 0:
            windows_main.tv_oilChange.setText("+" + str(gameData.oilChange))
        else:
            windows_main.tv_oilChange.setText(str(gameData.oilChange))

        gameData.ammoChange = gameData.ammo - gameData.ammoFirst
        if gameData.ammoChange >= 0:
            windows_main.tv_ammoChange.setText("+" + str(gameData.ammoChange))
        else:
            windows_main.tv_ammoChange.setText(str(gameData.ammoChange))

        gameData.steelChange = gameData.steel - gameData.steelFirst
        if gameData.steelChange >= 0:
            windows_main.tv_steelChange.setText("+" + str(gameData.steelChange))
        else:
            windows_main.tv_steelChange.setText(str(gameData.steelChange))

        gameData.aluminiumChange = gameData.aluminium - gameData.aluminiumFirst
        if gameData.aluminiumChange >= 0:
            windows_main.tv_aluminiumChange.setText("+" + str(gameData.aluminiumChange))
        else:
            windows_main.tv_aluminiumChange.setText(str(gameData.aluminiumChange))

        gameData.fastRepairChange = gameData.fastRepair - gameData.fastRepairFirst
        if gameData.fastRepairChange >= 0:
            windows_main.tv_fastRepairChange.setText("+" + str(gameData.fastRepairChange))
        else:
            windows_main.tv_fastRepairChange.setText(str(gameData.fastRepairChange))

        count.save_count()
        log.info('Refresh base data success!')

    @staticmethod
    def upgrade_add_battle_fleet(fleet):
        try:
            if len(fleet) > 0:
                windows_add_battle.lt_fleet.clear()
                for each_ship in fleet:
                    windows_add_battle.lt_fleet.addItem(
                        'Lv.' + str(gameData.allShip[int(each_ship)]['level']) + ' ' + str(
                            gameData.allShip[int(each_ship)]['title']))
        except Exception as e:
            log.error('Upgrade start fleet ERROR:', str(e))
            raise

    @staticmethod
    def upgrade_add_pvp_fleet(fleet):
        try:
            if len(fleet) > 0:
                windows_add_pvp.lt_fleet.clear()
                for each_ship in fleet:
                    windows_add_pvp.lt_fleet.addItem(
                        'Lv.' + str(gameData.allShip[int(each_ship)]['level']) + ' ' + str(
                            gameData.allShip[int(each_ship)]['title']))
        except Exception as e:
            log.error('Upgrade start fleet ERROR:', str(e))
            raise

    @staticmethod
    def check_upgrade():
        """
        功能:检测脚本更新
        :return:
        """
        gameData.get_mine_version()
        if "notice" in gameData.mine:
            QMessageBox.information(windows_main, "公告", gameData.mine["notice"], QMessageBox.Yes)
        if 'version' in gameData.mine:
            if gameData.mine['version'] > VERSION:  # 版本过期
                download = gameData.mine['url']
                new_version = gameData.mine['version']
                new_version_type = gameData.mine['version_type']
                data = ''
                if str(new_version) in gameData.mine['history_data']:
                    data = gameData.mine['history_data'][str(new_version)]
                speak = '发现新版本:' + str(new_version_type) + str(new_version)
                if data != '':
                    speak += '\n更新日志:' + data
                speak += '\n是否去下载最新版本?'
                reply = QMessageBox.question(windows_main, '护萌宝', speak, QMessageBox.Yes | QMessageBox.No,
                                             QMessageBox.Yes)
                if reply == QMessageBox.Yes:
                    if os.path.exists("Upgrade.exe"):
                        win32api.ShellExecute(0, 'open', 'Upgrade.exe', '', '', 1)
                        os._exit(0)
            else:
                return False
        else:
            QMessageBox.critical(windows_main, '护萌宝', "无法连接更新服务器!", QMessageBox.Yes,
                                 QMessageBox.Yes)


    @staticmethod
    def refresh_foe_ship_data(dicts):
        """
        刷新敌人信息
        :return: None
        """
        log.info("Refreshing foe ship data... ")
        try:
            foe_ship = []
            foe_ship.clear()
            for ship in dicts:
                name = ship['title']
                hp = "HP   " + str(ship['hp']) + "/" + str(ship['hpMax'])
                foe_ship.append({'title': name, 'hp': hp})
            windows_main.foe_ship.emit(foe_ship)
            log.info("Refresh finish")
        except Exception as e:
            log.error('Refresh foe ERROR:', str(e))
            raise

    @staticmethod
    def refresh_our_ship_data(fleet, name):
        """
        功能:刷新己方船只信息
        无返回值
        """
        log.info("Refreshing our ship data...")
        log.debug(fleet)
        try:
            windows_main.tv_fleetName.setText(name)
            data = []
            for ship in fleet:
                name = init_data.ship_cid_wu[gameData.allShip[int(ship)]['shipCid']]['title']
                hp = str(gameData.allShip[int(ship)]['battleProps']['hp']) + "/" + str(
                    gameData.allShip[int(ship)]['battlePropsMax']['hp'])
                level = "Lv." + str(gameData.allShip[int(ship)]['level'])
                path = "icon/photo/" + str(int(init_data.handbook_id[gameData.allShip[int(ship)]['shipCid']])) + ".png"
                data.append({'title': name, 'hp': hp, 'level': level, 'path': path})
            windows_main.our_ship.emit(data)
        except Exception as e:
            log.error('Refresh our ship data ERROR', str(e))
            raise
        log.info("Refresh our ship data finished")

    @staticmethod
    def check_build_ship():
        def build_ship(index):
            time.sleep(2)
            build_data2 = gameFunction.build_ship(dock=gameData.dock[index]['id'],
                                                  oil=windows_main.ed_build_o.text(),
                                                  ammo=windows_main.ed_build_ammo.text(),
                                                  steel=windows_main.ed_build_s.text(),
                                                  aluminium=windows_main.ed_build_al.text())
            new_time = build_data2['dockVo'][index]['endTime']
            set_log('使用公式' + windows_main.ed_build_o.text() + ' ' + windows_main.ed_build_ammo.text() + ' '
                    + windows_main.ed_build_s.text() + ' ' + windows_main.ed_build_al.text()
                    + ' 建造,完成时间:' + time.strftime('%H:%M', time.localtime(new_time)), 0)
            # 建造时间超过设定
            if windows_main.cb_build_time.isChecked is True and (new_time - time.time()) > int(
                    windows_main.ed_time.value() * 3600):
                time.sleep(2)
                gameFunction.build_instant_ship(dock=gameData.dock[index]['id'])
                log.info('Build instant ship', str(gameData.dock[index]['id']))
                set_log('快速建造 id=' + str(gameData.dock[index]['id']), 0)
                log.info('Build new ship')
                return True, build_data2
            else:
                return False, build_data2
        if windows_main.cb_build.isChecked() is True:
            build_data = {}
            for i in range(4):
                if gameData.dock[i]['locked'] == 0 and 'endTime' in gameData.dock[i] and len(gameData.allShip) < gameData.shipNumTop:
                    if gameData.dock[i]['endTime'] < time.time():
                        while True:
                            time.sleep(2)
                            # 取得新船
                            time.sleep(2)
                            ship_data = gameFunction.build_get_ship(dock=gameData.dock[i]['id'])
                            gameData.allShip[ship_data['shipVO']['id']] = ship_data['shipVO']  # 加入船只
                            ship_name = init_data.ship_cid_wu[ship_data['shipVO']['shipCid']]['title']
                            log.info('Get ship', ship_name)
                            set_log('建造出船:' + ship_name, 0)
                            # 检测是否有出条件
                            if windows_main.cb_build_unusual.isChecked() is True:
                                is_end = False
                                try:
                                    unusual_name = windows_main.ed_build_unusual.text()
                                    unusual_name = unusual_name.split('-')
                                    if ship_name in unusual_name:
                                        is_end = True
                                    else:
                                        for each_ship in unusual_name:
                                            if each_ship in ship_name:
                                                is_end = True
                                    if is_end is True:
                                        set_log('出特定船,结束建造任务', 0)
                                        windows_main.cb_build.setChecked(False)
                                        return 0
                                except Exception as e:
                                    log.error('Build Error: No such ship!', str(e))
                            if ship_data['shipVO']['shipCid'] not in gameData.unlockShip:
                                # 出新船
                                time.sleep(2)
                                gameFunction.lock_ship(ship=int(ship_data['shipVO']['id']))
                                set_log('建造新船:' + ship_data['shipVO']['title'] + " 锁船...", 0)
                                log.info('Get new ship', ship_data['shipVO']['title'])
                            # 建造新船
                            time.sleep(3)
                            result, build_data = build_ship(i)
                            if not result:
                                break
                elif gameData.dock[i]['locked'] == 0 and 'endTime' not in gameData.dock[i]:  # 此船坞空闲
                    result, build_data = build_ship(i)
                elif len(gameData.allShip) >= gameData.shipNumTop and windows_main.cb_dismantle.isChecked():
                    battle_main.dismantle()
                    if len(gameData.allShip) >= gameData.shipNumTop:
                        windows_main.cb_build.setChecked(False)
            if len(build_data) != 0:
                gameData.dock.clear()
                gameData.dock = build_data['dockVo']
            return False

    @staticmethod
    def change_name(item):
        if item == 0:
            rep = QMessageBox.question(windows_main, '护萌宝', '名称反和谐是利用游戏自带改名\n将动物园改为正常名称\n根据船只多少可能花费数分钟\n是否继续?', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if rep == QMessageBox.Yes:
                th_main.classical_list.insert(0, {'name': "改名", 'type': 3, 'num': 0, 'num_max': 0, 'data': {}})
                th_main.upgrade_list()
                th_main.list_save()
        else:
            all_name = {}
            for ids, data in gameData.allShip.items():
                if data['title'] != init_data.ship_cid_wu[data['shipCid']]['title'] \
                        and data['title'] != init_data.ship_cid[data['shipCid']]['title']:
                    all_name[int(ids)] = [data['title'], init_data.ship_cid_wu[data['shipCid']]['title']]
            num = 0
            now_name = ""
            for ids, data in all_name.items():
                try:
                    time.sleep(3)
                    num += 1
                    new_name = data[1]
                    now_name = new_name
                    new_name = "曰向" if new_name == '日向' else new_name
                    gameFunction.rename(ids=ids, new_name=new_name)
                    set_log("改名:" + data[0] + " → " + data[1] + " " + str(num / len(all_name) * 100)[: 4] + '%', 0)
                    gameData.allShip[int(ids)]['title'] = data[1]
                except HmError as e:
                    set_log('改名失败! ' + now_name + e.message, 0)
                    continue
            set_log('改名成功! 结束任务', 0)
            return False

    def ai_delay(self, data):
        times = 0
        if 'selfBuffs' in data and len(data['selfBuffs']) != 0:
            times += 4.12
        if 'openAirAttack' in data and len(data['openAirAttack']) != 0:
            times += 4.32
        if 'openMissileAttack' in data and len(data['openMissileAttack']) != 0:
            times += 4.93
        if 'openAntiSubAttack' in data and len(data['openAntiSubAttack']) != 0:
            times += 4.64
        if 'openTorpedoAttack' in data and len(data['openTorpedoAttack']) != 0:
            times += 5.14
        if 'normalAttacks' in data:
            times += len(data['normalAttacks']) * 2.78
        if 'normalAttacks2' in data:
            times += len(data['normalAttacks2']) * 2.78
        if 'closeTorpedoAttack' in data and len(data['closeTorpedoAttack']) != 0:
            times += 4.93
        if times < 15:
            times += random.uniform(4, 8)
        if windows_main.cb_rank.isChecked() is True and self.on_rank is True:
            times += random.randint(10, 15)
        times -= random.uniform(1, 2)
        return round(times, 2)

    def ai_delay_night(self, data):
        times = random.uniform(2, 3)
        times *= len(data['nightAttacks'])
        if windows_main.cb_rank.isChecked() is True and self.on_rank is True:
            times += random.randint(8, 12)
        return round(times, 2)

    @staticmethod
    def get_min_repair_time():
        max_time = -1
        for dock in gameData.repairDock:
            if dock["locked"] == 0:
                if "endTime" in dock and dock['endTime'] > time.time():
                    if max_time != -1:
                        max_time = min(max_time, dock['endTime'])
                    else:
                        max_time = dock['endTime']
        return max_time


class ThMain:
    def __init__(self):
        self.classical_list = []
        self.timer_list = []
        self.is_running = False
        self.now_rw = ''
        self.set_time_unix = time.mktime(datetime.datetime(2021, 7, 1, 0, 0, 0).timetuple())

        self.list_read()

        # 任务计数模块
        self.num_max = 0
        self.num = 0

        # 任务保存模块
        self.rw_tmp = [0, '']

        # 登录失效
        self.login_fin = 0

    def th_main_def(self):
        if gameData.main_data['systime'] > self.set_time_unix:
            raise Exception()
        set_log("进行初始化...", 0)
        log.info("Start main th")
        rank_data = gameData.get_rank_list()
        if rank_data['destroyRank']['my'] != 0:
            name = ""
            for rank in rank_data['destroyRank']['list']:
                if rank['uid'] == str(gameData.uid):
                    title = init_data.ship_cid_wu[int(rank['shipCid'])]['title']
                    name += title + " "
            set_log('金榜题名! ' + name, 3)
            set_log('您已上击沉榜,已强制开启慢速模式!', 3)
        set_log("开启主线程...", 0)
        while True:
            try:
                self.th_main()
            except HmError as e:
                set_log(e.message, 0)
                log.error(e.message)
                if e.code == -9995:  # 登录失效
                    set_log('登录失效,重新登录游戏', 3)
                    self.login_fin += 1
                    if self.login_fin >= 10:
                        log.cri("登录失效次数达到上限,无法继续")
                        set_log("登录失效次数达到上限,无法继续", 3)
                        break
                    other_function.re_login()
                elif e.code == -102 or e.code == -105 or e.code == -106 or e.code == -107 or e.code == -108:
                    set_log('资源不足,终止任务', 3)
                    log.cri("资源不足,终止任务")
                    break
                elif e.code == -204 or e.code == -213:
                    set_log('资源不足,终止任务', 3)
                    log.cri("资源不足,终止任务")
                    break
                elif e.code == -9999:  # 服务器维护
                    set_log('服务器维护中...终止程序', 3)
                    log.cri('服务器维护中...终止程序')
                    break
                elif e.code == -411:  # 正在出征中
                    other_function.re_login()
                    continue
                elif e.code == -99999:  # 正在出征中
                    return
                else:
                    other_function.re_login()
                    continue
            except requests.exceptions.ConnectTimeout as e:
                log.error('连接超时, 可能网络状态不好...')
                other_function.re_login()
                continue
            except requests.exceptions.HTTPError as e:
                log.error('网络错误:', str(e))
                other_function.re_login()
                continue
            except Exception as e:
                log.error('主线程错误:', str(e))
                set_log('主线程错误:' + str(e), 1)
                other_function.re_login()
                continue
        set_log("主线程被终止!", 0)

    def th_main(self):
        # classical [0name, 1type, 2num, 3num_max, 4data]
        # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
        # type  0:经典 1:演习 2:战役
        while True:
            # 任务刷新
            time.sleep(1)
            self.upgrade_list()
            # 定时任务检测并加入到经典任务
            if len(self.timer_list) != 0:
                time_change = []
                now_time = datetime.datetime.now()  # 取现行时间对象
                now_time_unix = int(time.mktime(now_time.timetuple()))  # 取现行时间时间戳
                num = -1
                for each_timer in self.timer_list:  # 遍历时间数组
                    num += 1
                    set_time_time = each_timer['time'].split(':')  # 分割设定时间部分
                    set_time_unix = int(time.mktime(datetime.datetime(now_time.year, now_time.month, now_time.day,
                                                                      int(set_time_time[0]), int(set_time_time[1]),
                                                                      now_time.second).timetuple()))  # 取设定时间时间戳
                    if now_time_unix > set_time_unix and each_timer['last_time'] != now_time.day:
                        # 满足现行时间大于设定时间且今日没运行
                        time_change.append(num)
                        if each_timer['type'] == 0:
                            # 经典刷图
                            classical = {
                                         'name': each_timer['name'],
                                         'type': 0,
                                         'num': each_timer['num'],
                                         'num_max': each_timer['num_max'],
                                         'data': each_timer['data'],
                                         'locked': -1
                                        }
                            self.classical_list.insert(0, classical)
                        elif each_timer['type'] == 1:
                            # 演习
                            classical = {
                                'name': each_timer['name'],
                                'num': 0,
                                'num_max': 5,
                                'type': 1,
                                'data': each_timer['data']
                            }
                            self.classical_list.insert(0, classical)
                        elif each_timer['type'] == 2:
                            # 战役
                            classical = {
                                'name': each_timer['name'],
                                'num': 0,
                                'num_max': 12,
                                'type': 2,
                                'data': each_timer['data']
                            }
                            self.classical_list.insert(0, classical)
                if len(time_change) != 0:
                    for each_timer_change in time_change:
                        self.timer_list[each_timer_change]['last_time'] = now_time.day
                    self.list_save()
                    self.upgrade_list()
            # 经典任务
            # -----------------------
            # classical [0name, 1type, 2num, 3num_max, 4data]
            # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
            # type  0:经典 1:演习 2:战役
            # ------------------------
            able_task = []
            if len(self.classical_list) != 0:
                # 增加任务任务的冻结参数(用于旧版本)
                num = 0
                add_unlocked = []
                for task in self.classical_list:
                    if task['type'] == 0 and 'locked' not in task:
                        add_unlocked.append(num)
                for x in add_unlocked:
                    self.classical_list[x]['locked'] = -1
                    self.upgrade_list()
                    self.list_save()
                # 检查冻结任务是否到解冻的时候
                num = 0
                unlocked_task = []
                for task in self.classical_list:
                    if task['type'] == 0 and 'locked' in task and task['locked'] != -1 and time.time() > task['locked']:
                        unlocked_task.append(num)
                    num += 1
                for x in unlocked_task:
                    self.classical_list[x]['locked'] = -1
                # 检查可用任务
                num = 0
                for task in self.classical_list:
                    if task['type'] == 0 and task['locked'] == -1:
                        able_task.append({'data': task, 'index': num})
                    elif task['type'] != 0:
                        able_task.append({'data': task, 'index': num})
                    num += 1
            # 正式执行任务
            if len(able_task) != 0 and windows_main.cb_run.isChecked() is True:
                now_rw = able_task[0]['data']
                index = able_task[0]['index']
                windows_main.tv_nowrw.setText(gameFunction.set_text_size(9, windows_main.lt_rw.item(index).text()))
                if self.now_rw != now_rw['name']:
                    log.info('Start', now_rw['name'])
                    set_log('开始任务:' + now_rw['name'], 3)
                    self.now_rw = now_rw['name']
                if 'num_max' in now_rw:
                    self.num_max = now_rw['num_max']
                if 'num' in now_rw:
                    self.num = now_rw['num']
                if now_rw['type'] == 0:  # 经典出击任务
                    if now_rw['num'] >= now_rw['num_max']:  # 超过出征计划
                        log.info("Del battle task")
                        del self.classical_list[index]
                        self.list_save()
                        self.upgrade_list()
                        continue
                    # 开始出征
                    battle_result, reason = battle_main.main(config_name=now_rw['name'], fleet=str(now_rw['data']['fleet']), repair=now_rw['data']['repair_data'], other_data=now_rw['data']['other_data'])
                    if battle_result is False:
                        set_log('任务1完成,原因:' + reason, 0)
                        log.info("Del battle task")
                        del self.classical_list[index]
                        self.upgrade_list()
                        self.list_save()
                        continue
                    elif battle_result == -1:
                        # 冻结任务
                        _now_time = time.localtime(int(reason))
                        set_log('任务因泡澡被冻结! 解冻时间:' + time.strftime("%H:%M", _now_time), 0)
                        self.classical_list[index]['locked'] = reason
                        self.list_save()
                        self.upgrade_list()
                    elif battle_result is True:
                        self.classical_list[index]['num'] += 1
                        self.list_save()
                        self.upgrade_list()
                elif now_rw['type'] == 1:  # 演习任务
                    config = now_rw['data']
                    battle_result = pvp_main.main(formats=config['format'], team=config['fleet'], night=config['night'],
                                                  cv=config['cv'], ss=config['ss'])
                    if battle_result is False:
                        del self.classical_list[index]
                        self.list_save()
                        self.upgrade_list()
                        continue
                elif now_rw['type'] == 2:  # 战役任务
                    if now_rw['num'] >= now_rw['num_max']:  # 超过出征计划
                        log.info("Del battle task")
                        del self.classical_list[index]
                        self.list_save()
                        self.upgrade_list()
                        continue
                    config = now_rw['data']
                    battle_result = campaign_main.main(maps=config['map'], formats=config['format'],
                                                       night=config['night'], repair=config['repair'], sl=config["sl"])
                    if battle_result is False:
                        del self.classical_list[index]
                        self.list_save()
                        self.upgrade_list()
                        continue
                    elif battle_result is True:
                        self.classical_list[index]['num'] += 1
                        self.list_save()
                        self.upgrade_list()

                elif now_rw['type'] == 3:  # 改名
                    other_function.change_name(1)
                    del self.classical_list[index]
                    self.list_save()
                    self.upgrade_list()
                elif now_rw['type'] == 4:  # 分解装备
                    other_function.dismantle_equipment(1)
                    del self.classical_list[index]
                    self.list_save()
                    self.upgrade_list()
            else:
                # 远征任务
                windows_main.tv_nowrw.setText(gameFunction.set_text_size(9, '没事可做(空闲模式)...'))
                while other_function.check_build_ship():
                    pass
                battle_main.check_task()
                if windows_main.cb_free_explore.isChecked():
                    battle_main.check_explore()
                if windows_main.cb_free_shower.isChecked():
                    other_function.free_shower()
                battle_main.check_task()
                time.sleep(5)

    def upgrade_list(self):
        # classical [0name, 1type, 2num, 3num_max, 4data]
        # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
        # type  0:经典 1:演习 2:战役
        try:
            windows_main.lt_rw.clear()
            for eachClassical in self.classical_list:
                data = str(eachClassical['name']) + "---" + str(eachClassical['num']) + '/' + str(
                    eachClassical['num_max'])
                if "locked" in eachClassical and eachClassical['locked'] != -1:
                    data += " 冻结至:" + time.strftime("%m/%d %H:%M:%S", time.localtime(int(eachClassical['locked'])))
                windows_main.lt_rw.addItem(data)
            for eachTimer in self.timer_list:
                windows_main.lt_rw.addItem(str(eachTimer['name']) + "--- 每天:" + str(eachTimer['time']))
        except Exception as e:
            log.error('Upgrade list ERROR:', str(e))
            raise

    def list_change(self):
        num = -1
        index = -1
        try:
            if windows_main.lt_rw.currentItem() is not None:
                for i in range(len(self.classical_list)):
                    num += 1
                    if windows_main.lt_rw.currentItem().text() == windows_main.lt_rw.item(i).text():
                        index = num
                if index == -1:
                    return 0
                if index != 0:  # 任务向上移动
                    a = self.classical_list[index - 1]
                    self.classical_list[index - 1] = self.classical_list[index]
                    self.classical_list[index] = a
                self.list_save()
                self.upgrade_list()

        except Exception as e:
            log.error('Move task fail! ', str(e))
            raise

    def list_del(self):
        if len(windows_main.lt_rw.selectedItems()) != 0:
            index = windows_main.lt_rw.row(windows_main.lt_rw.selectedItems()[0])
        else:
            return 0
        try:
            if index < len(self.classical_list):
                del self.classical_list[int(index)]
            else:
                del self.timer_list[int(index) - len(self.classical_list)]
            self.upgrade_list()
            self.list_save()
        except Exception as e:
            log.error('Del task2 fail! ', str(e))
            raise

    def list_save(self):
        with open('config\\classical_list.json', 'w') as f:
            f.write(json.dumps(self.classical_list))
        with open('config\\timer_list.json', 'w') as f:
            f.write(json.dumps(self.timer_list))

    def list_read(self):
        if os.path.exists('config\\classical_list.json'):
            with open('config\\classical_list.json', 'r') as f:
                self.classical_list = json.loads(f.read())
        if os.path.exists('config\\timer_list.json'):
            with open('config\\timer_list.json', 'r') as f:
                self.timer_list = json.loads(f.read())
        self.upgrade_list()

    def list_add_battle(self, item):
        try:
            # 普通出击任务
            if item == 0:  # 加入任务后,保存配置并打开配置窗口
                log.info('Add battle task 0')
                rw_function.refresh_rw()
                rw_function.refresh_start_battle_rw_list()
                windows_add_battle.rb_classical.setChecked(True)
                other_function.upgrade_add_battle_fleet(gameData.fleet[0])
                windows_add_battle.initialize()
                windows_add_battle.show()
            elif item == 1:
                log.info('Add battle task 1')
                windows_add_battle.close()
                # classical [0name, 1type, 2num, 3num_max, 4data]
                # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
                # type  0:经典 1:演习 2:战役

                # 特殊预设的队伍
                fleet = windows_add_battle.cb_fleet.currentIndex()
                if fleet >= 4:
                    fleet = windows_user_fleet.list_index[fleet - 4]
                if windows_add_battle.cb_repair_time.isChecked() is True:
                    g.repair_time_limit = float(windows_add_battle.ed_repairMaxTime.value())
                else:
                    g.repair_time_limit = -1.0
                if windows_add_battle.rb_classical.isChecked() is True:
                    # 经典任务
                    classical = {
                                 'name': rw_function.rw_list[windows_add_battle.cb_rw.currentIndex()],
                                 'type': 0,
                                 'num': 0,
                                 'locked': -1,

                                 'num_max': windows_add_battle.ed_startNum.value(),
                                 'data': {
                                          'fleet': fleet,
                                          'repair_data': windows_add_battle.repair_data,
                                          'other_data': {}
                                         }
                                }
                    if windows_add_battle.cb_specialShip.isChecked():
                        classical['data']['special'] = windows_add_battle.ed_specialShip.text()
                    self.classical_list.append(classical)
                else:
                    timer = {
                             'name': rw_function.rw_list[windows_add_battle.cb_rw.currentIndex()],
                             'num': 0,
                             'num_max': windows_add_battle.ed_startNum.value(),
                             'type': 0,
                             'time': str(windows_add_battle.te_time_hour.value()) + ":" + str(windows_add_battle.te_time_minute.value()),
                             'last_time': 0,
                             'locked': -1,
                             'data': {
                                      'fleet': fleet,
                                      'repair_data': windows_add_battle.repair_data,
                                      'other_data': {}
                                     }
                            }
                    if windows_add_battle.cb_specialShip.isChecked():
                        timer['data']['special'] = windows_add_battle.ed_specialShip.text()
                    self.timer_list.append(timer)
                windows_add_battle.cb_fleet.setCurrentIndex(0)
                self.list_save()
                self.upgrade_list()
        except Exception as e:
            log.error('Save battle Error:', str(e))

    def list_add_pvp(self, item):
        try:
            # 演习任务
            if item == 0:  # 加入任务后,保存配置并打开配置窗口
                log.info('Add PVP task 0')
                self.rw_tmp = [1, '演习']
                other_function.upgrade_add_pvp_fleet(gameData.fleet[0])
                pvp_main.upgrade_list(gameFunction.pvp_get_list())
                windows_add_pvp.rb_classical.setChecked(True)
                windows_add_pvp.show()
            elif item == 1:
                log.info('Add PVP task 1')
                windows_add_pvp.close()
                # classical [0name, 1type, 2num, 3num_max, 4data]
                # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
                # type  0:经典 1:演习 2:战役
                if windows_add_pvp.rb_classical.isChecked() is True:
                    # 经典任务
                    classical = {
                                 'name': "演习",
                                 'type': 1,
                                 'num': 0,
                                 'num_max': 5,
                                 'data': {
                                          'fleet': windows_add_pvp.cb_fleet.currentIndex(),
                                          'format': windows_add_pvp.cb_pvp_format.currentIndex(),
                                          'night': windows_add_pvp.cb_pvp_night.isChecked(),
                                          'cv': windows_add_pvp.cb_pvp_cv.isChecked(),
                                          'ss': windows_add_pvp.cb_pvp_ss.isChecked()
                                          }
                                 }
                    self.classical_list.append(classical)
                else:
                    timer = {
                             'name': '演习',
                             'type': 1,
                             'num': 0,
                             'num_max': 5,
                             'time': str(windows_add_pvp.te_time_hour.value()) + ":" + str(windows_add_pvp.te_time_minute.value()),
                             'last_time': 0,
                             'data': {'fleet': windows_add_pvp.cb_fleet.currentIndex(),
                                      'format': windows_add_pvp.cb_pvp_format.currentIndex(),
                                      'night': windows_add_pvp.cb_pvp_night.isChecked(),
                                      'cv': windows_add_pvp.cb_pvp_cv.isChecked(),
                                      'ss': windows_add_pvp.cb_pvp_ss.isChecked()
                                      }
                             }
                    self.timer_list.append(timer)
                self.list_save()
                self.upgrade_list()
        except Exception as e:
            log.error('Add PVP task error:', str(e))

    def list_add_campaign(self, item):
        # 战役任务
        try:
            if item == 0:  # 加入任务后,保存配置并打开配置窗口
                log.info('Add cam task 0')
                windows_add_campaign.rb_classical.setChecked(True)
                windows_add_campaign.show()
            elif item == 1:
                log.info('Add cam task 1')
                windows_add_campaign.close()
                # classical [0name, 1type, 2num, 3num_max, 4data]
                # timer [0name, 1type, 2time, 3last_time, 4num, 5num_max, 6data]
                # type  0:经典 1:演习 2:战役
                campaign_name = ['驱逐简单战役', '驱逐困难战役', '巡洋简单战役', '巡洋困难战役', '战列简单战役',
                                 '战列困难战役', '航母简单战役', '航母困难战役', '潜艇简单战役', '潜艇困难战役']
                if windows_add_campaign.rb_classical.isChecked() is True:
                    # 经典任务
                    classical = {
                                 'name': campaign_name[windows_add_campaign.cb_cm_map.currentIndex()],
                                 'type': 2,
                                 'num': 0,
                                 'num_max': 12,
                                 'data': {
                                          'map': windows_add_campaign.cb_cm_map.currentIndex(),
                                          'format': windows_add_campaign.cb_cm_format.currentIndex(),
                                          'repair': windows_add_campaign.cb_cm_repair.currentIndex(),
                                          'night': windows_add_campaign.cb_cm_night.isChecked(),
                                          'sl': windows_add_campaign.cb_sl.isChecked(),
                                         }
                                 }
                    if windows_add_campaign.cb_sl.isChecked():
                        classical["num_max"] = windows_add_campaign.ed_times.value()
                    self.classical_list.append(classical)
                else:
                    timer = {
                             'name': campaign_name[windows_add_campaign.cb_cm_map.currentIndex()],
                             'type': 2,
                             'num': 0,
                             'num_max': 12,
                             'time': str(windows_add_campaign.te_time_hour.value()) + ":" + str(windows_add_campaign.te_time_minute.value()),
                             'last_time': 0,
                             'data': {
                                      'map': windows_add_campaign.cb_cm_map.currentIndex(),
                                      'format': windows_add_campaign.cb_cm_format.currentIndex(),
                                      'repair': windows_add_campaign.cb_cm_repair.currentIndex(),
                                      'night': windows_add_campaign.cb_cm_night.isChecked(),
                                      'sl': windows_add_campaign.cb_sl.isChecked()
                                     }
                             }
                    if windows_add_campaign.cb_sl.isChecked():
                        timer["num_max"] = windows_add_campaign.ed_times.value()
                    self.timer_list.append(timer)
                self.list_save()
                self.upgrade_list()
        except Exception as e:
            log.error('Add cam Error:', str(e))


class ConfigFunction:
    def __init__(self):
        self.version = 0.3
        self.main_1 = {}
        self.main_2 = {}
        self.main_3 = {}
        self.main_build = {}
        self.qh_ship = []
        self.qh = {}

        self.active_code = {}

        if not os.path.exists('config'):
            os.mkdir('config')

        if os.path.exists('config/version.json'):
            is_del = False
            with open('config/version.json', 'r') as f:
                version_config = f.read()
                if float(version_config) != float(self.version):
                    is_del = True
            if is_del:
                shutil.rmtree('config')
                time.sleep(2)
                os.mkdir('config')
                with open('config/version.json', 'w') as f2:
                    f2.write(str(self.version))

        else:
            shutil.rmtree('config')
            time.sleep(2)
            os.mkdir('config')
            with open('config/version.json', 'w') as f2:
                f2.write(str(self.version))

    def main_save(self):
        log.info('Save main config')
        self.main_1_save()
        self.main_2_save()
        self.main_3_save()
        self.main_build_save()
        self.main_other_save()

    def main_read(self):
        log.info('Read main config')
        self.main_1_read()
        self.main_2_read()
        self.main_3_read()
        self.main_build_read()
        self.main_other_read()
        self.active_read()
        log.info("Read main config finish")

    def main_other_save(self):
        data = dict()
        data['cb_rank'] = windows_main.cb_rank.isChecked()
        data["500stop"] = windows_main.cb_500stop.isChecked()
        data["cb_free_shower"] = windows_main.cb_free_shower.isChecked()
        data["cb_free_explore"] = windows_main.cb_free_explore.isChecked()
        data["cb_changeName"] = windows_main.cb_changeName.isChecked()
        with open('config\\other.json', 'w') as file:
            file.write(json.dumps(data))

    def main_1_save(self):
        self.main_1 = dict()

        self.main_1['cb_repair'] = windows_main.cb_repair.currentIndex()
        self.main_1['cb_dismantle'] = windows_main.cb_dismantle.isChecked()

        # 强化写入
        self.main_1['qh_ship'] = self.qh_ship
        self.main_1['cb_s_f'] = windows_main.cb_s_f.isChecked()
        self.main_1['cb_s_t'] = windows_main.cb_s_t.isChecked()
        self.main_1['cb_s_d'] = windows_main.cb_s_d.isChecked()
        self.main_1['cb_s_a'] = windows_main.cb_s_a.isChecked()
        self.main_1['cb_strengthen'] = windows_main.cb_strengthen.isChecked()
        self.main_1['cb_s_unusualShip'] = windows_main.cb_s_unusualShip.isChecked()
        self.main_1['cb_s_save'] = windows_main.cb_s_save.currentIndex()
        self.main_1['ed_s_unusualShip'] = windows_main.ed_s_unusualShip.text()

        with open('config\\main1.json', 'w') as file:
            file.write(json.dumps(self.main_1))

    def main_2_save(self):
        self.main_2 = dict()
        self.main_2['cb_d_dd'] = windows_main.cb_d_dd.isChecked()
        self.main_2['cb_d_cl'] = windows_main.cb_d_cl.isChecked()
        self.main_2['cb_d_ca'] = windows_main.cb_d_ca.isChecked()
        self.main_2['cb_d_bb'] = windows_main.cb_d_bb.isChecked()
        self.main_2['cb_d_bc'] = windows_main.cb_d_bc.isChecked()
        self.main_2['cb_d_cvl'] = windows_main.cb_d_cvl.isChecked()
        self.main_2['cb_d_cv'] = windows_main.cb_d_cv.isChecked()
        self.main_2['cb_d_equipment'] = windows_main.cb_d_equipment.isChecked()
        self.main_2['cb_d_unusualShip'] = windows_main.cb_d_unusualShip.isChecked()
        self.main_2['cb_d_save'] = windows_main.cb_d_save.currentIndex()
        self.main_2['ed_d_unusualShip'] = windows_main.ed_d_unusualShip.text()
        with open('config\\main2.json', 'w') as files:
            files.write(json.dumps(self.main_2))

    def main_3_save(self):
        pass

    def main_build_save(self):
        self.main_build = dict()
        self.main_build['cb_build'] = windows_main.cb_build.isChecked()
        self.main_build['ed_build_o'] = windows_main.ed_build_o.text()
        self.main_build['ed_build_ammo'] = windows_main.ed_build_ammo.text()
        self.main_build['ed_build_s'] = windows_main.ed_build_s.text()
        self.main_build['ed_build_al'] = windows_main.ed_build_al.text()
        self.main_build['cb_build_unusual'] = windows_main.cb_build_unusual.isChecked()
        self.main_build['ed_build_unusual'] = windows_main.ed_build_unusual.text()
        self.main_build['cb_build_time'] = windows_main.cb_build_time.isChecked()
        self.main_build['ed_time'] = windows_main.ed_time.value()
        with open('config\\build.json', 'w') as file:
            file.write(json.dumps(self.main_build))

    def main_1_read(self):
        if os.path.exists('config\\main1.json'):
            try:
                with open('config\\main1.json', 'r') as file:
                    self.main_1 = json.loads(file.read())
                windows_main.cb_repair.setCurrentIndex(self.main_1['cb_repair'])
                windows_main.cb_dismantle.setChecked(self.main_1['cb_dismantle'])
                if 'qh_ship' in self.main_1:
                    self.qh_ship = self.main_1['qh_ship']
                if 'cb_s_f' in self.main_1:
                    windows_main.cb_s_f.setChecked(self.main_1['cb_s_f'])
                if 'cb_s_t' in self.main_1:
                    windows_main.cb_s_t.setChecked(self.main_1['cb_s_t'])
                if 'cb_s_d' in self.main_1:
                    windows_main.cb_s_d.setChecked(self.main_1['cb_s_d'])
                if 'cb_s_a' in self.main_1:
                    windows_main.cb_s_a.setChecked(self.main_1['cb_s_a'])
                if 'cb_strengthen' in self.main_1:
                    windows_main.cb_strengthen.setChecked(self.main_1['cb_strengthen'])
                if 'cb_s_unusualShip' in self.main_1:
                    windows_main.cb_s_unusualShip.setChecked(self.main_1['cb_s_unusualShip'])
                if 'cb_s_save' in self.main_1:
                    windows_main.cb_s_save.setCurrentIndex(self.main_1['cb_s_save'])
                if 'ed_s_unusualShip' in self.main_1:
                    windows_main.ed_s_unusualShip.setText(self.main_1['ed_s_unusualShip'])

            except Exception as e:
                log.error('Main 1 read Error', str(e))
                raise

    def main_2_read(self):
        if os.path.exists('config\\main2.json'):
            try:
                with open('config\\main2.json', 'r') as file:
                    self.main_2 = json.loads(file.read())
                windows_main.cb_d_dd.setChecked(self.main_2['cb_d_dd'])
                windows_main.cb_d_cl.setChecked(self.main_2['cb_d_cl'])
                windows_main.cb_d_ca.setChecked(self.main_2['cb_d_ca'])
                windows_main.cb_d_bb.setChecked(self.main_2['cb_d_bb'])
                windows_main.cb_d_bc.setChecked(self.main_2['cb_d_bc'])
                windows_main.cb_d_cvl.setChecked(self.main_2['cb_d_cvl'])
                windows_main.cb_d_cv.setChecked(self.main_2['cb_d_cv'])

                windows_main.cb_d_equipment.setChecked(self.main_2['cb_d_equipment'])
                windows_main.cb_d_save.setCurrentIndex(self.main_2['cb_d_save'])
                windows_main.cb_d_unusualShip.setChecked(self.main_2['cb_d_unusualShip'])
                windows_main.ed_d_unusualShip.setText(self.main_2['ed_d_unusualShip'])
            except Exception as e:
                log.error('Main 2 read Error', str(e))
                raise

    def main_3_read(self):
        if os.path.exists('config\\main3.json'):
            try:
                with open('config\\main3.json', 'r') as file:
                    self.main_3 = json.loads(file.read())
                pass
            except Exception as e:
                log.error('Main 3 read ERROR', str(e))
                raise

    def main_build_read(self):
        if os.path.exists('config\\build.json'):
            try:
                with open('config\\build.json', 'r') as file:
                    self.main_build = json.loads(file.read())
                windows_main.cb_build.setChecked(self.main_build['cb_build'])
                windows_main.ed_build_o.setValue(int(self.main_build['ed_build_o']))
                windows_main.ed_build_ammo.setValue(int(self.main_build['ed_build_ammo']))
                windows_main.ed_build_s.setValue(int(self.main_build['ed_build_s']))
                windows_main.ed_build_al.setValue(int(self.main_build['ed_build_al']))
                windows_main.cb_build_unusual.setChecked(self.main_build['cb_build_unusual'])
                windows_main.ed_build_unusual.setText(self.main_build['ed_build_unusual'])
                windows_main.cb_build_time.setChecked(self.main_build['cb_build_time'])
                if 'ed_time' in self.main_build:
                    windows_main.ed_time.setValue(self.main_build['ed_time'])
            except Exception as e:
                log.error('Main build read Error', str(e))
                raise
        else:
            windows_main.cb_build.setChecked(False)

    def main_other_read(self):
        if os.path.exists('config\\other.json'):
            try:
                with open('config\\other.json', 'r') as file:
                    data = json.loads(file.read())
                if "500stop" in data:
                    windows_main.cb_500stop.setChecked(data["500stop"])
                if "cb_rank" in data:
                    windows_main.cb_rank.setChecked(data['cb_rank'])
                if "cb_free_explore" in data:
                    windows_main.cb_free_explore.setChecked(data['cb_free_explore'])
                if "cb_free_shower" in data:
                    windows_main.cb_free_shower.setChecked(data['cb_free_shower'])
                if "cb_changeName" in data:
                    windows_main.cb_changeName.setChecked(data['cb_changeName'])
            except Exception as e:
                log.error('Main other read Error', str(e))
                raise

    def active_read(self):
        if os.path.exists('config\\active_code.json'):
            try:
                with open('config\\active_code.json', 'r') as file:
                    self.active_code = json.loads(file.read())
            except Exception as e:
                log.error('读取激活码失败', str(e))
                raise

    def active_write(self, username, code):
        try:
            with open('config\\active_code.json', 'w') as file:
                self.active_code[username] = code
                file.write(json.dumps(self.active_code))
        except Exception as e:
            log.error('写入激活码失败', str(e))
            raise


class Count:
    def __init__(self):
        self.SPOILS = 0
        self.FIGHT_COUNT = 1
        self.FINISH_COUNT = 2
        self.SHIP_COUNT = 3
        self.SL_COUNT = 4
        self.PATH_COUNT = 5

        self.now_time = time.strftime("%y%m%d", time.localtime(time.time()))

        self.count_data = {}
        self.spoils = 0
        self.fight_count = 0
        self.finish_count = 0
        self.ship_count = 0
        self.sl_count = 0
        self.path_count = 0

        self.other_count = {}
        self.read_count()

    def add_items(self, item, num):
        now_time = time.strftime("%y%m%d", time.localtime(time.time()))
        if now_time not in self.count_data:
            self.spoils = 0
            self.fight_count = 0
            self.finish_count = 0
            self.ship_count = 0
            self.sl_count = 0
            self.path_count = 0
            self.other_count = {}
        if item == self.SPOILS:
            self.spoils += num
        elif item == self.FIGHT_COUNT:
            self.fight_count += num
        elif item == self.FINISH_COUNT:
            self.finish_count += num
        elif item == self.SHIP_COUNT:
            self.ship_count += num
        elif item == self.SL_COUNT:
            self.sl_count += num
        elif item == self.PATH_COUNT:
            self.path_count += num
        self.save_count()
        self.read_count()
        self.refresh_table()

    def save_count(self):
        time_day = time.strftime("%y%m%d", time.localtime(time.time()))
        data = {
            'spoils': self.spoils,
            'fight_count': self.fight_count,
            'finish_count': self.finish_count,
            'ship_count': self.ship_count,
            'sl_count': self.sl_count,
            'other_count': self.other_count,
            'path_count': self.path_count
        }
        self.count_data[time_day] = data
        with open('count/count.json', 'w') as f:
            f.write(json.dumps(self.count_data))

    def read_count(self):
        time_day = time.strftime("%y%m%d", time.localtime(time.time()))
        if not os.path.exists('count'):
            os.mkdir('count')
        if os.path.exists('count/count.json'):
            with open('count/count.json', 'r') as f:
                self.count_data = json.loads(f.read())
        else:
            self.save_count()

        if time_day in self.count_data:  # 如果已经有数据
            data = self.count_data
            self.spoils = data[time_day]['spoils']
            self.fight_count = data[time_day]['fight_count']
            self.finish_count = data[time_day]['finish_count']
            self.ship_count = data[time_day]['ship_count']
            self.sl_count = data[time_day]['sl_count']
            self.other_count = data[time_day]['other_count']
            self.path_count = data[time_day]['path_count']
        else:
            data = self.count_data
            data[time_day] = {
                'spoils': self.spoils,
                'fight_count': self.fight_count,
                'finish_count': self.finish_count,
                'ship_count': self.ship_count,
                'sl_count': self.sl_count,
                'path_count': self.path_count,
                'other_count': self.other_count
            }

    def add_other(self, index, num):
        time_day = time.strftime("%y%m%d", time.localtime(time.time()))
        if time_day not in self.count_data:
            self.spoils = 0
            self.fight_count = 0
            self.finish_count = 0
            self.ship_count = 0
            self.sl_count = 0
            self.path_count = 0
            self.other_count = {}

        if index not in self.other_count:
            self.other_count[index] = num
        else:
            self.other_count[index] += num
        self.save_count()
        self.read_count()
        self.refresh_table()

    def refresh_table(self):
        windows_main.tb_count.clear()
        windows_main.tb_count.setRowCount(20)
        windows_main.tb_count.setColumnWidth(1, 50)
        windows_main.tb_count.setColumnWidth(3, 50)
        windows_main.tb_count.setEditTriggers(QAbstractItemView.NoEditTriggers)
        if len(self.other_count) > 6:
            windows_main.tb_count.setRowCount(len(self.other_count))
            windows_main.tb_count.setVerticalHeaderLabels([str(x) for x in list(range(len(self.other_count)))])
        else:
            windows_main.tb_count.setRowCount(6)
            windows_main.tb_count.setVerticalHeaderLabels([str(x) for x in list(range(6))])

        windows_main.tb_count.setColumnCount(4)
        windows_main.tb_count.setHorizontalHeaderLabels(['项目', '数量', '项目', '数量'])
        # 战斗数量
        windows_main.tb_count.setItem(0, 0, QTableWidgetItem('战斗数'))
        windows_main.tb_count.setItem(0, 1, QTableWidgetItem(str(self.fight_count)))
        # 节点数
        windows_main.tb_count.setItem(1, 0, QTableWidgetItem('节点数'))
        windows_main.tb_count.setItem(1, 1, QTableWidgetItem(str(self.path_count)))
        # 完成数
        windows_main.tb_count.setItem(2, 0, QTableWidgetItem('完成数'))
        windows_main.tb_count.setItem(2, 1, QTableWidgetItem(str(self.finish_count)))
        # 出船数
        windows_main.tb_count.setItem(3, 0, QTableWidgetItem('出船数'))
        windows_main.tb_count.setItem(3, 1, QTableWidgetItem(str(self.ship_count)))
        # SL数量
        windows_main.tb_count.setItem(4, 0, QTableWidgetItem('SL数'))
        windows_main.tb_count.setItem(4, 1, QTableWidgetItem(str(self.sl_count)))
        # 战利品数
        if self.spoils != 0:
            windows_main.tb_count.setItem(5, 0, QTableWidgetItem('战利品数'))
            windows_main.tb_count.setItem(5, 1, QTableWidgetItem(str(self.spoils)))
        i = 0
        if len(self.other_count) != 0:
            for cid, num in self.other_count.items():
                if int(cid) in RES:
                    windows_main.tb_count.setItem(i, 2, QTableWidgetItem(RES[int(cid)]))
                    windows_main.tb_count.setItem(i, 3, QTableWidgetItem(str(num)))
                    i += 1


def login():
    """
    功能:登录
    无返回值
    """

    def get_code(d):
        d = str(d).upper()
        d = re.sub("\d", "", d)
        d = d[:5]
        while len(d) < 5:
            d += "A"
        return d

    try:
        windows_main.show()  # 显示主界面
        windows_login.close()
        other_function.refresh_base_data()  # 刷新主要数据
        config_function.main_read()  # 读取配置文件
        windows_count_ship.ready()  # 初始化出船数据
        other_function.refresh_our_ship_data(gameData.fleet[0], gameData.fleetName[0])  # 初始化舰队数据
        other_function.continue_login_award()  # 进行签到
        th = threading.Thread(target=th_main.th_main_def, args=())  # 开启主进程
        count.refresh_table()  # 初始化基础统计数据
        battle_main.qh_upgrade_list()
        ti.show()
        th.start()
    except HmError as e:
        message = e.message
        QMessageBox.warning(windows_login, '错误', str(message), QMessageBox.Yes)
        log.error('Login Error:', e.message)
        return 0
    except Exception as e:
        QMessageBox.warning(windows_login, '错误', "脚本初始化失败\n错误代码:%s\n" % str(e), QMessageBox.Yes)
        log.error('Login Error:', str(e))
        return 0


def set_log(strs, i):
    windows_main.tv_nowDeal.setText(time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
    g.all_log += 1
    if g.all_log > 1000:
        windows_main.lt_log_detail.clear()
    if i == 1:
        windows_main.lt_log_detail.insertItem(0, time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
    elif i == 0:
        windows_main.lt_log_detail.insertItem(0,
                                              time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
        windows_main.lt_log_classical.insertItem(0, time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(
            strs))
        windows_main.tv_nowDeal.setText(time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
    elif i == 3:
        windows_main.lt_log_detail.insertItem(0,
                                              time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
        windows_main.lt_log_classical.insertItem(0, time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(
            strs))
        windows_main.lt_log_imp.insertItem(0,time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))
        windows_main.tv_nowDeal.setText(time.strftime('%H:%M:%S', time.localtime(time.time())) + " " + str(strs))


def login_windows():
    # -------这里插入响应事件------------
    # ----main----
    windows_main.bt_d_back.clicked.connect(lambda: windows_main.sw_mian.setCurrentIndex(0))  # 返回主界面
    windows_main.bt_count_ship.clicked.connect(lambda: windows_count_ship.show())
    windows_main.bt_add_qh.clicked.connect(battle_main.qh_add_ship)

    windows_main.bt_rw_up.clicked.connect(th_main.list_change)  # 任务上移
    windows_main.bt_rw_del.clicked.connect(th_main.list_del)

    windows_main.bt_pay.clicked.connect(pay.onShow)

    windows_main.bt_getLog.clicked.connect(lambda: OtherFunction.get_log(windows_main))

    # ----login----
    # ----rw-------
    windows_rw.ed_point.textChanged.connect(rw_function.point_change)
    windows_rw.cb_map.currentIndexChanged.connect(rw_function.map_change)
    windows_rw.bt_detail_1.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_2.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_3.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_4.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_5.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_6.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_7.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_8.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_9.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_10.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_11.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_12.clicked.connect(rw_function.show_detail)
    windows_rw.bt_detail_13.clicked.connect(rw_function.show_detail)
    windows_rw.ed_name.setClearButtonEnabled(True)
    windows_rw.ed_point.setClearButtonEnabled(True)

    windows_rw.bt_saveRw.clicked.connect(rw_function.write_config)
    windows_rw.bt_readRw.clicked.connect(rw_function.read_config)
    windows_rw.bt_delRw.clicked.connect(rw_function.del_config)
    # ----rw_detail-------
    windows_rw_detail.bt_save.clicked.connect(rw_function.save_detail)

    # ----rw_start-------
    windows_main.bt_add_battle.clicked.connect(lambda: th_main.list_add_battle(0))
    windows_main.bt_add_pvp.clicked.connect(lambda: th_main.list_add_pvp(0))
    windows_main.bt_add_campaign.clicked.connect(lambda: th_main.list_add_campaign(0))

    windows_add_battle.bt_start.clicked.connect(lambda: th_main.list_add_battle(1))
    windows_add_pvp.bt_pvp_run.clicked.connect(lambda: th_main.list_add_pvp(1))
    windows_add_campaign.bt_cm_run.clicked.connect(lambda: th_main.list_add_campaign(1))


    windows_add_pvp.cb_fleet.currentIndexChanged.connect(
        lambda: other_function.upgrade_add_pvp_fleet(gameData.fleet[windows_add_pvp.cb_fleet.currentIndex()]))

    windows_add_battle.bt_SetRw.clicked.connect(rw_function.show_rw)
    # -------这里插入配置事件------------
    other_function.check_upgrade()
    windows_login.first_login()
    # -------------------------------------


# 实例化对象
app = QtWidgets.QApplication(sys.argv)

windows_main = WindowsMain()
log.windows = windows_main
windows_rw = WindowsRw()
windows_count_ship = WindowsCountShip()
windows_mine = WindowsMineShip()
pay = WindowsPay()
th_main = ThMain()
other_function = OtherFunction()
windows_user_fleet = WindowsUserFleet()
windows_rw_detail = WindowsRwDetail()
windows_login = WindowsLogin()
gameLogin = GameLogin()
windows_add_battle = WindowsAddBattle()
windows_add_pvp = WindowsAddPVP()
windows_add_campaign = WindowsAddCampaign()

ti = TrayIcon(windows_main)
count = Count()
rw_function = RwFunction()
battle_main = BattleMain()
campaign_main = CampaignMain()
pvp_main = PvpMain()
config_function = ConfigFunction()
login_windows()  # 启动加载页面与关联方法
sys.exit(app.exec_())
