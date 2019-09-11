# -*- coding: utf-8 -*-
import os
import json
import time
import logging
import win32api
import win32con

VERSION = 0.70
RES = {2: '油', 3: '弹', 4: '钢', 9: '铝', 10141: "航母核心", 10241: '战列核心', 10341: '巡洋核心', 10441: '驱逐核心',
       10541: '潜艇核心', 141: '快速建造', 241: '建造蓝图', 541: '快速修理', 741: '装备蓝图', 66641: '损管'}

HEADER = {'Accept-Encoding': 'identity',
          'Connection': 'Keep-Alive',
          'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 5.1.1; mi max Build/LMY48Z)'}


class G:
    def __init__(self):
        self.repair_time_limit = 0
        self.all_log = 0



g = G()


class InitData:
    def __init__(self):
        self.init_out_data = False
        self.init_version = None
        self.init_data = dict()
        self.ship_cid = dict()
        self.ship_cid_wu = dict()
        self.error_code = dict()
        self.error_code_1 = dict()
        self.handbook_id = dict()
        self.new_init_version = None
        self.ship_equipmnt = {}
        self.res_url = ""

    def read_init(self):
        if not os.path.exists('data'):
            os.mkdir('data')
        if os.path.exists('data/init.json'):
            with open('data/init.json', 'r') as f:
                data = f.read()
            self.init_data = json.loads(data)
            self.init_version = self.init_data['DataVersion']
            if "res_url" in self.init_data:
                self.res_url = self.init_data["res_url"]
            # 领导船只cid数据
            for each_ship in self.init_data['shipCard']:
                self.ship_cid[each_ship['cid']] = each_ship
            # 普通船只cid数据
            for each_ship in self.init_data['shipCardWu']:
                self.ship_cid_wu[each_ship['cid']] = each_ship
            # 错误代码
            self.error_code_1 = self.init_data['errorCode']
            for code, message in self.error_code_1.items():
                self.error_code[int(code)] = message
            # 图鉴代号
            for each_ship in self.init_data['shipCard']:
                if 'shipIndex' in each_ship:
                    self.handbook_id[each_ship['cid']] = each_ship['shipIndex']
            # 装备属性
            for equipment in self.init_data['shipEquipmnt']:
                self.ship_equipmnt[equipment["cid"]] = equipment



class Logger:
    def __init__(self, clevel=logging.DEBUG, flevel=logging.DEBUG):
        self.windows = None
        times = time.strftime("%m-%d-%H-%M-%S", time.localtime())
        path = 'log/' + times + '.log'
        self.path = path
        if not os.path.exists('log'):
            os.mkdir('log')
        with open(path, 'w') as f:
            f.write('')
        self.logger = logging.getLogger('Main')
        self.logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')
        # 设置CMD日志
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(clevel)
        # 设置文件日志
        fh = logging.FileHandler(path)
        fh.setFormatter(fmt)
        fh.setLevel(flevel)
        self.logger.addHandler(sh)
        self.logger.addHandler(fh)

    def debug(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.debug(" ".join(arg))

    def info(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.info(" ".join(arg))

    def war(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.warning(" ".join(arg))

    def error(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.error(" ".join(arg))

    def cri(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.critical(" ".join(arg))

    def d(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.debug(" ".join(arg))

    def i(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.info(" ".join(arg))

    def w(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.warning(" ".join(arg))

    def e(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.error(" ".join(arg))

    def c(self, *kwargs):
        arg = [str(x) for x in kwargs]
        self.logger.critical(" ".join(arg))

    @staticmethod
    def get_desktop():
        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                  r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 0,
                                  win32con.KEY_READ)
        return win32api.RegQueryValueEx(key, 'Desktop')[0]

    def get_log(self):
        try:
            with open(self.path, 'r') as f:
                with open(self.get_desktop() + "/护萌宝{}.log".format(
                        time.strftime("%m-%d-%H-%M-%S", time.localtime())), 'w') as f2:
                    f2.write(f.read())
        except Exception as e:
            log.e("导出日志错误", e)


log = Logger(logging.DEBUG, logging.DEBUG)
init_data = InitData()


