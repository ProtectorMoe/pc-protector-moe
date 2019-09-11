# -*- coding: utf-8 -*-
import zlib
import hashlib
import json
import time
from Error import *
from Constant import *
import os
from Net import *

is_write = True


class GameData:
    def __init__(self):
        """
        功能：定义初始变量
        """
        self.login_name = ""


        self.allData = {}
        self.userDetail = {}

        self.res_url = ""
        # other
        self.is_first_login = True
        # 登陆数据
        self.cookies = None
        self.headers = None
        self.version = None
        self.server = None
        self.channel = None
        # 玩家数据
        self.main_data = dict()
        self.uid = 0
        self.username = None
        self.level = 0
        self.exp = 0
        self.nextExp = 0

        # 玩家资源
        self.gold = 0
        self.oil = 0  # 油
        self.ammo = 0  # 弹
        self.steel = 0  # 弹
        self.aluminium = 0  # 铝
        self.shipNumTop = 0

        self.oilFirst = 0  # 油
        self.ammoFirst = 0  # 弹
        self.steelFirst = 0  # 弹
        self.aluminiumFirst = 0  # 铝
        self.fastRepairFirst = 0  # 快修

        self.oilChange = 0  # 油
        self.ammoChange = 0  # 弹
        self.steelChange = 0  # 弹
        self.aluminiumChange = 0  # 铝
        self.fastRepairChange = 0  # 快修

        self.fastRepair = 0
        self.fastRepairFirst = 0
        self.fastBuild = 0
        self.shipBlueMap = 0
        self.equipmentMap = 0
        self.cvCube = 0
        self.bbCube = 0
        self.clCube = 0
        self.ddCube = 0
        self.ssCube = 0

        self.exploreInfo = []
        self.taskInfo = {}

        self.startTime = 0
        self.login_award = 0

        # 战役
        self.campaignTotal = 0
        self.campaignRemainNum = 0
        self.campaignMap = []

        # 建造开发
        self.dock = []
        self.repairDock = []
        self.equipmentDock = []

        # 请求榜单
        self.rank_count = 0
        self.rank = {}

        # 玩家队伍
        self.fleet = {0: [0, 0, 0, 0, 0, 0],
                      1: [0, 0, 0, 0, 0, 0],
                      2: [0, 0, 0, 0, 0, 0],
                      3: [0, 0, 0, 0, 0, 0],
                      4: [0, 0, 0, 0, 0, 0],
                      5: [0, 0, 0, 0, 0, 0],
                      6: [0, 0, 0, 0, 0, 0],
                      7: [0, 0, 0, 0, 0, 0]
                      }
        self.fleetName = {0: "第一舰队", 1: "第二舰队", 2: "第三舰队", 3: "第四舰队"}
        # 玩家船只数据
        self.allShip = {}
        self.allEquipment = {}
        self.allPoint = {}
        self.allLevel = {}
        self.unlockShip = []
        self.package = {}

        self.mine = {}

    def get_mine_version(self):
        url = 'http://www.simonkimi.top/'
        try:
            session.get("http://monster.gostats.cn/bin/count/a_507596/t_5/i_1/counter.png", timeout=5)
            self.mine = json.loads(session.get(url=url, timeout=5).text)
        except Exception as e:
            print('Check upgrade Error:', e)

    def get_data(self, version, cookies, server, channel):
        self.cookies = cookies
        self.version = version
        self.server = server
        self.channel = channel
        self.get_campaign_data()
        self.get_user_data()
        self.get_pve_data()
        self.get_activity_point()

    def get_campaign_data(self):
        """
        功能：获取战役信息
        无返回值
        """
        print('Getting campaign data...')
        try:
            user_data = zlib.decompress(
                session.get(url=self.server + 'campaign/getUserData/' + self.get_url_end(), headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            user_data = json.loads(user_data)
            error_find(user_data)
            self.campaignTotal = user_data['passInfo']['totalNum']
            self.campaignRemainNum = user_data['passInfo']['remainNum']
            self.campaignMap = user_data['canCampaignChallengeLevel']

            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_campaign_data.json', 'w') as f:
                    f.write(json.dumps(user_data))
            return user_data
        except HmError as e:
            print('Get campaign data FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get campaign data FAILED! Reason:', e)
            raise

    def remove_ship(self, fleet):
        temp = {}
        fleet2 = [int(x) for x in fleet]
        for ids, data in self.allShip.items():
            if ids not in fleet2:
                temp[int(ids)] = data
        self.allShip.clear()
        self.allShip = temp
        return len(self.allShip)

    @staticmethod
    def add_ship(id, data):
        if id in gameData.allShip:
            raise Exception("船只重复!")
        else:
            gameData.allShip[int(id)] = data

    def get_user_data(self):
        """
        功能：首次登陆获取信息
        无返回值
        """
        print('Getting user data...')
        try:
            user_data = zlib.decompress(
                session.get(url=self.server + 'api/initGame?&crazy=0' + self.get_url_end(), headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            user_data = json.loads(user_data)
            error_find(user_data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/user_data.json', 'w') as f:
                    f.write(json.dumps(user_data))
            self.allData = user_data

            if "detailInfo" in user_data["userVo"]:
                self.userDetail = user_data["userVo"]["detailInfo"]

            self.uid = user_data['userVo']['uid']
            self.username = user_data['userVo']['username']
            self.level = user_data['userVo']['level']
            self.shipNumTop = user_data['userVo']['shipNumTop']
            self.exp = user_data['userVo']['exp']
            self.nextExp = user_data['userVo']['nextExp']

            self.upgrade_fleet(user_data)

            self.oil = user_data['userVo']['oil']
            self.ammo = user_data['userVo']['ammo']
            self.steel = user_data['userVo']['steel']
            self.aluminium = user_data['userVo']['aluminium']

            self.login_award = user_data['marketingData']['continueLoginAward']['canGetDay']
            self.main_data = user_data

            self.startTime = user_data['systime']

            self.exploreInfo.clear()
            for eachExplore in user_data['pveExploreVo']['levels']:
                self.exploreInfo.append(eachExplore)

            self.taskInfo.clear()
            for eachTask in user_data['taskVo']:
                self.taskInfo[eachTask['taskCid']] = eachTask

            self.allShip.clear()
            for eachShip in user_data['userShipVO']:
                self.allShip[eachShip['id']] = eachShip

            self.allEquipment.clear()
            for eachEquipment in user_data['equipmentVo']:
                self.allEquipment[eachEquipment['equipmentCid']] = eachEquipment

            self.package.clear()
            for eachPackage in user_data['packageVo']:
                self.package[eachPackage['itemCid']] = eachPackage['num']

            self.unlockShip.clear()
            for eachUnlockShip in user_data["unlockShip"]:
                self.unlockShip.append(int(eachUnlockShip))

            self.dock = user_data['dockVo']
            self.equipmentDock = user_data['equipmentDockVo']
            self.repairDock = user_data['repairDockVo']

            if 541 in self.package:
                self.fastRepair = int(self.package[541])
            if 141 in self.package:
                self.fastBuild = int(self.package[141])
            if 741 in self.package:
                self.equipmentMap = int(self.package[741])
            if 241 in self.package:
                self.shipBlueMap = int(self.package[241])

            if 10141 in self.package:
                self.cvCube = int(self.package[10141])
            if 10241 in self.package:
                self.bbCube = int(self.package[10241])
            if 10341 in self.package:
                self.clCube = int(self.package[10341])
            if 10441 in self.package:
                self.ddCube = int(self.package[10441])
            if 10541 in self.package:
                self.ssCube = int(self.package[10541])

            if self.is_first_login is True:
                self.oilFirst = self.oil
                self.ammoFirst = self.ammo
                self.steelFirst = self.steel
                self.aluminiumFirst = self.aluminium
                self.fastRepairFirst = self.fastRepair
                self.is_first_login = False

            print('Get user data success!')
        except HmError as e:
            print('Get user data FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Get user data FAILED! Reason:', Error_information)
            raise

    def get_activity_point(self):
        print('Get_activity_point')
        try:
            pve_data = zlib.decompress(
                session.get(url=self.server + 'pevent/getPveData/' + self.get_url_end(), headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            pve_data = json.loads(pve_data)
            error_find(pve_data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/peventGetPveData.json', 'w') as f:
                    f.write(json.dumps(pve_data))

            if type(pve_data) == dict:
                if "pveNode" in pve_data:
                    for eachPoint in pve_data['pveNode']:
                        self.allPoint[int(eachPoint['id'])] = eachPoint

                if "pveEventLevel" in pve_data:
                    for level in pve_data['pveEventLevel']:
                        self.allLevel[int(level['id'])] = level

            print('Get pve data success!')
        except HmError as e:
            print('Get ship info FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get ship info FAILED! Reason:', e)
            raise

    def get_pve_data(self):
        print('Getting pve data...')
        try:
            pve_data = zlib.decompress(
                session.get(url=self.server + 'pve/getPveData/' + self.get_url_end(), headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            pve_data = json.loads(pve_data)
            error_find(pve_data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_pve_data.json', 'w') as f:
                    f.write(json.dumps(pve_data))
            for eachPoint in pve_data['pveNode']:
                self.allPoint[int(eachPoint['id'])] = eachPoint
            for level in pve_data['pveLevel']:
                self.allLevel[int(level['id'])] = level
            print('Get pve data success!')
        except HmError as e:
            print('Get ship info FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get ship info FAILED! Reason:', e)
            raise

    def get_rank_list(self):
        print('Getting rank list...')
        try:
            if self.rank_count / 8 == int(self.rank_count / 8):
                self.rank = zlib.decompress(
                    session.get(url=self.server + 'rank/getData/' + self.get_url_end(), headers=HEADER,
                                cookies=self.cookies, timeout=10).content)
                self.rank = json.loads(self.rank)
                error_find(self.rank)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_rank_list.json', 'w') as f:
                    f.write(json.dumps(self.rank))
            print('Get rank list success!')
            self.rank_count += 1
            return self.rank
        except HmError as e:
            print('Get rank list FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get rank list FAILED! Reason:', e)
            raise

    def get_ocean_data(self, node):
        """
        功能：获取活动数据
        返回值：dict
        """
        try:
            url = self.server + 'guard/getLevelNode/' + node + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_ocean_data.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get ocean data FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Get ocean data FAILED! Reason:', Error_information)
            raise

    def get_ocean_level(self):
        """
        功能：获取活动数据
        返回值：dict
        """
        try:
            url = self.server + 'guard/getConfig/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if "pveEventLevel" in data:
                for level in data['pveEventLevel']:
                    self.allLevel[int(level['id'])] = level
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_ocean_data.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get ocean data FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Get ocean data FAILED! Reason:', Error_information)
            raise

    def set_ocean_fleet(self, fleet, node):
        """
        功能：获取活动数据
        返回值：dict
        """
        try:
            url = self.server + 'pevent/setFleet/{}/{}/'.format(str(node), str(fleet)) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if "pveEventLevel" in data:
                for level in data['pveEventLevel']:
                    self.allLevel[int(level['id'])] = level
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_ocean_data.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get ocean data FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Get ocean data FAILED! Reason:', Error_information)
            raise

    def upgrade_ship(self, ids, jsons):
        """
        功能：新添加一个船只数据
        :param ids: 船只id
        :param jsons: 船只数据
        :return: None
        """
        self.allShip[ids] = jsons

    def upgrade_point(self, data):
        """
        功能：更新活动点信息
        """
        for eachPoint in data['oceanNode']:
            self.allPoint[int(eachPoint['id'])] = eachPoint

    def upgrade_level(self, data):
        """
        功能：更新活动点信息
        """
        for eachLevel in data['oceanLevel']:
            self.allLevel[int(eachLevel['id'])] = eachLevel

    def upgrade_equipment(self, data):
        self.allEquipment.clear()
        for eachEquipment in data['equipmentVo']:
            self.allEquipment[eachEquipment['equipmentCid']] = eachEquipment

    def upgrade_fleet(self, user_data):
        if "fleetVo" in user_data:
            self.fleet[0] = user_data['fleetVo'][0]['ships']
            self.fleet[1] = user_data['fleetVo'][1]['ships']
            self.fleet[2] = user_data['fleetVo'][2]['ships']
            self.fleet[3] = user_data['fleetVo'][3]['ships']
            self.fleet[4] = user_data['fleetVo'][4]['ships']
            self.fleet[5] = user_data['fleetVo'][5]['ships']
            self.fleet[6] = user_data['fleetVo'][6]['ships']
            self.fleet[7] = user_data['fleetVo'][7]['ships']

            self.fleetName[0] = user_data['fleetVo'][0]['title']
            self.fleetName[1] = user_data['fleetVo'][1]['title']
            self.fleetName[2] = user_data['fleetVo'][2]['title']
            self.fleetName[3] = user_data['fleetVo'][3]['title']

    def get_refresh_data(self):
        """
        功能：回到港口内容刷新
        无返回值
        """
        print('Getting refresh data...')
        try:
            session.get(url=self.server + 'bsea/getData/' + self.get_url_end(), headers=HEADER, cookies=self.cookies, timeout=10)
            session.get(url=self.server + 'live/getUserInfo' + self.get_url_end(),
                        headers=HEADER, cookies=self.cookies, timeout=10)
            session.get(url=self.server + 'active/getUserData/' + self.get_url_end(),
                        headers=HEADER, cookies=self.cookies, timeout=10)
            session.get(url=self.server + 'pve/getUserData/' + self.get_url_end(),
                        headers=HEADER, cookies=self.cookies, timeout=10)
            session.get(url=self.server + 'campaign/getUserData/' + self.get_url_end(),
                        headers=HEADER, cookies=self.cookies, timeout=10)
        except HmError as e:
            print('Get refresh data FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get refresh data FAILED! Reason:', e)
            raise

    def get_url_end(self):
        """
        功能：返回url尾部
        返回值：文本型
        """
        url_time = str(int(round(time.time() * 1000)))
        md5_raw = url_time + 'ade2688f1904e9fb8d2efdb61b5e398a'
        md5 = hashlib.md5(md5_raw.encode('utf-8')).hexdigest()
        url_end = '&t={time}&e={key}&gz=1&market=2&channel={channel}&version={version}'
        url_end_dict = {'time': url_time, 'key': md5, 'channel': self.channel, 'version': self.version}
        url_end = url_end.format(**url_end_dict)
        return url_end


gameData = GameData()
