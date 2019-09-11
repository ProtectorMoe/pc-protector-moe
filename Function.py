# -*- coding: utf-8 -*-
from Data import *
from Error import *
import json
import hashlib
import zlib
import time
import random
import os
from urllib.request import quote
from Net import *

is_write = True


class GameFunction:
    def __init__(self):
        self.cookies = None
        self.version = None
        self.server = None
        self.channel = None

    def start_game_function(self, version, cookies, server, channel):
        self.cookies = cookies
        self.version = version
        self.server = server
        self.channel = channel

    def get_init_data(self, res_url, end):
        """
        获取init数据
        :return:
        """
        try:
            print("请求新的res数据")
            user_data = zlib.decompress(
                session.get(url=res_url + end,
                            headers=HEADER, timeout=30).content)
            user_data = json.loads(user_data)
            user_data["res_url"] = res_url
            user_data = json.dumps(user_data)
            return user_data
        except Exception as e:
            log.e("获取init数据出错", e)
            raise

    def login_award(self):
        """
        功能：获取签到奖励
        :return:dict
        """
        try:
            log.debug("Login award:", "")
            url = self.server + 'active/getLoginAward/c3ecc6250c89e88d83832e3395efb973/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/login_award.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Start challenge FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Start challenge FAILED! Reason:', e)
            raise

    def challenge_start(self, maps, team, head="pve"):
        """
        功能：开始出征
        返回值：dict
        """

        try:
            url = self.server + '{head}/cha11enge/{map}/{team}/0/'.format(map=maps, team=team, head=head) + self.get_url_end()
            log.debug("Start challenge:", "{head}/cha11enge/{map}/{team}".format(map=maps, team=team, head=head))
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_start.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Start challenge FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Start challenge FAILED! Reason:', e)
            raise

    def challenge_new_next(self, head="pve"):
        """
        功能：下一点
        返回值：bytes
        """
        try:
            url = self.server + '{head}/newNext/'.format(head=head) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_new_next.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('New next FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('New next FAILED! Reason:', Error_information)
            raise

    def challenge_fight(self, maps, team, formats, head="pve"):
        """
        功能：开始战斗
        返回值：dict
        """
        try:
            arg = self.str_arg(maps=maps, team=team, formats=formats, head=head)
            log.debug("Challenge fight", arg)
            url = self.server + '{head}/dealto/{maps}/{team}/{formats}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.post(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10, data={'pve_level': 1, 'pid': random.randint(1000000, 2000000)}).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_fight.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Challenge fight FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Challenge fight FAILED! Reason:', e)
            raise

    def challenge_get_result(self, is_night_fight, head="pve"):
        """
        功能：取战斗结果
        返回值：dict
        """
        # isNightFight:是否夜战，是：1，不是：0
        try:
            url = self.server + '{head}/getWarResult/'.format(head=head) + str(is_night_fight) + '/' + self.get_url_end()
            log.debug("Get Result", url)
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_get_result.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get Result FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get Result FAILED! Reason:', e)
            raise

    def challenge_skip_war(self, head="pve"):
        """
        功能：迂回
        返回值：dict
        """
        try:
            url = self.server + '{head}/SkipWar/'.format(head=head) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_skip_war.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except Exception as e:
            print('Skip war FAILED! Reason:', e)
            raise

    def challenge_spy(self, head="pve"):
        """
                功能：索敌
                返回值：dict
        """
        try:
            url = self.server + '{head}/spy/'.format(head=head) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/challenge_spy.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Spy FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Spy FAILED! Reason:', e)
            raise

    def repair(self, ship):
        """
        功能：修理
        返回值：dict
        """
        try:
            wait = [str(x) for x in ship]
            url = self.server + 'boat/instantRepairShips/[' + ','.join(wait) + ']/' + self.get_url_end()
            log.debug("Repair:", ','.join(wait))
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if 'packageVo' in data:
                gameData.fastRepair = data['packageVo'][0]['num']
            if "userVo" in data:
                gameData.oil = data['userVo']['oil']
                gameData.steel = data['userVo']['steel']
                gameData.ammo = data['userVo']['ammo']
                gameData.aluminium = data['userVo']['aluminium']

            if is_write and os.path.exists('requestsData'):
                with open('requestsData/repair.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Repair FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Repair FAILED! Reason:', e)
            raise

    def strengthen(self, ids, ship):
        """
        功能：强化
        返回值：dict
        """
        try:
            wait = [str(x) for x in ship]
            arg = self.str_arg(ids=str(ids), ship=','.join(wait))
            url = self.server + 'boat/strengthen/{ids}/[{ship}]/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/strengthen.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Repair FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Repair FAILED! Reason:', e)
            raise

    def shower(self, ship):
        """
        功能：修理
        返回值：dict
        """
        try:
            arg = self.str_arg(ship=ship)
            url = self.server + 'boat/repair/{ship}/0/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/shower.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Shower FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Shower FAILED! Reason:', e)
            raise

    def rubdown(self, ship):
        """
        功能：修理
        返回值：dict
        """
        try:
            arg = self.str_arg(ship=ship)
            url = self.server + 'boat/rubdown/{ship}'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/rubdown.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Rubdown FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Rubdown FAILED! Reason:', e)
            raise

    def repair_complete(self, ids, ship):
        """
        功能：出浴
        返回值：dict
        """
        try:
            arg = self.str_arg(ship=ship, ids=ids)
            url = self.server + 'boat/repairComplete/{ids}/{ship}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/repair_complete.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('RepairComplete FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('RepairComplete FAILED! Reason:', e)
            raise

    def supply(self, ship):
        """
                功能：快速补给
                返回值：dict
        """
        try:
            wait = []
            for each in ship:
                wait.append(str(each))
            url = self.server + 'boat/supplyBoats/[' + ','.join(wait) + ']/0/0/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/supply.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Fast supply FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Fast supply FAILED! Reason:', Error_information)
            raise

    def dismantle(self, ship, is_save):
        """
        功能：分解
        返回值：dict
        """
        try:
            url = self.server + 'dock/dismantleBoat/[' + ','.join(ship) \
                  + ']/' + str(is_save) + '/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/dismantle.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Decompose FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Decompose FAILED! Reason:', e)
            raise

    def get_explore(self, maps):
        """
        功能：收远征
        返回值：bytes
        """
        try:
            arg = self.str_arg(maps=maps)
            url = self.server + 'explore/getResult/{maps}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_explore.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get explore FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get explore FAILED! Reason:', e)
            raise

    def get_task(self, cid):
        """
        功能：收任务
        返回值：bytes
        """
        try:
            arg = self.str_arg(cid=cid)
            url = self.server + 'task/getAward/{cid}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_task.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get explore FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Get explore FAILED! Reason:', e)
            raise

    def start_explore(self, maps, team):
        """
        功能：开始远征
        返回值：bytes
        """
        try:
            arg = self.str_arg(maps=maps, team=team)
            url = self.server + 'explore/start/{team}/{maps}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/start_explore.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Start explore FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Start explore FAILED! Reason:', Error_information)
            raise

    def lock_ship(self, ship):
        """
        功能：开始远征
        返回值：bytes
        """
        try:
            url = self.server + 'boat/lock/{ship}/'.format(ship=str(ship)) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER, cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/lock_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Lock ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Lock ship FAILED! Reason:', Error_information)
            raise

    def campaign_get_fleet(self, maps):
        """
        获取用户战役船只信息
        :return:
        """
        try:
            url = self.server + 'campaign/getFleet/{maps}/'.format(maps=str(maps)) + self.get_url_end()
            data = zlib.decompress(
                 session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/campaign_get_fleet.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Skip war FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Skip war FAILED! Reason:', e)
            raise

    def campaign_get_spy(self, maps):
        """
        获取用户战役船只信息
        :return:
        """
        try:
            url = self.server + 'campaign/spy/{maps}/'.format(maps=str(maps)) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/campaign_get_spy.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Campaign spy FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Campaign spy FAILED! Reason:', e)
            raise

    def campaign_fight(self, maps, formats):
        """
        获取用户战役船只信息
        :return:
        """
        try:
            arg = self.str_arg(maps=maps, formats=formats)
            url = self.server + 'campaign/challenge/{maps}/{formats}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/campaign_fight.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Campaign fight FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Campaign fight FAILED! Reason:', Error_information)
            raise

    def campaign_get_result(self, is_night_fight):
        """
        功能：取战斗结果
        返回值：dict
        """
        # isNightFight:是否夜战，是：1，不是：0
        try:
            url = self.server + 'campaign/getWarResult/{0}/'.format(str(is_night_fight)) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/campaign_get_result.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Campaign get result FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Campaign get result FAILED! Reason:', e)
            raise

    def pvp_get_list(self):
        """
                功能：取演习列表
                返回值：dict
                """
        try:
            url = self.server + 'pvp/getChallengeList/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)

            if is_write and os.path.exists('requestsData'):
                with open('requestsData/pvp_list.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('PVP get list FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('PVP get list FAILED! Reason:', e)
            raise

    def pvp_spy(self, uid, fleet):
        """
                功能：取演习列表
                返回值：dict
                """
        try:
            arg = self.str_arg(uid=uid, fleet=fleet)
            url = self.server + 'pvp/spy/{uid}/{fleet}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/pvp_spy.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('PVP spy FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('PVP spy FAILED! Reason:', e)
            raise


    def pvp_fight(self, uid, fleet, formats):
        """
        功能：取演习列表
        返回值：dict
        """
        try:
            arg = self.str_arg(uid=uid, fleet=fleet, formats=formats)
            url = self.server + 'pvp/challenge/{uid}/{fleet}/{formats}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/pvp_fight.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('PVP fight FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('PVP fight FAILED! Reason:', Error_information)
            raise

    def pvp_get_result(self, is_night_fight):
        """
        功能：取战斗结果
        返回值：dict
        """
        # isNightFight:是否夜战，是：1，不是：0
        try:
            url = self.server + 'pvp/getWarResult/{0}/'.format(str(is_night_fight)) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/PVP_get_result.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('PVP get Result FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('PVP get Result FAILED! Reason:', Error_information)
            raise

    def build_ship(self, dock, oil, ammo, steel, aluminium):
        """
        功能：建造船只
        返回值：dict
        """
        #
        try:
            arg = self.str_arg(dock=dock, oil=oil, ammo=ammo, steel=steel, aluminium=aluminium)
            url = self.server + 'dock/buildBoat/{dock}/{oil}/{steel}/{ammo}/{aluminium}'.format(
                **arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/Build_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build ship FAILED! Reason:', Error_information)
            raise

    def build_equipment(self, dock, oil, ammo, steel, aluminium):
        """
        功能：开发装备
        返回值：dict
        """
        #
        try:
            arg = self.str_arg(dock=dock, oil=oil, ammo=ammo, steel=steel, aluminium=aluminium)
            url = self.server + 'dock/buildEquipment/{dock}/{oil}/{steel}/{ammo}/{aluminium}'.format(
                **arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/Build_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build equipment FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build equipment FAILED! Reason:', Error_information)
            raise

    def build_get_ship(self, dock):
        """
        功能：收船
        返回值：dict
        """
        try:
            arg = self.str_arg(dock=dock)
            url = self.server + 'dock/getBoat/{dock}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/build_get_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build get ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build get ship FAILED! Reason:', Error_information)
            raise

    def build_get_equipment(self, dock):
        """
        功能：收装备
        返回值：dict
        """
        try:
            arg = self.str_arg(dock=dock)
            url = self.server + 'dock/getEquipment/{dock}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/build_get_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build get equipment FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build get equipment FAILED! Reason:', Error_information)
            raise

    def build_instant_ship(self, dock):
        """
        功能：快速建造
        返回值：dict
        """
        try:
            arg = self.str_arg(dock=dock)
            url = self.server + 'dock/instantBuild/{dock}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/build_instant_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build instant ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build instant ship FAILED! Reason:', Error_information)
            raise

    def build_instant_equipment(self, dock):
        """
        功能：快速开发
        返回值：dict
        """
        try:
            arg = self.str_arg(dock=dock)
            url = self.server + 'dock/instantEquipmentBuild/{dock}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/build_instant_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Build instant equipment FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Build instant equipment FAILED! Reason:', Error_information)
            raise

    def change_ship(self, fleet, ids, path):
        """
        功能：换船
        返回值：dict
        """
        try:
            arg = self.str_arg(fleet=fleet, ids=ids, path=path)
            url = self.server + 'boat/changeBoat/{fleet}/{ids}/{path}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/change_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Change ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Change ship FAILED! Reason:', Error_information)
            raise

    def remove_ship(self, fleet, path):
        """
        功能：换船
        返回值：dict
        """
        try:
            arg = self.str_arg(fleet=fleet, path=path)
            url = self.server + 'boat/removeBoat/{fleet}/{path}/'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/remove_ship.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Remove ship FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Change ship FAILED! Reason:', Error_information)
            raise

    def remove_equipment(self, ids, path):
        """
        功能：移除装备
        返回值：dict
        """
        try:
            arg = self.str_arg(ids=ids, path=path)
            url = self.server + 'boat/removeEquipment/{ids}/{path}'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/remove_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Remove equipment FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Remove equipment FAILED! Reason:', Error_information)
            raise

    def change_equipment(self, ids, cid, path):
        """
        功能：更换装备
        返回值：dict
        """
        try:
            arg = self.str_arg(ids=ids, path=path, cid=cid)
            url = self.server + 'boat/changeEquipment/{ids}/{cid}/{path}'.format(**arg) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/change_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Change equipment FAILED! Reason:', e.message)
            raise
        except Exception as e:
            print('Change equipment FAILED! Reason:', e)
            raise

    def rename(self, ids, new_name):
        """
        功能：改名
        返回值：dict
        """
        try:
            arg = self.str_arg(ids=ids, new_name=new_name)
            url = self.server + 'boat/renameShip/{ids}/{new_name}/'.format(**arg) + self.get_url_end()
            url = quote(url, safe=";/?:@&=+$,", encoding="utf-8")
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                             cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/rename.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Rename FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Rename FAILED! Reason:', Error_information)
            raise

    def dismantle_equipment(self, cid, num):
        """
         功能：分解装备
         返回值：dict
         """
        try:
            url = self.server + 'dock/dismantleEquipment/' + self.get_url_end()
            data = '{' + '"{}":{}'.format(str(cid), str(num)) + '}'
            data = zlib.decompress(
                session.post(url=url, headers=HEADER, cookies=self.cookies, data={"content": data}, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/dismantle_equipment.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Dismantle equipment FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Dismantle equipment FAILED! Reason:', Error_information)
            raise

    def get_active_data(self):
        """
                功能：收装备
                返回值：dict
                """
        try:
            url = self.server + 'ocean/getCIAList/' + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/get_active_data.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Get active data FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Get active data FAILED! Reason:', Error_information)
            raise

    def instant_fleet(self, fleet, ship):

        try:

            ships = "[" + ",".join([str(x) for x in ship]) + "]"
            args = self.str_arg(fleet=fleet, ships=ships)
            url = self.server + 'boat/instantFleet/{fleet}/{ships}/'.format(**args) + self.get_url_end()
            data = zlib.decompress(
                session.get(url=url, headers=HEADER,
                            cookies=self.cookies, timeout=10).content)
            data = json.loads(data)
            error_find(data)
            if is_write and os.path.exists('requestsData'):
                with open('requestsData/instant_fleet.json', 'w') as f:
                    f.write(json.dumps(data))
            return data
        except HmError as e:
            print('Instant fleet FAILED! Reason:', e.message)
            raise
        except Exception as Error_information:
            print('Instant fleet FAILED! Reason:', Error_information)
            raise

    def get_icon(self, index):
        url = "http://ima.ntwikis.com/cancollezh/20151119/M_NORMAL_{}.png".format(str(index))
        try:
            data = session.get(url).content
            if not os.path.exists("icon/big"):
                os.mkdir('icon/big')
            with open('icon/big/{}.png'.format(str(index)), 'wb') as f:
                f.write(data)
        except Exception as e:
            print('icon E', e)

    def get_pay_icon(self):
        try:
            data_wx = session.get("http://www.simonkimi.top/pay/wxpay.png").content
            data_zfb = session.get("http://www.simonkimi.top/pay/zfbpay.png").content
            data_hb = session.get("http://www.simonkimi.top/pay/hb.png").content
            content = [data_wx, data_zfb, data_hb]
            return content
        except Exception as e:
            print('icon pay', e)

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

    @staticmethod
    def get_md5(data):
        return hashlib.md5(str(data).encode('utf-8')).hexdigest()


    @staticmethod
    def str_arg(**arg):
        new_arg = {}
        for index, key in arg.items():
            new_arg[index] = str(key)
        return new_arg

    @staticmethod
    def set_text_size(size, strs):
        return '<html><head/><body><p><span style=" font-size:{:s}pt;">{:s}</span></p></body></html>'.format(str(size),
                                                                                                             str(strs))

gameFunction = GameFunction()
