import datetime
import struct, pathlib, json, operator, zlib, binascii
import blowfish_mod

LENGTH_STRUCT = struct.Struct("<i")
CLOCK_STRUCT = struct.Struct("<f")
CORD_STRUCT = struct.Struct("<fff")
B_STRUCT = struct.Struct("b")
C_STRUCT = struct.Struct("c")
BLOCK_LENGTH = 8
CIPHER = blowfish_mod.Blowfish(b"\xDE\x72\xBE\xA0\xDE\x04\xBE\xB1\xDE\xFE\xBE\xEF\xDE\xAD\xBE\xEF")
all_tanks = None

class ReplayWotParse(object):
    def __init__(self, replay_path, only_head=True):
        if not replay_path: return
        self.replay_path = pathlib.Path(replay_path)
        self.is_full_match = False
        self.is_only_head = only_head
        self.data_head = []

        if not self.replay_path.is_file(): return
        self.full_replay = open(self.replay_path, 'rb')
        self.read_replay_head()
        if not only_head:
            self.magic = binascii.hexlify(self.full_replay.read(4))
            self.data_gameplay = b''
            self.decode_gameplay_list = []
            self.read_replay_gameplay()
            self.cursor = 0
        self.full_replay.close()

    def read_replay_head_length(self):
        buffer = self.full_replay.read(LENGTH_STRUCT.size)
        if not buffer:
            raise StopIteration()
        return LENGTH_STRUCT.unpack(buffer)[0]

    def read_replay_head(self):
        header = self.full_replay.read(len(b"\x12\x32\x34\x11\x02\x00\x00\x00"))
        json_block_count = header[4]
        for i in range(json_block_count):
            try:
                length = self.read_replay_head_length()
                json_data = json.loads(self.full_replay.read(length))
                self.data_head.append(json_data)
            except:
                pass
        if len(self.data_head) == 2:
            self.is_full_match = True

    def read_replay_gameplay(self):
        blocks = []
        previous_block = bytes(BLOCK_LENGTH)
        length = self.read_replay_head_length()
        while True:
            block = self.full_replay.read(BLOCK_LENGTH)
            if not block:
                break
            if len(block) < BLOCK_LENGTH:
                block += b'\x00' * (BLOCK_LENGTH - len(block))
            block = CIPHER.decrypt(block)
            block = bytes(map(operator.xor, block, previous_block))
            previous_block = block
            blocks.append(block)
        self.data_gameplay = zlib.decompress(b"".join(blocks)[:length])

    def read_gameplay_length(self, length=LENGTH_STRUCT.size):
        if len(self.data_gameplay) <= self.cursor: return None
        buffer = self.data_gameplay[self.cursor:self.cursor+length]
        self.cursor += length
        if not buffer: return None
        return buffer

    def decode_gameplay(self):
        if not self.data_gameplay: return []
        self.cursor = 0
        self.decode_gameplay_list = []
        while True:
            payload_length_data = self.read_gameplay_length()
            packet_type_data = self.read_gameplay_length()
            if payload_length_data is None or packet_type_data is None: break
            payload_length = LENGTH_STRUCT.unpack(payload_length_data)[0]
            packet_type = LENGTH_STRUCT.unpack(packet_type_data)[0]
            payload = self.read_gameplay_length(payload_length+4)
            if payload is None: break
            # clock = CLOCK_STRUCT.unpack(payload[0:4])[0]
            # print(f'{payload_length:^5}', f'{packet_type:^5}', f'{clock:^5}', payload[:50])
            packet_data = self.decode_packet(payload, packet_type, payload_length)
            self.decode_gameplay_list.append(
                {
                    'payload_length': payload_length,
                    'packet_type': packet_type,
                    'packet_data': packet_data,
                    'payload': payload,
                })

    def decode_packet(self, payload, packet_type, payload_length=None):
        if not payload or packet_type is None: return {}
        temp_data = {}
        cursor = 0
        clock = CLOCK_STRUCT.unpack(payload[cursor:cursor+CLOCK_STRUCT.size])[0]
        if clock is not None:
            temp_data['clock'] = clock
        cursor += CLOCK_STRUCT.size
        if packet_type == 0:
            edited = payload[cursor:cursor + LENGTH_STRUCT.size]
            unknown_id = LENGTH_STRUCT.unpack(edited)[0]
            if unknown_id:
                temp_data['unknown_id'] = unknown_id
            name_len_STRUCT = struct.Struct(">i")
            cursor += 11
            edited = payload[cursor:cursor + name_len_STRUCT.size]
            name_len = name_len_STRUCT.unpack(edited)[0]
            cursor += LENGTH_STRUCT.size
            nick_name = bytes(payload[cursor:cursor + name_len]).decode("utf-8")
            if nick_name:
                temp_data['nick_name'] = nick_name
            cursor += name_len

            len_game_player_id = ord(payload[cursor:cursor + 1])
            cursor += 1

            game_player_id = int(payload[cursor:cursor + len_game_player_id])
            if game_player_id:
                temp_data['game_player_id'] = game_player_id
            cursor += len_game_player_id

            timestamp_start = LENGTH_STRUCT.unpack(payload[cursor:cursor + LENGTH_STRUCT.size])[0]
            if timestamp_start:
                temp_data['timestamp_start'] = timestamp_start
            cursor += LENGTH_STRUCT.size + 33

            gameParamsRev = payload[cursor:cursor + 16].decode("utf-8")
            if gameParamsRev:
                temp_data['gameParamsRev'] = gameParamsRev
            cursor += 30

            edited = payload[cursor:cursor + B_STRUCT.size]
            battleLevel_index = B_STRUCT.unpack(edited)[0]
            cursor += B_STRUCT.size
            battleLevel = None
            if battleLevel_index == 75:
                edited = payload[cursor:cursor + C_STRUCT.size]
                battleLevel = ord(C_STRUCT.unpack(edited)[0])
                cursor += C_STRUCT.size
            elif battleLevel_index == 74:
                edited = payload[cursor:cursor + LENGTH_STRUCT.size]
                battleLevel = LENGTH_STRUCT.unpack(edited)[0]
                cursor += LENGTH_STRUCT.size
            if battleLevel is not None:
                temp_data['battleLevel'] = battleLevel
            cursor += 13

            edited = payload[cursor:cursor + B_STRUCT.size]
            arenaTypeID_index = B_STRUCT.unpack(edited)[0]
            cursor += B_STRUCT.size
            arenaTypeID = None
            if arenaTypeID_index == 75:
                edited = payload[cursor:cursor + C_STRUCT.size]
                arenaTypeID = ord(C_STRUCT.unpack(edited)[0])
                cursor += C_STRUCT.size
            elif arenaTypeID_index == 74:
                edited = payload[cursor:cursor + LENGTH_STRUCT.size]
                arenaTypeID = LENGTH_STRUCT.unpack(edited)[0]
                cursor += LENGTH_STRUCT.size
            if arenaTypeID is not None:
                temp_data['arenaTypeID'] = arenaTypeID
            cursor += 11

            edited = payload[cursor:cursor + B_STRUCT.size]
            arenaKind_index = B_STRUCT.unpack(edited)[0]
            cursor += B_STRUCT.size
            arenaKind = None
            if arenaKind_index == 75:
                edited = payload[cursor:cursor + C_STRUCT.size]
                arenaKind = ord(C_STRUCT.unpack(edited)[0])
                cursor += C_STRUCT.size
            elif arenaKind_index == 74:
                edited = payload[cursor:cursor + LENGTH_STRUCT.size]
                arenaKind = LENGTH_STRUCT.unpack(edited)[0]
                cursor += LENGTH_STRUCT.size
            if arenaKind is not None:
                temp_data['arenaKind'] = arenaKind
        elif packet_type == 1:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            world_id = LENGTH_STRUCT.unpack(cluster)[0]
            if world_id:
                temp_data['world_id'] = world_id
            cursor = 14
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            entity_id = LENGTH_STRUCT.unpack(cluster)[0]
            if entity_id:
                temp_data['entity_id'] = entity_id
            cursor += LENGTH_STRUCT.size
            cluster = payload[cursor:cursor + CORD_STRUCT.size]
            coordinate = CORD_STRUCT.unpack(cluster)
            if coordinate:
                temp_data['coordinate'] = coordinate
        elif packet_type == 2:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            world_id = LENGTH_STRUCT.unpack(cluster)[0]
            if world_id:
                temp_data['world_id'] = world_id
        elif packet_type in [4, 7]:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            entity_id = LENGTH_STRUCT.unpack(cluster)[0]
            if entity_id:
                temp_data['entity_id'] = entity_id
        elif packet_type == 5:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            entity_id = LENGTH_STRUCT.unpack(cluster)[0]
            if entity_id:
                temp_data['entity_id'] = entity_id
            cursor += LENGTH_STRUCT.size

            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            entity_type = LENGTH_STRUCT.unpack(cluster)[0]
            if entity_type:
                temp_data['entity_type'] = entity_type
            cursor += LENGTH_STRUCT.size + 10

            cluster = payload[cursor:cursor + CORD_STRUCT.size]
            coordinate = CORD_STRUCT.unpack(cluster)
            if coordinate:
                temp_data['coordinate'] = coordinate

            if entity_type == 6:
                cursor = 61
                cluster = payload[cursor:cursor + B_STRUCT.size]
                type_byte = B_STRUCT.unpack(cluster)[0]
                cursor += B_STRUCT.size
                len_nickname = None
                if type_byte == 12:
                    cursor += 3
                    cluster = payload[cursor:cursor + B_STRUCT.size]
                    len_nickname = B_STRUCT.unpack(cluster)[0]
                    cursor += B_STRUCT.size
                elif type_byte == 20:
                    cluster = payload[cursor:cursor + B_STRUCT.size]
                    len_nickname = B_STRUCT.unpack(cluster)[0]
                    cursor += B_STRUCT.size
                if len_nickname:
                    nick_name = payload[cursor:cursor + len_nickname]
                    if nick_name:
                        temp_data['nick_name'] = nick_name
        elif packet_type == 6:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            entity_id = LENGTH_STRUCT.unpack(cluster)[0]
            if entity_id:
                temp_data['entity_id'] = entity_id
            cursor += LENGTH_STRUCT.size
        elif packet_type == 35:
            cluster = payload[cursor:cursor + LENGTH_STRUCT.size]
            len_text = LENGTH_STRUCT.unpack(cluster)[0]
            cursor += LENGTH_STRUCT.size
            message_user = bytes(payload[cursor:cursor+len_text]).decode()
            if message_user:
                temp_data['message_user'] = message_user

        return temp_data

    def get_map(self):
        for i in self.data_head:
            if 'mapDisplayName' in i:
                return i['mapDisplayName']

    def get_player_team_id(self):
        player_nick_name = None
        for i in self.data_head:
            if 'playerName' in i:
                player_nick_name = i['playerName']
            if 'vehicles' in i and player_nick_name:
                for game_player_id in i['vehicles']:
                    if 'name' in i['vehicles'][game_player_id] and  player_nick_name == i['vehicles'][game_player_id]['name']:
                        return i['vehicles'][game_player_id]['team']

    def get_time_stamp(self):
        for i in self.data_head:
            if type(i) is dict and 'dateTime' in i:
                return int(datetime.datetime.strptime(i['dateTime'], "%d.%m.%Y %H:%M:%S").timestamp())

    def is_player_win(self):
        player_team_id = self.get_player_team_id()
        if not player_team_id: return None
        for i in self.data_head:
            if type(i) is list:
                for j in i:
                    if 'common' in j and 'winnerTeam' in j['common']:
                        if player_team_id == j['common']['winnerTeam']:
                            return True
                        else:
                            return False

    def get_player_info(self):
        wg_player_id = None
        player_name = None
        for i in self.data_head:
            if 'playerID' in i:
                wg_player_id = i['playerID']
            if 'playerName' in i:
                player_name = i['playerName']

        if not wg_player_id or not player_name: return None
        player_data = {}
        for i in self.data_head:
            if type(i) is dict and 'vehicles' in i:
                for game_player_id in i['vehicles']:
                    if 'name' in i['vehicles'][game_player_id] and player_name == i['vehicles'][game_player_id]['name']:
                        player_data['game_player_id'] = game_player_id
                        player_data['info'] = i['vehicles'][game_player_id]
            if type(i) is list and 'game_player_id' in player_data:
                for j in i:
                    if 'vehicles' in j and player_data['game_player_id'] in j['vehicles']:
                        player_data['battle_info'] = j['vehicles'][player_data['game_player_id']]
        return player_data

    def get_player_info_by_avatar_id(self, avatar_id):
        user_data = {}
        for i in self.data_head:
            if type(i) is dict and 'vehicles' in i and avatar_id in i['vehicles']:
                user_data['game_player_id'] = avatar_id
                user_data['info'] = i['vehicles'][avatar_id]
            if type(i) is list:
                for j in i:
                    if 'vehicles' in j and avatar_id in j['vehicles']:
                        user_data['battle_info'] = j['vehicles'][avatar_id]
        return user_data

    def get_player_team_info(self):
        player_team_id = self.get_player_team_id()
        player_team_data = []
        for i in self.data_head:
            if type(i) is dict and 'vehicles' in i:
                for game_player_id in i['vehicles']:
                    if 'team' in i['vehicles'][game_player_id] and player_team_id == i['vehicles'][game_player_id]['team']:
                        player_team_data.append(self.get_player_info_by_avatar_id(game_player_id))
        return player_team_data

    def get_player_enemy_info(self):
        player_team_id = self.get_player_team_id()
        player_enemy_data = []
        for i in self.data_head:
            if type(i) is dict and 'vehicles' in i:
                for game_player_id in i['vehicles']:
                    if 'team' in i['vehicles'][game_player_id] and player_team_id != i['vehicles'][game_player_id]['team']:
                        player_enemy_data.append(self.get_player_info_by_avatar_id(game_player_id))
        return player_enemy_data

    def get_team_data_for_discord(self):
        global all_tanks
        from wot_statistic import get_all_tanks
        team_data = self.get_player_team_info()
        if not team_data: return
        return_data = {}
        win_or_lose = self.is_player_win()
        if all_tanks is None:
            all_tanks = get_all_tanks()
        for i in team_data:
            player_wg_id = None
            reserve_tank_name = 'Unknown'
            if 'game_player_id' in i:
                player_wg_id = i['game_player_id']
            if 'info' in i:
                player_data = i['info']
                if 'vehicleType' in player_data:
                    reserve_tank_name = player_data['vehicleType']
                if 'team' in player_data:
                    if not player_wg_id in return_data:
                        return_data[player_wg_id] = {}
                if 'isAlive' in player_data:
                    return_data[player_wg_id]['isAlive'] = player_data['isAlive']
                if 'name' in player_data:
                    return_data[player_wg_id]['name'] = player_data['name']
                return_data[player_wg_id]['win'] = win_or_lose
            if 'battle_info' in i:
                for tank_result in i['battle_info']:
                    if not 'vehicleType' in return_data[player_wg_id]:
                        return_data[player_wg_id]['vehicleType'] = []
                    if 'typeCompDescr' in tank_result:
                        tank_name = reserve_tank_name
                        if str(tank_result['typeCompDescr']) in all_tanks:
                            data_tank = all_tanks[str(tank_result['typeCompDescr'])]
                            if 'short_name' in data_tank:
                                tank_name = data_tank['short_name']
                        if tank_name not in return_data[player_wg_id]['vehicleType']:
                            return_data[player_wg_id]['vehicleType'].append(tank_name)
                    if not 'frags' in return_data[player_wg_id]:
                        return_data[player_wg_id]['frags'] = 0
                    if 'kills' in tank_result:
                        return_data[player_wg_id]['frags'] += tank_result['kills']
                    if not 'account_id' in return_data[player_wg_id]:
                        if 'accountDBID' in tank_result:
                            return_data[player_wg_id]['account_id'] = tank_result['accountDBID']
                    if not 'shots' in return_data[player_wg_id]:
                        return_data[player_wg_id]['shots'] = 0
                    if 'shots' in tank_result:
                        return_data[player_wg_id]['shots'] += tank_result['shots']
                    if not 'hits' in return_data[player_wg_id]:
                        return_data[player_wg_id]['hits'] = 0
                    if 'directHits' in tank_result:
                        return_data[player_wg_id]['hits'] += tank_result['directHits']
                    if not 'hits_damaged' in return_data[player_wg_id]:
                        return_data[player_wg_id]['hits_damaged'] = 0
                    if 'piercingEnemyHits' in tank_result:
                        return_data[player_wg_id]['hits_damaged'] += tank_result['piercingEnemyHits']
                    if not 'damage' in return_data[player_wg_id]:
                        return_data[player_wg_id]['damage'] = 0
                    if 'damageDealt' in tank_result:
                        return_data[player_wg_id]['damage'] += tank_result['damageDealt']
                    if not 'assist' in return_data[player_wg_id]:
                        return_data[player_wg_id]['assist'] = 0
                    if 'damageAssistedRadio' in tank_result:
                        return_data[player_wg_id]['assist'] += tank_result['damageAssistedRadio']
                    if 'damageAssistedStun' in tank_result:
                        return_data[player_wg_id]['assist'] += tank_result['damageAssistedStun']
                    if 'damageAssistedTrack' in tank_result:
                        return_data[player_wg_id]['assist'] += tank_result['damageAssistedTrack']
                    if 'damageAssistedSmoke' in tank_result:
                        return_data[player_wg_id]['assist'] += tank_result['damageAssistedSmoke']
                    if 'damageAssistedInspire' in tank_result:
                        return_data[player_wg_id]['assist'] += tank_result['damageAssistedInspire']
                    if 'damageBlockedByArmor' in tank_result:
                        return_data[player_wg_id]['block'] = tank_result['damageBlockedByArmor']
        return return_data

    def get_info_from_decode_game_play(self):
        if self.is_only_head: return
        if not self.decode_gameplay_list:
            self.decode_gameplay()
        # for data in self.decode_gameplay_list:
        #     print(data)


# replay_path = r'F:\World_of_Tanks_RU\replays\20211029_0954_ussr-R171_IS_3_II_hw21_95_lost_city_ctf_h19.wotreplay'
#
# replay = ReplayWotParse(replay_path, False)
# replay.decode_gameplay()
# exit()
