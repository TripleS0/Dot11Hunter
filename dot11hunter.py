import argparse
import json
import socket
import sys
import queue
import time
import scapy
from datetime import datetime
from scapy.all import Dot11, Dot11FCS
from handler import create_handlers
from base import Dot11HunterBase, GeoFrame, FrameSubType, RepeatedTimer
from base import CFG, logger, Dot11HunterUtils
from channel import ChannelSwitch
from bt_server import BtServer


class Dot11Hunter(Dot11HunterBase):
    # Sniff 802.11 frames and dispatch to handlers by queue
    def __init__(self):
        super().__init__()
        self.setName('Dot11Hunter')
        self.log_extra = {'thread_name': self.getName()}
        self.interface = None
        self.channel_switch = None
        self.handlers = []
        self.bt_server = None
        self.time_synchronized = False
        self.crnt_location = {'longitude': None, 'latitude': None,
                              'timestamp': None}
        self.frame_counters = dict()  # for sampling
        self.frm_queues = dict()  # frame queues
        self.log_frame_counters = {
            'data': 0,
            'beacon': 0,
            'probe_req': 0,
            'ctrl': 0,
            'mgmt': 0
        }
        self.parse_arg()
        self.event_queue = queue.Queue(
            maxsize=CFG['DEFAULT'].getint('event_queue_max_size'))
        self.init_attributes()

    def parse_arg(self):
        parser = argparse.ArgumentParser(
            description='Dot11Hunter: hunt devices by sniffing 802.11')
        # Mandatory parameter: interface
        parser.add_argument('-i', dest='interface', help='monitor interface')
        args = parser.parse_args()
        self.interface = args.interface
        if self.interface is None:
            parser.print_help()
            sys.exit(0)

    def init_attributes(self):
        frame_types = Dot11HunterUtils.get_frame_types()
        for t in frame_types:
            self.frm_queues[t] = queue.Queue(
                maxsize=CFG['DEFAULT'].getint('frm_queue_max_size'))
            self.frame_counters[t] = 0

    def dump_log(self):
        logger.info(
            'is using {}% memory, current channel is {}'.format(
                Dot11HunterUtils.get_mem_used_by_dot11hunter(),
                self.channel_switch.current_channel),
            extra=self.log_extra)
        logger.info(
            'captured {} beacon, {} probe_req, {} management, {} control, '
            '{} data frames'.format(
                self.log_frame_counters['beacon'],
                self.log_frame_counters['probe_req'],
                self.log_frame_counters['mgmt'],
                self.log_frame_counters['ctrl'],
                self.log_frame_counters['data']),
            extra=self.log_extra)
        self.log_frame_counters['beacon'] = 0
        self.log_frame_counters['probe_req'] = 0
        self.log_frame_counters['mgmt'] = 0
        self.log_frame_counters['ctrl'] = 0
        self.log_frame_counters['data'] = 0

    def dispatch(self, frame):
        beacon_sample_itvl = 1 / CFG['DOT11'].getfloat('beacon_sample_rate')
        data_sample_itvl = 1 / CFG['DOT11'].getfloat('data_sample_rate')
        mgmt_sample_itvl = 1 / CFG['DOT11'].getfloat('mgmt_sample_rate')
        ctrl_sample_itvl = 1 / CFG['DOT11'].getfloat('ctrl_sample_rate')
        # Only parse 802.11 frames
        if Dot11 not in frame.layers() and Dot11FCS not in frame.layers():
            return
        sts = FrameSubType.get_type_subtype(frame)  # type/sub_type

        # only location within 10 seconds is valid
        geo = None
        if self.crnt_location['timestamp'] is not None:
            interval = time.time() - self.crnt_location['timestamp']
            if 0 <= interval <= 10:
                geo = {'longitude': self.crnt_location['longitude'],
                       'latitude': self.crnt_location['latitude']}
        geo_frame = GeoFrame(frame, geo, datetime.now())
        try:
            # Beacon frames are handled independently because it is too
            # frequent
            if sts == FrameSubType.BEACON:
                if self.frame_counters['beacon'] >= beacon_sample_itvl:
                    self.frm_queues['beacon'].put_nowait(geo_frame)
                    self.frame_counters['beacon'] = 0
                else:
                    self.frame_counters['beacon'] += 1
                    self.log_frame_counters['beacon'] += 1
            elif sts == FrameSubType.PROBE_REQ:
                self.frm_queues['probe_req'].put_nowait(geo_frame)
                self.log_frame_counters['probe_req'] += 1
            elif sts in FrameSubType.MGMT:
                if self.frame_counters['mgmt'] >= mgmt_sample_itvl:
                    self.frm_queues['mgmt'].put_nowait(geo_frame)
                    self.frame_counters['mgmt'] = 0
                else:
                    self.frame_counters['mgmt'] += 1
                    self.log_frame_counters['mgmt'] += 1
            elif sts in FrameSubType.CTRL:
                if self.frame_counters['ctrl'] >= ctrl_sample_itvl:
                    self.frm_queues['ctrl'].put_nowait(geo_frame)
                    self.frame_counters['ctrl'] = 0
                else:
                    self.frame_counters['ctrl'] += 1
                    self.log_frame_counters['ctrl'] += 1
            elif sts in FrameSubType.DATA:
                if self.frame_counters['data'] >= data_sample_itvl:
                    self.frm_queues['data'].put_nowait(geo_frame)
                    self.frame_counters['data'] = 0
                else:
                    self.frame_counters['data'] += 1
                    self.log_frame_counters['data'] += 1
        except queue.Full:
            pass
        except Exception as e:
            logger.critical('{}'.format(str(e)), extra=self.log_extra)

    def update_location(self, data):
        data = json.loads(data)
        self.crnt_location['longitude'] = data['longitude']
        self.crnt_location['latitude'] = data['latitude']
        self.crnt_location['timestamp'] = data['timestamp']/1000
        ts_phone = data['timestamp'] / 1000
        if abs(ts_phone - time.time()) > 10:
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_phone))
            cmd = 'date -s "{}"'.format(str_time)
            Dot11HunterUtils.run_cmd(cmd)
            logger.info('time synchronized successfully.', extra=self.log_extra)
            self.time_synchronized = True
            current_date = Dot11HunterUtils.run_cmd('date')
            logger.info('current system date: {}'.format(current_date),
                        extra=self.log_extra)
        else:
            if self.time_synchronized is False:
                self.time_synchronized = True
                logger.info('time is correct, no need to synchronize.', extra=self.log_extra)

    def send_latest_captures_sys_status(self):
        data = dict()
        sql_mac = 'SELECT HEX(addr), last_seen FROM mac order by last_seen desc LIMIT 1'
        sql_ssid = 'SELECT ssid, last_seen FROM ap order by last_seen desc LIMIT 1'
        sql_association = 'SELECT HEX(mac.addr), ap.ssid, ' \
                          'association.last_seen FROM association JOIN mac ' \
                          'JOIN ap WHERE mac.id=association.mac_id AND ' \
                          'ap.id=association.ap_id ORDER BY ' \
                          'association.last_seen DESC LIMIT 1'
        sql_mac_count = 'SELECT COUNT(id) FROM mac'
        sql_ap_count = 'SELECT COUNT(id) FROM ap'
        sql_association_count = 'SELECT COUNT(id) FROM association'
        sql_geo_count = 'SELECT COUNT(id) FROM geo'
        try:
            db_conn, db_cursor = Dot11HunterUtils.connect_db()
            data['mac'] = self.fetch_data_with_lastseen(db_cursor, sql_mac)
            data['ssid'] = self.fetch_data_with_lastseen(db_cursor, sql_ssid)
            db_cursor.execute(sql_association)
            row = db_cursor.fetchall()
            if row:
                mac, ssid, date = row[0]
                if time.time() - date.timestamp() < 60:
                    data['association'] = '{} <-> {}'.format(mac, ssid)
                else:
                    data['association'] = None
            data['mac_count'] = self.fetch_data(db_cursor, sql_mac_count)
            data['ap_count'] = self.fetch_data(db_cursor, sql_ap_count)
            data['geo_count'] = self.fetch_data(db_cursor, sql_geo_count)
            data['association_count'] = self.fetch_data(db_cursor,
                                                        sql_association_count)
            db_conn.close()
            data['cpu_usage'], data['mem_usage'], data['temperature'] = \
                Dot11HunterUtils.get_sys_status()
            self.bt_server.send(json.dumps(data))
        except Exception as e:
            logger.critical(str(e), extra=self.log_extra)

    @staticmethod
    def fetch_data_with_lastseen(db_cursor, sql):
        result = None
        db_cursor.execute(sql)
        row = db_cursor.fetchall()
        if row:
            temp_result, date = row[0]
            if time.time() - date.timestamp() < 60:
                result = temp_result
        return result

    @staticmethod
    def fetch_data(db_cursor, sql):
        result = None
        db_cursor.execute(sql)
        row = db_cursor.fetchall()
        if row:
            result = row[0][0]
        return result

    def is_internet_connected(self):
        s = socket.socket()
        s.settimeout(8)
        try:
            status = s.connect_ex(('www.baidu.com', 443))
            if status == 0:
                s.close()
                logger.info('Internet Connected, NTP should work', extra=self.log_extra)
                return True
            else:
                return False
        except Exception as e:
            return False

    def ntp(self):
        result = False
        cmd = 'ntpdate ntp1.aliyun.com'
        outs = Dot11HunterUtils.run_cmd(cmd, timeout=60)
        if isinstance(outs, tuple):
            if 'offset' in outs[0]:
                result = True
                logger.info('ntpdate success.', extra=self.log_extra)
                return result
        logger.info('ntpdate failed.', extra=self.log_extra)
        return result

    def run(self):
        # start bluetooth server
        self.bt_server = BtServer(recv_callback=self.update_location)
        self.bt_server.start()
        # start sending latest captures and sys status to phone
        RepeatedTimer(func=self.send_latest_captures_sys_status,
                      interval=5).start()
        # start channel switch
        self.channel_switch = ChannelSwitch(self.interface)
        self.channel_switch.start()
        # start handlers
        self.handlers = create_handlers(self.frm_queues, self.event_queue)
        for handler in self.handlers:
            handler.start()
        is_ntpped = self.ntp()
        if not is_ntpped and not self.time_synchronized:
            logger.info('waiting for time synchronization...', extra=self.log_extra)
        while not is_ntpped and not self.time_synchronized:
            time.sleep(1)
        # start sniffer
        logger.info('start sniffing', extra=self.log_extra)
        scapy.all.conf.iface = self.interface
        scapy.all.sniff(prn=self.dispatch, store=False)
        for handler in self.handlers:
            handler.join()
        self.channel_switch.join()


if __name__ == '__main__':
    hunter = Dot11Hunter()
    hunter.run()
