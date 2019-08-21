import configparser
import os
import subprocess
import shlex
import logging
import threading
import signal
import re
import time
import mysql.connector
import psutil
from scapy.all import Dot11, Dot11FCS


def setup_logger():
    result = logging.getLogger('main')
    result.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(thread_name)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    level = CFG['DEFAULT']['log_level']
    f_handler = logging.FileHandler(CFG['DEFAULT']['log_path'])
    f_handler.setLevel(level)
    f_handler.setFormatter(fmt)
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(fmt)
    result.addHandler(f_handler)
    result.addHandler(console)
    return result

class Dot11HunterUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_frame_types():
        # Parse frame types in config
        result = []
        s = CFG['DOT11']['frame_types']
        for t in s.split(', '):
            result.append(t)
        return result

    @staticmethod
    def get_mem_used_by_dot11hunter():
        result = None
        cmd = 'ps -aux | grep dot11hunter\.py | grep -v grep'
        outs = subprocess.check_output(cmd, shell=True)
        outs = outs.decode('utf-8')
        if not outs:
            return result
        result = re.findall(r'^(?:[\w.]+?\s+?){3}([\w.]+?)\s+?', outs)[0]
        return float(result)

    @staticmethod
    def get_sys_status():
        result = (None, None, None)
        try:
            cpu_usage = psutil.cpu_percent()
            mem_usage = psutil.virtual_memory().percent
            temperature = psutil.sensors_temperatures()['cpu-thermal'][0].current
            result = (cpu_usage, mem_usage, temperature)
        except Exception as e:
            logger.critical((str(e)), extra='Dot11HunterUtils')
        return result

    @staticmethod
    def run_cmd(cmd, timeout=15, shell=False):
        proc = subprocess.Popen(shlex.split(cmd),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                shell=shell)
        outs, errs = proc.communicate(timeout=timeout)
        if proc.poll() is not None:
            proc.kill()
        return outs, errs

    @staticmethod
    def connect_db():
        config = {
            'user': CFG['MYSQL']['user'],
            'host': CFG['MYSQL']['host'],
            'password': CFG['MYSQL']['password'],
            'database': CFG['MYSQL']['database'],
            'connection_timeout': 180,
            'use_pure': True,
            'autocommit': True
        }
        db_conn = mysql.connector.connect(**config)
        db_cursor = db_conn.cursor()
        return db_conn, db_cursor

    @staticmethod
    def is_cache_fresh(key, timestamp, cache, threshold, lock):
        result = False
        lock.acquire()
        # print('lock acquire')
        if key in cache.keys():
            delta = timestamp - cache[key]
            # Ignore the event not fresher enough
            if delta.days < 0 or \
                    (delta.days >= 0 and delta.seconds <= threshold):
                lock.release()
                return result
        result = True
        cache[key] = timestamp
        # print('done')
        lock.release()
        # print('lock release')
        return result

CFG = configparser.ConfigParser(
    interpolation=configparser.ExtendedInterpolation())
CFG.read(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      'config.ini'))
logger = setup_logger()


class GeoFrame:
    # Frame with Geo
    def __init__(self, frame, geo, timestamp):
        self.frame = frame
        self.geo = geo
        self.timestamp = timestamp


class FrameSubType:
    # management
    BEACON = 0x08
    PROBE_REQ = 0x04
    PROBE_RESP = 0x05
    ACTION = 0x0D
    ASSOCIATION = 0x00
    # control
    PS_POLL = 0x1A
    RTS = 0x1B
    # CTS = 0x1C
    BLOCK_ACK_REQ = 0x18
    BLOCK_ACK = 0x19
    # ACK = 0x1D
    # data
    # DATA_ = 0x20
    NULL_FUNC = 0x24
    QOS_DATA = 0x28
    QOS_NULL_FUNC = 0x2C
    # type category
    MGMT = (PROBE_REQ, PROBE_RESP, ACTION, ASSOCIATION)
    CTRL = (PS_POLL, RTS, BLOCK_ACK_REQ, BLOCK_ACK)
    DATA = (NULL_FUNC, QOS_DATA, QOS_NULL_FUNC)

    @staticmethod
    def get_type_subtype(frame):
        layer = None
        if Dot11 in frame.layers():
            layer = Dot11
        elif Dot11FCS in frame.layers():
            layer = Dot11FCS
        frame_type = frame[layer].type
        frame_subtype = frame[layer].subtype
        type_subtype = frame_type * 16 + frame_subtype
        return type_subtype


class Dot11HunterBase(threading.Thread):
    def __init__(self):
        super().__init__()
        self.setup_signal()
        self.log_timer = None
        self.start_log_timer()
        self.log_extra = None

    def setup_signal(self):
        signal.signal(signal.SIGHUP, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)
        signal.signal(signal.SIGINT, self.terminate)

    def terminate(self, signum, frame):
        logger.critical(
            'terminates, signum: {}, frame: {}'.format(signum, frame),
            extra=self.log_extra)
        signal.pthread_kill(threading.get_ident(), signal.SIGKILL)

    def dump_log(self):
        pass

    def start_log_timer(self):
        self.log_timer = LogTimer(self)
        self.log_timer.start()


class LogTimer(threading.Thread):
    def __init__(self, log_entity):
        super().__init__()
        self.log_entity = log_entity

    def run(self):
        while True:
            time.sleep(CFG['DEFAULT'].getfloat('log_interval'))
            self.log_entity.dump_log()


class RepeatedTimer(threading.Thread):
    def __init__(self, func=None, interval=60):
        super().__init__()
        self.func = func
        self.interval = interval

    def run(self):
        while True:
            time.sleep(self.interval)
            self.func()
