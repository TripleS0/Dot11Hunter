import re
import time
import threading
from base import CFG, Dot11HunterUtils, logger


class ChannelSwitch(threading.Thread):
    def __init__(self, interface):
        super().__init__()
        self.setName('ChannelSwitch')
        self.log_extra = {'thread_name': self.getName()}
        self.channels = list()
        self.interface = interface
        self.current_channel = None

    def run(self):
        try:
            self.get_available_channels()
            self.switch_channel()
        except Exception as e:
            logger.critical(str(e), extra=self.log_extra)

    def switch_channel(self):
        while True:
            for ch in self.channels:
                self.set_channel(ch)
                self.current_channel = self.get_current_channel()
                time.sleep(CFG['DEFAULT'].getfloat('channel_interval'))

    def get_available_channels(self):
        cmd = 'iwlist {} channel'.format(self.interface)
        outs, errs = Dot11HunterUtils.run_cmd(cmd)
        if 'channels' in outs:
            m = re.findall(r'Channel (\d+) :', outs, re.MULTILINE)
            if m:
                for i in m:
                    ch = int(i)
                    if ch <= CFG['DOT11'].getint('max_channel'):
                        self.channels.append(ch)

    def get_current_channel(self):
        result = None
        cmd = 'iwlist {} channel'.format(self.interface)
        outs, errs = Dot11HunterUtils.run_cmd(cmd)
        if 'channels' in outs:
            m = re.findall(r'\(Channel (\d+)\)', outs, re.MULTILINE)
            if m:
                result = int(m[0])
        return result

    def set_channel(self, channel):
        cmd = 'iwconfig {} channel {}'.format(self.interface, channel)
        Dot11HunterUtils.run_cmd(cmd)

