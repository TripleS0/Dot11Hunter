import queue
from base import Dot11HunterBase, FrameSubType, logger, CFG
from scapy.all import *
from event import EventHandler, Dot11Event


# Create handler threads to process frames
def create_handlers(frm_queues, event_queue, caches=None, cache_update_lock=None):
    result = list()
    result.append(BeaconHandler(frm_queues['beacon'], event_queue))
    result.append(ProbeReqHandler(frm_queues['probe_req'], event_queue))
    result.append(MgmtHandler(frm_queues['mgmt'], event_queue))
    result.append(CtrlHandler(frm_queues['ctrl'], event_queue))
    result.append(DataHandler(frm_queues['data'], event_queue))
    for i in range(CFG['DEFAULT'].getint('num_event_handlers')):
        result.append(EventHandler(event_queue=event_queue,
                                   name='EventHandler{}'.format(i),
                                   caches=caches,
                                   cache_update_lock=cache_update_lock))
    return result


class HandlerBase(Dot11HunterBase):
    def __init__(self, frm_queue=None, event_queue=None):
        super().__init__()
        self.frm_queue = frm_queue
        self.event_queue = event_queue  # info extracted from frames

    def run(self):
        while True:
            try:
                geo_frame = self.frm_queue.get()
                self.parse_frame(geo_frame)
            except queue.Full:
                pass
            except Exception as e:
                logger.critical('{}'.format(str(e)), extra=self.log_extra)

    def extract_ssid(self, frame):
        result = None
        for l in self.extract_layers(frame):
            if isinstance(l, Dot11Elt) and l.ID == 0:
                result = l.info.decode('utf8')
                break
        return result

    @staticmethod
    def decompose_geo_frame(geo_frame):
        return geo_frame.frame, geo_frame.geo, geo_frame.timestamp

    def put_events(self, ts, MAC=False, GEO=False, SSID=False,
                   ASSOCIATION=False, **kwargs):
        if 'ssid_origin' in kwargs and kwargs['ssid_origin'] is not None:
            ssid_origin = kwargs['ssid_origin']
        else:
            ssid_origin = None
        # events related to the same entity such as MAC or association should
        # be handled by only one EventHandle because their sequence make sense
        temp_events_group = []
        if MAC:
            # self.event_queue.put_nowait(Dot11Event(src=kwargs['src'],
            #                                        timestamp=ts,
            #                                        type=Dot11Event.MAC,
            #                                        origin=kwargs[
            #                                            'mac_origin']))
            temp_events_group.append(Dot11Event(src=kwargs['src'],
                                                   timestamp=ts,
                                                   type=Dot11Event.MAC,
                                                   origin=kwargs[
                                                       'mac_origin']))
            if 'dst' in kwargs and kwargs['dst'] is not None:
                # Here dst mac is assigned to src for the convenience of
                # event.handle_mac
                # self.event_queue.put_nowait(
                #     Dot11Event(src=kwargs['dst'],
                #                timestamp=ts,
                #                type=Dot11Event.MAC,
                #                origin=kwargs[
                #                    'mac_origin']))
                temp_events_group.append(Dot11Event(src=kwargs['dst'],
                                                    timestamp=ts,
                                                    type=Dot11Event.MAC,
                                                    origin=kwargs[
                                                        'mac_origin']))
        if GEO:
            # self.event_queue.put_nowait(
            #     Dot11Event(src=kwargs['src'],
            #                timestamp=ts,
            #                geo=kwargs['geo'],
            #                type=Dot11Event.GEO))
            temp_events_group.append(Dot11Event(src=kwargs['src'],
                                                timestamp=ts,
                                                geo=kwargs['geo'],
                                                type=Dot11Event.GEO))
            if 'dst' in kwargs and kwargs['dst'] is not None:
                # self.event_queue.put_nowait(
                #     Dot11Event(src=kwargs['dst'],
                #                timestamp=ts,
                #                geo=kwargs['geo'],
                #                type=Dot11Event.GEO))
                temp_events_group.append(
                    Dot11Event(src=kwargs['dst'],
                               timestamp=ts,
                               geo=kwargs['geo'],
                               type=Dot11Event.GEO))
        if SSID:
            # self.event_queue.put_nowait(
            #     Dot11Event(src=kwargs['src'],
            #                ssid=kwargs['ssid'],
            #                timestamp=ts,
            #                type=Dot11Event.SSID,
            #                origin=ssid_origin))
            temp_events_group.append(Dot11Event(src=kwargs['src'],
                                                ssid=kwargs['ssid'],
                                                timestamp=ts,
                                                type=Dot11Event.SSID,
                                                origin=ssid_origin))
        if ASSOCIATION:
            # self.event_queue.put_nowait(
            #     Dot11Event(src=kwargs['src'],
            #                dst=kwargs['dst'],
            #                ssid=kwargs['ssid'],
            #                timestamp=ts,
            #                type=Dot11Event.ASSOCIATION))
            temp_events_group.append(Dot11Event(src=kwargs['src'],
                                                dst=kwargs['dst'],
                                                ssid=kwargs['ssid'],
                                                timestamp=ts,
                                                type=Dot11Event.ASSOCIATION))
        if temp_events_group:
            self.event_queue.put_nowait(temp_events_group)

    def parse_frame(self, frame):
        pass

    @staticmethod
    def extract_layers(frame):
        while frame.payload:
            frame = frame.payload
            yield frame


class BeaconHandler(HandlerBase):
    def __init__(self, frm_queue, event_queue):
        super().__init__(frm_queue, event_queue)
        self.setName('BeaconHandler')
        self.log_extra = {'thread_name': self.getName()}

    def parse_frame(self, geo_frame):
        frame, geo, ts = self.decompose_geo_frame(geo_frame)
        src = frame.payload.addr2
        ssid = self.extract_ssid(frame)
        ssid_origin = 'from_beacon'
        mac_origin = 'from_mgmt'
        if ssid is None:
            self.put_events(ts, MAC=True, GEO=True, src=src,
                            mac_origin=mac_origin,
                            geo=geo)
        else:
            self.put_events(ts, MAC=True, GEO=True, SSID=True, src=src,
                            ssid=ssid, mac_origin=mac_origin,
                            ssid_origin=ssid_origin, geo=geo)


class ProbeReqHandler(HandlerBase):
    def __init__(self, frm_queue, event_queue):
        super().__init__(frm_queue, event_queue)
        self.setName('ProbeReqHandler')
        self.log_extra = {'thread_name': self.getName()}

    def parse_frame(self, geo_frame):
        frame, geo, ts = self.decompose_geo_frame(geo_frame)
        mac_origin = 'from_mgmt'
        ssid_origin = 'from_probe_req'
        src = frame.payload.addr2
        ssid = self.extract_ssid(frame)
        if ssid:
            # self.put_events(ts, SSID=True, src=None, ssid=ssid,
            #                 ssid_origin=ssid_origin)
            self.put_events(ts, MAC=True, GEO=True, ASSOCIATION=True,
                            SSID=True, src=src, dst=None, ssid=ssid,
                            mac_origin=mac_origin, ssid_origin=ssid_origin,
                            geo=geo)
        else:
            self.put_events(ts, MAC=True, GEO=True, src=src, geo=geo,
                            mac_origin=mac_origin)


class MgmtHandler(HandlerBase):
    def __init__(self, frm_queue, event_queue):
        super().__init__(frm_queue, event_queue)
        self.setName('MgmtHandler')
        self.log_extra = {'thread_name': self.getName()}

    def parse_frame(self, geo_frame):
        frame, geo, ts = self.decompose_geo_frame(geo_frame)
        sts = FrameSubType.get_type_subtype(frame)
        mac_origin = 'from_mgmt'
        if sts == FrameSubType.PROBE_RESP:
            ssid_origin = 'from_probe_resp'
            src = frame.payload.addr2
            dst = frame.payload.addr1
            ssid = self.extract_ssid(frame)
            if ssid:
                self.put_events(ts, MAC=True, SSID=True, GEO=True,
                                ASSOCIATION=True, src=src, dst=dst, ssid=ssid,
                                mac_origin=mac_origin, ssid_origin=ssid_origin,
                                geo=geo)
            else:
                self.put_events(ts, MAC=True, GEO=True,
                                ASSOCIATION=True, src=src, dst=dst, ssid=ssid,
                                mac_origin=mac_origin, geo=geo)
        elif sts == FrameSubType.ACTION:
            src = frame.payload.addr2
            dst = frame.payload.addr1
            # logger.debug('action: {} -> {}'.format(src, dst))
            self.put_events(ts, MAC=True, GEO=True, ASSOCIATION=True,
                            src=src, dst=dst, geo=geo,
                            ssid=None, mac_origin=mac_origin)


class CtrlHandler(HandlerBase):
    def __init__(self, frm_queue, event_queue):
        super().__init__(frm_queue, event_queue)
        self.setName('CtrlHandler')
        self.log_extra = {'thread_name': self.getName()}

    def parse_frame(self, geo_frame):
        frame, geo, ts = self.decompose_geo_frame(geo_frame)
        sts = FrameSubType.get_type_subtype(frame)
        mac_origin = 'from_ctrl'
        if sts in (FrameSubType.PS_POLL, FrameSubType.RTS,
                   FrameSubType.BLOCK_ACK, FrameSubType.BLOCK_ACK_REQ):
            src = frame.payload.addr2
            dst = frame.payload.addr1
            self.put_events(
                ts, MAC=True, GEO=True, ASSOCIATION=True, src=src,
                dst=dst, geo=geo, ssid=None, mac_origin=mac_origin)


class DataHandler(HandlerBase):
    def __init__(self, frm_queue, event_queue):
        super().__init__(frm_queue, event_queue)
        self.setName('DataHandler')
        self.log_extra = {'thread_name': self.getName()}

    def parse_frame(self, geo_frame):
        frame, geo, ts = self.decompose_geo_frame(geo_frame)
        sts = FrameSubType.get_type_subtype(frame)
        mac_origin = 'from_data'
        if sts in (FrameSubType.NULL_FUNC, FrameSubType.QOS_NULL_FUNC,
                   FrameSubType.QOS_DATA):
            src = frame.payload.addr2
            dst = frame.payload.addr1
            if dst.lower() != 'ff:ff:ff:ff:ff:ff':
                self.put_events(ts, MAC=True, GEO=True, ASSOCIATION=True,
                                src=src, dst=dst, geo=geo, ssid=None,
                                mac_origin=mac_origin)
            else:
                self.put_events(ts, MAC=True, GEO=True, src=src,
                                geo=geo, mac_origin=mac_origin)
