from datetime import datetime
from base import Dot11HunterBase, CFG, logger, RepeatedTimer, Dot11HunterUtils


class EventHandler(Dot11HunterBase):
    # Handle event queues to save them in database
    def __init__(self, event_queue):
        super().__init__()
        self.setName('EventHandler')
        self.log_extra = {'thread_name': self.getName()}
        self.event_queue = event_queue
        # Cache current records to lower database burden
        self.mac_cache = dict()
        self.ssid_cache = dict()
        self.asocit_cache = dict()
        self.geo_cache = dict()
        self.event_counters = {
            'MAC_new': 0,
            'MAC': 0,
            'SSID_new': 0,
            'SSID': 0,
            'GEO_new': 0,
            'GEO': 0,
            'ASSOCIATION_new': 0,
            'ASSOCIATION': 0
        }
        self.db_conn, self.db_cursor = Dot11HunterUtils.connect_db()
        self.clear_cache_timer = RepeatedTimer(func=self.clear_cache,
                                               interval=120)
        self.clear_cache_timer.start()

    def dump_log(self):
        crnt_size = self.event_queue.qsize()
        logger.info('buffered {} events'.format(crnt_size),
                    extra=self.log_extra)
        logger.info('recorded {}/{} MAC, {}/{} SSID, {}/{} GEO, '
                    '{}/{} ASSOCIATION'.format(
                                       self.event_counters['MAC_new'],
                                       self.event_counters['MAC'],
                                       self.event_counters['SSID_new'],
                                       self.event_counters['SSID'],
                                       self.event_counters['GEO_new'],
                                       self.event_counters['GEO'],
                                       self.event_counters['ASSOCIATION_new'],
                                       self.event_counters['ASSOCIATION']),
                    extra=self.log_extra)
        # clear counts
        for k in self.event_counters.keys():
            self.event_counters[k] = 0

    def run(self):
        while True:
            try:
                while True:
                    event = self.event_queue.get()
                    # continue
                    if event.type == Dot11Event.MAC:
                        self.event_counters['MAC'] += 1
                        if self.handle_mac(event):
                            self.event_counters['MAC_new'] += 1
                    elif event.type == Dot11Event.SSID:
                        self.event_counters['SSID'] += 1
                        if self.handle_ssid(event):
                            self.event_counters['SSID_new'] += 1
                    elif event.type == Dot11Event.GEO:
                        self.event_counters['GEO'] += 1
                        if self.handle_geo(event):
                            self.event_counters['GEO_new'] += 1
                    elif event.type == Dot11Event.ASSOCIATION:
                        self.event_counters['ASSOCIATION'] += 1
                        if self.handle_association(event):
                            self.event_counters['ASSOCIATION_new'] += 1
            except Exception as e:
                logger.critical('{}'.format(str(e)), extra=self.log_extra)

    def clear_cache(self):
        # Clear cached records
        # count = 0
        for cache in zip([self.mac_cache, self.ssid_cache, self.asocit_cache],
                         ['mac_update_interval', 'ap_update_interval',
                          'association_update_interval']):
            for k in list(cache[0].keys()):
                delta = datetime.now() - cache[0][k]
                if delta.seconds >= CFG['MYSQL'].getfloat(cache[1]):
                    del cache[0][k]

    @staticmethod
    def is_fresh(key, timestamp, cache, threshold):
        result = False
        if key in cache.keys():
            delta = timestamp - cache[key]
            # Ignore the event not fresher enough
            if delta.days < 0 or \
                    (delta.days >= 0 and delta.seconds <= threshold):
                return result
        result = True
        cache[key] = timestamp
        return result

    def handle_mac(self, event):
        # Save and update the mac address
        result = False
        mac_addr = int(event.src.replace(':', ''), 16)   # mac is an int
        thold = CFG['MYSQL'].getfloat('mac_update_interval')
        if not self.is_fresh(mac_addr, event.timestamp, self.mac_cache, thold):
            return result
        self.db_cursor = self.db_conn.cursor()
        sql = 'SELECT id, count FROM mac WHERE addr=%s'
        self.db_cursor.execute(sql, (mac_addr,))
        row = self.db_cursor.fetchall()
        if not row:
            sql = 'INSERT INTO mac (addr, first_seen, last_seen, count, {}) ' \
                  'values (%s, %s, %s, %s, %s)'.format(event.origin)
            data = (mac_addr, event.timestamp, event.timestamp, 1, True)
            self.db_cursor.execute(sql, data)
            self.db_conn.commit()
            result = True
        else:
            id_ = row[0][0]
            last_count = row[0][1]
            sql = 'UPDATE mac SET last_seen=%s, count=%s, {}=%s WHERE ' \
                  'id=%s'.format(event.origin)
            data = (event.timestamp, last_count + 1, True, id_)
            self.db_cursor.execute(sql, data)
            self.db_conn.commit()
            result = True
        return result

    def fetch_mac_id(self, mac_addr):
        result = None
        sql = 'SELECT id FROM mac WHERE addr=%s'
        self.db_cursor.execute(sql, (mac_addr,))
        rows = self.db_cursor.fetchall()
        if rows:
            result = rows[0][0]
        return result

    def handle_ssid(self, event):
        # Use ssid as key may result in error when two different APs have same
        # SSID. Thus, MAC address is preferred.
        result = False
        mac_addr = event.src
        if mac_addr is not None:
            mac_addr = int(event.src.replace(':', ''), 16)
            cache_key = mac_addr
        else:
            mac_addr = None
            cache_key = event.ssid
        cache_key = (cache_key, event.origin)
        thold = CFG['MYSQL'].getfloat('ap_update_interval')
        if not self.is_fresh(cache_key, event.timestamp, self.ssid_cache, thold):
            return
        if mac_addr is not None:
            insert_flag = True
            sql = 'SELECT ap.id, ap.ssid, mac.id, ap.count FROM ap JOIN mac ' \
                  'ON ap.mac_id=mac.id AND mac.addr=%s'
            self.db_cursor.execute(sql, (mac_addr,))
            rows = self.db_cursor.fetchall()
            if not rows:
                pass
            else:
                for row in rows:
                    id_, ssid, mac_id, count = row
                    if event.ssid == ssid:
                        insert_flag = False
                        sql = 'UPDATE ap SET last_seen=%s, count=%s, {}=%s ' \
                              'WHERE id=%s'.format(event.origin)
                        data = (event.timestamp, count+1, True, id_)
                        self.db_cursor.execute(sql, data)
                        self.db_conn.commit()
                        result = True
                        break
            if insert_flag:
                mac_id = self.fetch_mac_id(mac_addr)
                if mac_id is None and event.origin == 'from_beacon':
                    raise RuntimeError('Beacon SSID is inserted before MAC')
                sql = 'INSERT INTO ap (ssid, mac_id, first_seen, last_seen, ' \
                      'count, {}) ' \
                      'VALUES (%s, %s, %s, %s, %s, %s)'.format(event.origin)
                data = (event.ssid, mac_id, event.timestamp, event.timestamp,
                        1, True)
                self.db_cursor.execute(sql, data)
                self.db_conn.commit()
                result = True
        else:
            # The ssid is from probe_req
            # There may be such error: AP_A has SSID, and STA probes AP_B
            # whose ssid is also SSID, then it is difficult to know which AP
            # SSID belongs to. Here SSID is considered to belong to the
            # first record in database whose ssid=SSID.
            if not event.ssid:
                # Sometimes the ssid is an empty string
                return
            sql = 'SELECT id, count FROM ap WHERE ssid=%s'
            self.db_cursor.execute(sql, (event.ssid,))
            row = self.db_cursor.fetchall()
            if not row:
                sql = 'INSERT INTO ap (ssid, first_seen, last_seen, count, '\
                      '{}) VALUES (%s, %s, %s, %s, %s)'.format(event.origin)
                data = (event.ssid, event.timestamp, event.timestamp, 1, True)
                self.db_cursor.execute(sql, data)
                self.db_conn.commit()
                result = True
            else:
                id_, count = row[0]
                sql = 'UPDATE ap SET last_seen=%s, count=%s, {}=%s ' \
                      'WHERE id=%s'.format(event.origin)
                data = (event.timestamp, count + 1, True, id_)
                self.db_cursor.execute(sql, data)
                self.db_conn.commit()
                result = True
        return result

    def handle_geo(self, event):
        # Save the latitude and longitude of mac address
        result = False
        # geo is not available
        if not event.geo:
            return result
        mac_addr = int(event.src.replace(':', ''), 16)  # mac is an int
        thold = CFG['MYSQL'].getfloat('geo_update_interval')
        if not self.is_fresh(mac_addr, event.timestamp, self.geo_cache, thold):
            return result
        sql = 'SELECT id FROM mac WHERE addr=%s'
        self.db_cursor = self.db_conn.cursor()
        self.db_cursor.execute(sql, (mac_addr,))
        row = self.db_cursor.fetchall()
        if not row:
            logger.warn('MAC address {} not found in database'
                        ''.format(event.src), extra=self.log_extra)
            result = False
        else:
            mac_id = row[0][0]
            sql = 'INSERT INTO geo (mac_id, latitude, longitude, seen) ' \
                  'VALUES (%s, %s, %s, %s)'
            data = (mac_id, event.geo['latitude'], event.geo['longitude'],
                    event.timestamp)
            self.db_cursor.execute(sql, data)
            self.db_conn.commit()
            result = True
        return result

    def get_sta_ap_id(self, src, dst, ssid):
        sta_id = None
        ap_id = None
        src_mac_id = None
        dst_mac_id = None
        ap_is = None    # 'src' or 'dst'
        sql_mac_id = 'SELECT id FROM mac WHERE addr=%s'
        if src:
            self.db_cursor.execute(sql_mac_id, (src, ))
            row = self.db_cursor.fetchall()
            if row:
                src_mac_id = row[0][0]
            else:
                logger.warn('source mac: {} not found'.format(src),
                            extra=self.log_extra)
        if dst:
            self.db_cursor.execute(sql_mac_id, (dst,))
            row = self.db_cursor.fetchall()
            if row:
                dst_mac_id = row[0][0]
            else:
                logger.warn('dst mac: {} not found'.format(dst),
                            extra=self.log_extra)
        if src_mac_id and not ap_id:
            sql_q = 'SELECT id FROM ap WHERE mac_id=%s'
            self.db_cursor.execute(sql_q, (src_mac_id, ))
            row = self.db_cursor.fetchall()
            if row:
                ap_id = row[0][0]
                ap_is = 'src'
        if ssid and not ap_id:
            # for probe_req only
            sql_ssid = 'SELECT id FROM ap WHERE ssid=%s'
            self.db_cursor.execute(sql_ssid, (ssid,))
            row = self.db_cursor.fetchall()
            if row:
                ap_id = row[0][0]
                sta_id = src_mac_id
                return sta_id, ap_id
            else:
                logger.warn('ssid: {} not found in ap'.format(ssid),
                            extra=self.log_extra)
        if dst and not ap_id:
            sql_q = 'SELECT id FROM ap WHERE mac_id=%s'
            self.db_cursor.execute(sql_q, (dst_mac_id,))
            row = self.db_cursor.fetchall()
            if row:
                ap_id = row[0][0]
                ap_is = 'dst'
        if ap_id:
            if ap_is == 'src':
                sta_id = dst_mac_id
            elif ap_is == 'dst':
                sta_id = src_mac_id
        return sta_id, ap_id

    def handle_association(self, event):
        # Note: if mac or ssid of AP is not seen before, this association will
        # be discard
        # src->dst: sta_mac -> ap_ssid, sta_mac -> ap_mac, ap_mac -> sta_mac,
        result = False
        src = int(event.src.replace(':', ''), 16)
        if event.dst:
            dst = int(event.dst.replace(':', ''), 16)
        else:
            dst = None
        ts = event.timestamp
        ssid = event.ssid
        sta_id, ap_id = self.get_sta_ap_id(src, dst, ssid)
        thold = CFG['MYSQL'].getfloat('association_update_interval')
        if not self.is_fresh((sta_id, ap_id), ts, self.asocit_cache, thold):
            return
        if not sta_id or not ap_id:
            # logger.warn('STA or AP not in db. src: {}, dst: {}, ssid: {}'
            #             .format(event.src, event.dst, event.ssid),
            #             extra=self.log_extra)
            return result
        sql_q = 'SELECT id FROM association WHERE mac_id=%s and ap_id=%s'
        self.db_cursor.execute(sql_q, (sta_id, ap_id))
        row = self.db_cursor.fetchall()
        if row:
            sql_u = 'UPDATE association SET last_seen=%s WHERE id=%s'
            self.db_cursor.execute(sql_u, (ts, row[0][0]))
            self.db_conn.commit()
            result = True
        else:
            sql_i = 'INSERT INTO association (mac_id, ap_id, first_seen, ' \
                    'last_seen) VALUES (%s, %s, %s, %s)'
            data = (sta_id, ap_id, ts, ts)
            self.db_cursor.execute(sql_i, data)
            self.db_conn.commit()
            result = True
        return result


class Dot11Event:
    SSID = 0x01
    MAC = 0x02
    ASSOCIATION = 0x03
    GEO = 0x04

    def __init__(self, src=None, dst=None, timestamp=None, geo=None,
                 type=None, ssid=None, origin=None):
        # mac address
        self.src = src
        self.dst = dst
        self.timestamp = timestamp
        self.geo = geo
        self.type = type    # event type:
        self.ssid = ssid
        self.origin = origin    # frame type

    def dump(self):
        print('src: %s, dst: %s, ssid: %s, time: %s'
              % (self.src, self.dst, self.ssid, self.geo))
