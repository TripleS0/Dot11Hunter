import bluetooth
import threading
from base import logger, Dot11HunterBase, CFG


class BtServer(Dot11HunterBase):
    def __init__(self, recv_callback):
        super().__init__()
        # recv_callback is called when receiving geo data from phone
        self.recv_callback = recv_callback
        self.setName('BtServer')
        self.log_extra = {'thread_name': self.getName()}
        self.server_socket = None
        self.socks = list()

    def init_socket(self):
        self.server_socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        self.server_socket.bind(('', bluetooth.PORT_ANY))
        self.server_socket.listen(1)
        port = self.server_socket.getsockname()[1]
        uuid = CFG['BLUETOOTH']['UUID']
        bluetooth.advertise_service(self.server_socket, "sampleserver",
                                    service_id=uuid,
                                    service_classes=[uuid,
                                                     bluetooth.SERIAL_PORT_CLASS],
                                    profiles=[bluetooth.SERIAL_PORT_PROFILE])
        logger.info('BtServer is listening on port {}.'.format(port),
                    extra=self.log_extra)

    def send(self, data):
        for sock in self.socks:
            sock.send(data.encode('utf-8'))

    def run(self):
        self.init_socket()
        while True:
            logger.info('waiting for connecting...', extra=self.log_extra)
            sock, info = self.server_socket.accept()
            logger.info('{}  connected!'.format(str(info[0])),
                        extra=self.log_extra)
            self.socks.append(sock)
            t = threading.Thread(target=self.serve_socket,
                                 args=(sock, info[0]))
            t.start()

    def serve_socket(self, sock, info):
        while True:
            try:
                rcv = sock.recv(1024).decode('utf-8')
                self.recv_callback(rcv)
            except Exception as e:
                self.socks.remove(sock)
                logger.critical(str(e), extra=self.log_extra)
