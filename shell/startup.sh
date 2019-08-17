PATH=/usr/local/sbin:$PATH
PATH=/usr/local/bin:$PATH
PATH=/usr/sbin:$PATH
PATH=/sbin:$PATH
/usr/sbin/service mariadb start
/usr/sbin/airmon-ng check kill
/usr/sbin/airmon-ng start wlan1
sleep 120
cd dot11hunter
(nohup /usr/bin/python3 dot11hunter.py -i wlan1 &)