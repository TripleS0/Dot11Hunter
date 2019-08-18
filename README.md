# Dot11Hunter
A tool to capture MAC addresses, SSID, the **association** between them and the **location** where they are seen. It is built on a Raspberry Pi with a WiFi Dongle working in promiscuous mode.


## Getting Started


### Prerequisites
#### Hardware 
* Dot11Hunter system consists of a capture computer and an Android phone.
* The capture computer should support bluetooth and have a WLAN interface working in promiscuous mode. Recommended one:
    + Raspberry Pi Model 3B+
    + [Kali Linux ARM Images](https://www.offensive-security.com/kali-linux-arm-images/) for Raspberry Pi Foundation
    + One from [RPi USB Wi-Fi Adapters](https://elinux.org/RPi_USB_Wi-Fi_Adapters)
* The Android phone should also support bluetooth and be Internet connected. It runs Dot11Hunter app to provide current location (latitude and longitude) to the capture computer and monitor it.
* A power bank powering the capture computer if it moves, such as deploying the system in a car.


### Installing on capture computer

Install packages in Kali Linux 

```
apt install python3-pip mariadb-server libbluetooth-dev bluetooth aircrack-ng
```

Install python3 packages 
```
pip3 install scapy mysql-connector-python psutil PyBluez
```

Create database
```sql
create schema dot11hunter;
use dot11hunter;
source database/dot11hunter.sql
```

Configure config.ini
```
[MYSQL]
user: your user name
password: your password
database: dot11hunter
```

Auto run at startup (optional)  
run in shell `# crontab -e` and add at the end

```
@reboot /your_path/dot11hunter/shell/startup.sh
```
note that `(nohup /usr/bin/python3 dot11hunter.py -i wlan1 &)` in `startup.sh` should set to be your correct WLAN interface in monitor mode.

### Installing on Android phone
Install the app `android_app/Dot11Hunter.apk`. Grant bluetooth and location permission to it.

## Running
On capture computer:   
1. Pair the bluethooth of capture computer and Android phone. Here is the guide of how to [Pair a Raspberry Pi and Android phone](https://bluedot.readthedocs.io/en/latest/pairpiandroid.html).
2. Start mysql service and wlan monitoring. The wlan interface should be your own correct one.
    ```shell
    # service mariadb start
    # airmon-ng check kill
    # airmon-ng start wlan1
    ```
3. Run `# python3 dot11hunter.py -i wlan1 ` . If it works, you will see 

4. On Android phone, start Dot11Hunter, search your capture computer and connect to it. If everything works fine, you will see
<img src="https://github.com/SecHeart/Dot11Hunter/blob/master/pictures/android_dot11hunter.png">

If every thing works fine, the capture computer and Android phone would show as the pictures.


## License

This project is licensed under the GNU License - see the [LICENSE.md](LICENSE.md) file for details


