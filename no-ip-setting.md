After create a account on no-ip.com

# Dynamic DNS Update Client (DUC) for Linux
```bash
wget http://www.no-ip.com/client/linux/noip-duc-linux.tar.gz
tar vzxf noip-duc-linux.tar.gz
cd noip-2.1.9-1
make
sudo make install
```

During `make` you may enconter some warning messages
```bash
oip2.c: In function ‘dynamic_update’:
noip2.c:1595:6: warning: variable ‘i’ set but not used [-Wunused-but-set-variable]
  int i, x, is_group, retval, response;
      ^
noip2.c: In function ‘domains’:
noip2.c:1826:13: warning: variable ‘x’ set but not used [-Wunused-but-set-variable]
         int x;
             ^
noip2.c: In function ‘hosts’:
noip2.c:1838:20: warning: variable ‘y’ set but not used [-Wunused-but-set-variable]
         int     x, y, z;
                    ^
```

And when `sudo make install` you may like to enter your account and password you register in no-ip.com
```bash
if [ ! -d /usr/local/bin ]; then mkdir -p /usr/local/bin;fi
if [ ! -d /usr/local/etc ]; then mkdir -p /usr/local/etc;fi
cp noip2 /usr/local/bin/noip2
/usr/local/bin/noip2 -C -c /tmp/no-ip2.conf

Auto configuration for Linux client of no-ip.com.

Multiple network devices have been detected.

Please select the Internet interface from this list.

By typing the number associated with it.
0	wlan0
1	wlan0
0
Please enter the login/email string for no-ip.com  example@gmail.com
Please enter the password for user 'example@gmail.com'  ************

Only one host [m4sherman.ddns.net] is registered to this account.
It will be used.
Please enter an update interval:[30]
Do you wish to run something at successful update?[N] (y/N)  ^M
```

And it will be work if you ip forwaring setting properly.

# Run

## run in background
`/usr/local/bin/noip2`

## at first in background
```
sudo vim /etc/rc.local
# Active no-ip
/usr/local/bin/noip2
```