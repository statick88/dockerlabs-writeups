# Surface — 112 Asucar

## nmap (TCP only; see the UDP section for the four instruments that carry the UDP claim)

    $ nmap -sV -Pn -p- --min-rate 2000 172.17.0.12

    Nmap scan report for 172.17.0.12
    Host is up (0.000045s latency).
    Not shown: 65533 closed tcp ports (conn-refused)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.59 ((Debian))
    Service Info: OS: Linux; CPE: cpe:/o/linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 7.82 seconds

## Versions, read from the artefact

    $ grep -n "wp_version = " /var/www/html/wp-includes/version.php
    19:$wp_version = '6.5.3';

    $ /usr/sbin/apache2 -v | head -2
    Server version: Apache/2.4.59 (Debian)
    Server built:   2024-04-05T12:02:26

    $ php -v | head -2
    PHP 8.2.18 (cli) (built: Apr 11 2024 22:07:45) (NTS)
    Copyright (c) The PHP Group

    $ /usr/sbin/sshd -V
    OpenSSH_9.2, OpenSSL 3.0.11 19 Sep 2023

    $ grep PRETTY_NAME /etc/os-release
    PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"

    $ sed -n '8p' /var/www/html/wp-content/plugins/site-editor/site-editor.php
     * Version: 1.1

    $ grep 'Stable tag' /var/www/html/wp-content/plugins/site-editor/readme.txt
    Stable tag: 1.1

    $ /usr/bin/puttygen --help | head -2
    PuTTYgen: key generator and converter for the PuTTY tools
    Release 0.78

## Listening sockets, measured inside

    $ ss -tln
    State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
    LISTEN 0      80         127.0.0.1:3306      0.0.0.0:*
    LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("apache2",pid=25,fd=3))
    LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=47,fd=3))
    LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=47,fd=4))

    4 rows. `ss -tln | tail -n +2 | wc -l` = 4.

## UDP — a count-bearing negative, four independent instruments

    $ echo "ss -lun lines: $(ss -lun | tail -n +2 | wc -l)"            ->  0
    $ echo "netstat -lun lines: $(netstat -lun | tail -n +3 | wc -l)"  ->  0
    $ echo "/proc/net/udp data lines: $(tail -n +2 /proc/net/udp | wc -l)"   ->  0
    $ echo "/proc/net/udp6 data lines: $(tail -n +2 /proc/net/udp6 | wc -l)" ->  0
    $ docker image inspect asucar:latest --format '{{.Config.ExposedPorts}}'
    map[]

`nmap -p-` is TCP by definition. Four instruments reading zero is a measured
absence of a UDP surface, not a blind spot.

## Docroot inventory, with counts

    php files in docroot                       : 1298
    plugin directories in wp-content/plugins   : 1
      /var/www/html/wp-content/plugins/site-editor
    themes in wp-content/themes                : 3
      twentytwentyfour  twentytwentythree  twentytwentytwo

    $ mysql -uwordpress -pSUPERPASSWORD wordpress -N -e "SELECT option_value FROM wp_options WHERE option_name='active_plugins';"
    a:1:{i:0;s:27:"site-editor/site-editor.php";}

    -- a backup / archive / VCS-file sweep of the docroot: 0 matches
    find /var/www/html \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' \
       -o -name '*.swp' -o -name '*~' -o -name '*.zip' -o -name '*.tar.gz' \
       -o -name '.git' -o -name '*.sql' -o -name '*.log' \) | wc -l
    0

## The decoy directory named `wordpress`, measured (not named by resemblance)

    $ ls -la /var/www/html/wordpress
    drwxr-xr-x 2 www-data www-data 4096 May 12  2024 .

    $ find /var/www/html/wordpress -type f | wc -l
    0

    $ curl -s -o wdir.html -w 'GET /wordpress/ : %{http_code} bytes=%{size_download}\n' 'http://172.17.0.12/wordpress/'
    GET /wordpress/ : 200 bytes=746
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <html>
     <head>
      <title>Index of /wordpress</title>
     </head>
     <body>
    <h1>Index of /wordpress</h1>

    $ curl -s -w '%{http_code} bytes=%{size_download}' 'http://172.17.0.12/wordpress/wp-includes/version.php'
    GET /wordpress/wp-includes/version.php : 404 bytes=273

An empty directory, indexed because `asucar.conf` sets `Options Indexes`.

## Virtual hosts, with a name that cannot exist as the control

    Host: asucar.dl               -> 200 bytes=96060 md5=b5bec52b71b29b435186f5563eafaf6c
    Host: www.asucar.dl           -> 301 bytes=0     md5=d41d8cd98f00b204e9800998ecf8427e
    Host: 172.17.0.12             -> 200 bytes=96154 md5=fa36c1e8338d88027422aac7d0bb76b6
    Host: nonexistent-host.invalid-> 200 bytes=96154 md5=fa36c1e8338d88027422aac7d0bb76b6

`nonexistent-host.invalid` shares the IP-address hash, so the IP-address body is
the baseline (the `000-default` vhost). No hidden vhost.

## User enumeration, with the impossible-id control

    GET /?author=1      -> 200 bytes=69513   slug "author/wordpress"   md5=d6849c5f45e36573253d21ca2b2196f6
    GET /?author=2      -> 404 bytes=62735
    GET /?author=3      -> 404 bytes=62735
    GET /?author=4      -> 404 bytes=62735
    GET /?author=5      -> 404 bytes=62735
    GET /?author=99999  -> 404 bytes=62735   md5=2783a9c9de9a0c5c4bfbc1a49f481680

    $ curl -s 'http://172.17.0.12/index.php/wp-json/wp/v2/users'
    [{"id":1,"name":"wordpress","url":"http:\/\/172.17.0.2","description":"","link":"http:\/\/asucar.dl\/index.php\/author\/wordpress\/","slug":"wordpress", ...}]

## What the docroot search did NOT find (counts)

    0 backup/archive/VCS files (above)
    1 WordPress user row  (SELECT user_login FROM wp_users -> wordpress)
    0 wp_ajax_nopriv_* actions registered by the single active plugin
    0 credential-bearing post contents (7 wp_posts rows read, 0 contained one)
