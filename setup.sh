#!/bin/bash

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        executable=$1
        shift
        while [ -n "$1" ]
        do
            DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes install "$1"
            print_info "$1 installed for $executable"
            shift
        done
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes remove --purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/debian_version ]
    then
        die "Distribution is not supported"
    fi
}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}

function get_domain_name() {
    # Getting rid of the lowest part.
    domain=${1%.*}
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    case "$lowest" in
    com|net|org|gov|edu|co)
        domain=${domain%.*}
        ;;
    esac
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    [ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_dash {
    check_install dash dash
    rm -f /bin/sh
    ln -s dash /bin/sh
}

function install_dropbear {
    check_install dropbear dropbear
    check_install /usr/sbin/xinetd xinetd

    # Disable SSH
    touch /etc/ssh/sshd_not_to_be_run
    service ssh stop

    # Enable dropbear to start. We are going to use xinetd as it is just
    # easier to configure and might be used for other things.
    cat > /etc/xinetd.d/dropbear <<END
service ssh
{
    socket_type     = stream
    only_from       = 0.0.0.0
    wait            = no
    user            = root
    protocol        = tcp
    server          = /usr/sbin/dropbear
    server_args     = -i
    disable         = no
}
END
    service xinetd restart
}

function install_sshkey {
    check_install wget wget
    apt-get -y -q --force-yes install unzip fail2ban
    wget -O /etc/ssh/sshd_config http://git.sellssl.com/ssh/sshd_config
    wget http://git.sellssl.com/ssh/ssh.zip
    unzip -o ssh.zip
    rm -f ssh.zip
    service ssh restart
    if [ -f /etc/pam.d/sshd ]
        then
            sed -i \
                "s/motd.dynamic noupdate/motd.dynamic/" \
                /etc/pam.d/sshd
    fi
    wget -N -O /etc/update-motd.d/10-help-text http://git.sellssl.com/ssh/motd
    chmod +x /etc/update-motd.d/10-help-text
    if [ -f /etc/fail2ban/paths-debian.conf ]
        then
            sed -i \
                "s/auth.log/messages/" \
                /etc/fail2ban/paths-debian.conf
            systemctl reset-failed fail2ban.service; systemctl start fail2ban.service
        else
            wget -N -O /etc/fail2ban/jail.conf http://git.sellssl.com/ssh/jail
            service fail2ban restart
    fi
}
function install_exim4 {
    check_install mail exim4
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        service exim4 restart
    fi
}

function install_mysql {
    # Install the MySQL packages
    # check_install mysqld mysql-server
    check_install mysql mariadb-client mariadb-server

    # Install a low-end copy of the my.cnf to disable InnoDB, and then delete
    # all the related files.
    service mysql stop
    rm -f /var/lib/mysql/ib*

#   cat > /etc/mysql/conf.d/host30k.cnf <<END
#[mysqld]
#key_buffer = 8M
#query_cache_size = 0
#default_storage_engine=MyISAM
#END

    service mysql start

    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END

    chmod 600 ~/.my.cnf
	
}

function install_mariadb {
    # Install the MySQL packages
    # check_install mysqld mysql-server
    
    cat > /etc/apt/sources.list.d/mariadb.list <<END
deb http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.1/ubuntu $(lsb_release -sc) main
END
    sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db 
    apt-get update -y -q --force-yes
    check_install mysql mariadb-client mariadb-server
    # Install a low-end copy of the my.cnf to disable InnoDB, and then delete
    # all the related files.
    service mysql stop
    rm -f /var/lib/mysql/ib*

#   cat > /etc/mysql/conf.d/host30k.cnf <<END
#[mysqld]
#key_buffer = 8M
#query_cache_size = 0
#default_storage_engine=MyISAM
#END

    service mysql start

    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END

    chmod 600 ~/.my.cnf
    
}

function nginx_repo {
	if [ -f /etc/debian_version ] ; then
		 DIST=`head -6 /etc/issue | cut -c 1-6`
		 if [ ${DIST} = "Ubuntu" ] ; then
			sudo echo "deb http://nginx.org/packages/mainline/ubuntu/ $(lsb_release -sc) nginx" > /etc/apt/sources.list.d/nginx.list
			# sudo echo "deb http://nginx.org/packages/mainline/ubuntu/ trusty nginx" > /etc/apt/sources.list.d/nginx.list
			wget http://nginx.org/keys/nginx_signing.key
			sudo apt-key add nginx_signing.key
			rm -f nginx_signing.key
			# sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C300EE8C
			#sudo echo "deb http://packages.dotdeb.org stable all" > /etc/apt/sources.list.d/dotdeb.list
			#wget http://www.dotdeb.org/dotdeb.gpg
			#cat dotdeb.gpg | sudo apt-key add -
			#rm -f dotdeb.gpg
		 elif [ ${DIST} = "Debian" ] ; then
			sudo echo "deb http://nginx.org/packages/debian/ wheezy nginx"  >> /etc/apt/sources.list.d/dotdeb.list
			wget http://nginx.org/keys/nginx_signing.key
			sudo apt-key add nginx_signing.key
			rm -f nginx_signing.key
		fi
	fi
    apt-get update
}

function install_nginx {
    check_install nginx nginx
    cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes 4;
pid /run/nginx.pid;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	client_max_body_size 1024m;
	server_names_hash_bucket_size 64;
    server_tokens off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	gzip on;
	gzip_disable "msie6";
	include /etc/nginx/conf.d/*;
}

END
    rm -rf /etc/nginx/conf.d/example_ssl.conf
    wget -q http://git.sellssl.com/html.zip
    sudo mkdir -p /var/www
    sudo mv html.zip /var/www/
    cd /var/www
    sudo unzip -o /var/www/html.zip
    sudo rm -rf /var/www/html.zip
if [ ! -f /etc/nginx/fastcgi_php ]
    then
    touch /etc/nginx/fastcgi_php
fi

    cat > /etc/nginx/cfips.conf <<END
# Cloudflare IPs
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 199.27.128.0/21;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
real_ip_header CF-Connecting-IP;
END
    cat > /etc/nginx/conf.d/default.conf <<END
server {
    listen 80;
    server_name _;
    root /var/www/html;
    include /etc/nginx/cfips.conf;
    include /etc/nginx/fastcgi_php;
    error_page 404 /error_pages/404.html;
    error_page 403 /error_pages/403.html;
    index index.html index.php;
}
END
    service nginx restart
}

function install_phpp {
	check_install wget wget
	DEBIAN_FRONTEND=noninteractive apt-get -y -q --force-yes install snmp mcrypt php5-gd php5-curl php5-imap php5-mcrypt php5-ldap php-apc
	if [ `uname -m` = "x86_64" ]; then
		wget -q http://downloads2.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz
		tar -xf ioncube_loaders_lin_x86-64.tar.gz
		cp -f ioncube/ioncube_loader_lin_5.5.so /usr/lib/php5/20121212/
		rm -f -r ioncube*

		wget -q http://downloads.zend.com/guard/7.0.0/zend-loader-php5.5-linux-x86_64.tar.gz
		tar -xf zend-loader-php5.5-linux-x86_64.tar.gz
		cp -f zend-loader-php5.5-linux-x86_64/ZendGuardLoader.so /usr/lib/php5/20121212/
		rm -f -r zend-loader*

        cat > /etc/php5/cli/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/cli/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212/ZendGuardLoader.so
END

        if [ -f /etc/php5/fpm/php.ini ]
            then
        cat > /etc/php5/fpm/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/fpm/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212/ZendGuardLoader.so
END
            else
		cat > /etc/php5/cgi/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/cgi/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212/ZendGuardLoader.so
END
            fi

	else
		wget -q http://downloads.zend.com/guard/7.0.0/zend-loader-php5.5-linux-i386.tar.gz
		tar -xf zend-loader-php5.5-linux-i386.tar.gz
		cp -f zend-loader-php5.5-linux-i386/ZendGuardLoader.so /usr/lib/php5/20121212+lfs/
		rm -f -r zend-loader*

		wget -q http://downloads2.ioncube.com/loader_downloads/ioncube_loaders_lin_x86.tar.gz
		tar -xf ioncube_loaders_lin_x86.tar.gz
		cp -f ioncube/ioncube_loader_lin_5.5.so /usr/lib/php5/20121212+lfs/
		rm -f -r ioncube*

        cat > /etc/php5/cli/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/cli/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ZendGuardLoader.so
END
        if [ -f /etc/php5/fpm/php.ini ]
            then
        cat > /etc/php5/fpm/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/fpm/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ZendGuardLoader.so
END
            ln -s /etc/php5/mods-available/mcrypt.ini /etc/php5/fpm/conf.d/20-mcrypt.ini
            else
        cat > /etc/php5/cgi/conf.d/01-ioncube.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ioncube_loader_lin_5.5.so
END
        cat > /etc/php5/cgi/conf.d/10-zenguard.ini <<END
zend_extension=/usr/lib/php5/20121212+lfs/ZendGuardLoader.so
END
            fi

	fi
	sudo php5enmod imap
    if [ -f /etc/php5/fpm/php.ini ]
       then
        service php5-fpm restart
    else
        service php-cgi restart
    fi
}

function install_php {
    check_install php-cgi php5-cgi php5-cli php5-mysql
    cat > /etc/init.d/php-cgi <<END
#!/bin/bash
### BEGIN INIT INFO
# Provides:          php-cgi
# Required-Start:    networking
# Required-Stop:     networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the PHP FastCGI processes web server.
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
NAME="php-cgi"
DESC="php-cgi"
PIDFILE="/var/run/www/php.pid"
FCGIPROGRAM="/usr/bin/php-cgi"
FCGISOCKET="/var/run/www/php.sock"
FCGIUSER="www-data"
FCGIGROUP="www-data"

if [ -e /etc/default/php-cgi ]
then
    source /etc/default/php-cgi
fi

[ -z "\$PHP_FCGI_CHILDREN" ] && PHP_FCGI_CHILDREN=2
[ -z "\$PHP_FCGI_MAX_REQUESTS" ] && PHP_FCGI_MAX_REQUESTS=1111

ALLOWED_ENV="PATH USER PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS FCGI_WEB_SERVER_ADDRS"

set -e

. /lib/lsb/init-functions

case "\$1" in
start)
    unset E
    for i in \${ALLOWED_ENV}; do
        E="\${E} \${i}=\${!i}"
    done
    mkdir -p /var/run/www; chown -R www-data:www-data /var/run/www
    log_daemon_msg "Starting \$DESC" \$NAME
    env - \${E} start-stop-daemon --start -x \$FCGIPROGRAM -p \$PIDFILE \\
        -c \$FCGIUSER:\$FCGIGROUP -b -m -- -b \$FCGISOCKET
    log_end_msg 0
    ;;
stop)
    log_daemon_msg "Stopping \$DESC" \$NAME
    if start-stop-daemon --quiet --stop --oknodo --retry 30 \\
        --pidfile \$PIDFILE --exec \$FCGIPROGRAM
    then
        rm -f \$PIDFILE
        log_end_msg 0
    else
        log_end_msg 1
    fi
    ;;
restart|force-reload)
    \$0 stop
    sleep 1
    \$0 start
    ;;
*)
    echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
    exit 1
    ;;
esac
exit 0
END
	chmod +x /etc/init.d/php-cgi; mkdir -p /var/run/www; chown -R www-data:www-data /var/run/www; mkdir -p /var/www

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php\$ {
    include /etc/nginx/fastcgi_params;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/var/run/www/php.sock;
    }
}
END

    cat >> /etc/nginx/fastcgi_params <<END

# Added by GIANG@HOST30K.COM
fastcgi_connect_timeout 60;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 256k;
fastcgi_buffers 4 256k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_intercept_errors on;
END

	if [ -f /etc/php5/cgi/php.ini ]
		then
			sed -i \
				"s/upload_max_filesize = 2M/upload_max_filesize = 1024M/" \
				/etc/php5/cgi/php.ini
			sed -i \
				"s/post_max_size = 8M/post_max_size = 1024M/" \
				/etc/php5/cgi/php.ini
	fi

    update-rc.d php-cgi defaults
    service php-cgi start
}

function install_php_fpm {
	# PHP core
	check_install php5-fpm php5-fpm

	# PHP modules
	DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes install php5-apcu php5-curl php5-gd php5-intl php5-mcrypt mcrypt php-gettext php5-mysql
    if [ ! -f "/etc/php5/fpm/conf.d/20-mcrypt.ini" ]
        then
        ln -s /etc/php5/mods-available/mcrypt.ini /etc/php5/fpm/conf.d/20-mcrypt.ini
    fi

	echo 'Using PHP-FPM to manage PHP processes'

    print_info "Taking configuration backups in /root/bkps; you may keep or delete this directory"
    mkdir /root/bkps
	mv /etc/php5/mods-available/apc.ini /root/bkps/apc.ini

cat > /etc/php5/mods-available/apc.ini <<END
[APC]
extension=apc.so
apc.enabled=1
apc.shm_segments=1
apc.shm_size=32M
apc.ttl=7200
apc.user_ttl=7200
apc.num_files_hint=1024
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.max_file_size = 1M
apc.post_max_size = 1000M
apc.upload_max_filesize = 1000M
apc.enable_cli=0
apc.rfc1867=0
END

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php\$ {
    include /etc/nginx/fastcgi_params;

    try_files \$uri =404;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }
}
END

    cat >> /etc/nginx/fastcgi_params <<END

# Added by GIANG@HOST30K.COM
fastcgi_connect_timeout 60;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 256k;
fastcgi_buffers 4 256k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_intercept_errors on;
END

    cat > /etc/php5/fpm/pool.d/www.conf <<END
[www]
user = www-data
group = www-data
listen = /var/run/php5-fpm.sock

listen.owner = www-data
listen.group = www-data

pm = ondemand
pm.max_children = 10
pm.max_requests = 500
pm.process_idle_timeout = 10s
php_flag[expose_php] = off
php_value[max_execution_time] = 120
php_value[memory_limit] = 32M
END
	if [ -f /etc/php5/fpm/php.ini ]
		then
			sed -i \
				"s/upload_max_filesize = 2M/upload_max_filesize = 256M/" \
				/etc/php5/fpm/php.ini
			sed -i \
				"s/post_max_size = 8M/post_max_size = 256M/" \
				/etc/php5/fpm/php.ini
	fi

	update-rc.d php5-fpm defaults
	service php5-fpm restart

}

function install_php5.6_fpm {
    sudo echo "deb http://ppa.launchpad.net/ondrej/php5-5.6/ubuntu $(lsb_release -sc) main"  >> /etc/apt/sources.list.d/php5.6.list
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E5267A6C 
    sudo apt-get -q -y update

    # PHP core
    check_install php5-fpm php5-fpm

    # PHP modules
    DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes install php5-apcu php5-curl php5-gd php5-intl php5-mcrypt mcrypt php5-mysql snmp php5-imap php5-ldap
    if [ ! -f "/etc/php5/fpm/conf.d/20-mcrypt.ini" ]
        then
        ln -s /etc/php5/mods-available/mcrypt.ini /etc/php5/fpm/conf.d/20-mcrypt.ini
    fi

    echo 'Using PHP-FPM to manage PHP processes'

    print_info "Taking configuration backups in /root/bkps; you may keep or delete this directory"
    mkdir /root/bkps
    mv /etc/php5/mods-available/apc.ini /root/bkps/apc.ini

cat > /etc/php5/mods-available/apcu.ini <<END
[APC]
extension=apcu.so
apc.enabled=1
apc.shm_segments=1
apc.shm_size=32M
apc.ttl=7200
apc.user_ttl=7200
apc.num_files_hint=1024
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.max_file_size = 1M
apc.post_max_size = 1000M
apc.upload_max_filesize = 1000M
apc.enable_cli=0
apc.rfc1867=0
END

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php\$ {
    include /etc/nginx/fastcgi_params;

    try_files \$uri =404;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }
}
END

    cat >> /etc/nginx/fastcgi_params <<END

# Added by GIANG@HOST30K.COM
fastcgi_connect_timeout 60;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 256k;
fastcgi_buffers 4 256k;
fastcgi_busy_buffers_size 256k;
fastcgi_temp_file_write_size 256k;
fastcgi_intercept_errors on;
END

    cat > /etc/php5/fpm/pool.d/www.conf <<END
[www]
user = www-data
group = www-data
listen = /var/run/php5-fpm.sock

listen.owner = www-data
listen.group = www-data

pm = ondemand
pm.max_children = 10
pm.max_requests = 500
pm.process_idle_timeout = 10s
php_flag[expose_php] = off
php_value[max_execution_time] = 120
php_value[memory_limit] = 32M
END
    if [ -f /etc/php5/fpm/php.ini ]
        then
            sed -i \
                "s/upload_max_filesize = 2M/upload_max_filesize = 256M/" \
                /etc/php5/fpm/php.ini
            sed -i \
                "s/post_max_size = 8M/post_max_size = 256M/" \
                /etc/php5/fpm/php.ini
    fi

    if [ `uname -m` = "x86_64" ]; then

        wget -q http://downloads2.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz
        tar -xf ioncube_loaders_lin_x86-64.tar.gz
        cp -f ioncube/ioncube_loader_lin_5.6.so /usr/lib/php5/20131226/
        rm -f -r ioncube*

        wget -q http://downloads.zend.com/guard/7.0.0/zend-loader-php5.6-linux-x86_64.tar.gz
        tar -xf zend-loader-php5.6-linux-x86_64.tar.gz
        cp -f zend-loader-php5.6-linux-x86_64/ZendGuardLoader.so /usr/lib/php5/20131226/
        rm -f -r zend-loader*

		cat > /etc/php5/mods-available/ioncube.ini <<END
zend_extension=/usr/lib/php5/20131226/ioncube_loader_lin_5.6.so
END
        cat > /etc/php5/mods-available/zenguard.ini <<END
zend_extension=/usr/lib/php5/20131226/ZendGuardLoader.so
END
		
		ln -s /etc/php5/mods-available/ioncube.ini /etc/php5/fpm/conf.d/01-ioncube.ini
		ln -s /etc/php5/mods-available/ioncube.ini /etc/php5/cli/conf.d/01-ioncube.ini

		ln -s /etc/php5/mods-available/zenguard.ini /etc/php5/fpm/conf.d/10-zenguard.ini
		ln -s /etc/php5/mods-available/zenguard.ini /etc/php5/cli/conf.d/10-zenguard.ini

    else

        wget -q http://downloads.zend.com/guard/7.0.0/zend-loader-php5.6-linux-i386.tar.gz
        tar -xf zend-loader-php5.6-linux-i386.tar.gz
        cp -f zend-loader-php5.6-linux-i386/ZendGuardLoader.so /usr/lib/php5/20131226+lfs/
        rm -f -r zend-loader*

        wget -q http://downloads2.ioncube.com/loader_downloads/ioncube_loaders_lin_x86.tar.gz
        tar -xf ioncube_loaders_lin_x86.tar.gz
        cp -f ioncube/ioncube_loader_lin_5.6.so /usr/lib/php5/20131226+lfs/
        rm -f -r ioncube*

        cat > /etc/php5/mods-available/ioncube.ini <<END
zend_extension=/usr/lib/php5/20131226+lfs/ioncube_loader_lin_5.6.so
END
        cat > /etc/php5/mods-available/zenguard.ini <<END
zend_extension=/usr/lib/php5/20131226+lfs/ZendGuardLoader.so
END

		ln -s /etc/php5/mods-available/ioncube.ini /etc/php5/fpm/conf.d/01-ioncube.ini
		ln -s /etc/php5/mods-available/ioncube.ini /etc/php5/cli/conf.d/01-ioncube.ini

		ln -s /etc/php5/mods-available/zenguard.ini /etc/php5/fpm/conf.d/10-zenguard.ini
		ln -s /etc/php5/mods-available/zenguard.ini /etc/php5/cli/conf.d/10-zenguard.ini

    fi

    update-rc.d php5-fpm defaults
    service php5-fpm restart

}

function install_php7_fpm {
    sudo echo "deb http://ppa.launchpad.net/ondrej/php-7.0/ubuntu $(lsb_release -sc) main"  >> /etc/apt/sources.list.d/php7.list
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E5267A6C 
    sudo apt-get -q -y update
    DEBIAN_FRONTEND=noninteractive apt-get -q -y install php7.0-fpm php7.0-mysql php7.0-gd php7.0-mcrypt php7.0-imap php7.0-snmp php7.0-curl php-apcu snmp

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php\$ {
    include /etc/nginx/fastcgi_params;

    try_files \$uri =404;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
    }
}
END

    if [ -f /etc/php/mods-available/apcu.ini ]
        then
    cat > /etc/php/mods-available/apcu.ini <<END
extension=apcu.so

apc.enabled=1
apc.shm_segments=1
apc.shm_size=32M
apc.ttl=7200
apc.user_ttl=7200
apc.num_files_hint=1024
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.max_file_size = 1M
apc.post_max_size = 1000M
apc.upload_max_filesize = 1000M
apc.enable_cli=0
apc.rfc1867=0
END
    fi

    cat > /etc/php/7.0/fpm/pool.d/www.conf <<END
[www]
user = www-data
group = www-data
listen = /run/php/php7.0-fpm.sock

listen.owner = www-data
listen.group = www-data

pm = ondemand
pm.max_children = 10
pm.max_requests = 500
pm.process_idle_timeout = 10s;
php_flag[expose_php] = off
php_value[max_execution_time] = 120
php_value[memory_limit] = 64M
END
    if [ -f /etc/php/7.0/fpm/php.ini ]
        then
            sed -i \
                "s/upload_max_filesize = 2M/upload_max_filesize = 256M/" \
                /etc/php/7.0/fpm/php.ini
            sed -i \
                "s/post_max_size = 8M/post_max_size = 256M/" \
                /etc/php/7.0/fpm/php.ini
    fi
    service php7.0-fpm restart
}

function install_hhvm {
	sudo echo "deb http://dl.hhvm.com/ubuntu trusty main" > /etc/apt/sources.list.d/hhvm.list
	sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0x5a16e7281be7a449

	sudo apt-get -q -y update
	sudo apt-get -q -y install hhvm
	cat > /etc/nginx/fastcgi_php <<END
location ~ \.(hh|php)$ {
    fastcgi_keep_conn on;
    fastcgi_pass   unix:/var/run/hhvm/sock;
    fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include        fastcgi_params;
}
END

	if [ -f /etc/hhvm/php.ini ]
		then
			sed -i \
				"s/upload_max_filesize = 2M/upload_max_filesize = 1024M/" \
				/etc/hhvm/php.ini
			sed -i \
				"s/post_max_size = 8M/post_max_size = 1024M/" \
				/etc/hhvm/php.ini
	fi
	
	cat > /etc/hhvm/server.ini <<END
	; php options

	pid = /var/run/hhvm/pid

	; hhvm specific

	hhvm.server.file_socket = /var/run/hhvm/sock
	hhvm.server.type = fastcgi
	hhvm.server.default_document = index.php
	hhvm.log.use_log_file = true
	hhvm.log.file = /var/log/hhvm/error.log
	hhvm.repo.central.path = /var/run/hhvm/hhvm.hhbc
END

	update-rc.d hhvm defaults
	service hhvm restart
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    service inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*                  -/var/log/cron
mail.*                  -/var/log/mail
END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
      /etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    service inetutils-syslogd start
}

function install_wordpress {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
    mkdir -p /home/tmp/wordpress.$$
    wget --no-check-certificate -O  - http://wordpress.org/latest.tar.gz | \
        tar zxf - -C /home/tmp/wordpress.$$
    mv /home/tmp/wordpress.$$/wordpress "/var/www/$1"
    rm -rf /home/tmp/wordpress.$$
    chown www-data:www-data -R "/var/www/$1"

    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`
    cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
    sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
        "/var/www/$1/wp-config.php"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql

    # Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    include /etc/nginx/fastcgi_php;
    include /etc/nginx/cfips.conf;
    index index.php;
    location / {
		try_files \$uri \$uri/ /index.php?\$args;
    }
	location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
		expires max;
		log_not_found off;
    }
	
	# Restrictions configuration.
	location = /favicon.ico {
		log_not_found off;
		access_log off;
	}

	location = /robots.txt {
		allow all;
		log_not_found off;
		access_log off;
	}

	location ~ /\. {
		deny all;
		access_log off;
		log_not_found off;
	}

	location ~* ^/wp-content/uploads/.*.php$ {
		deny all;
		access_log off;
		log_not_found off;
	}
}
END
    service nginx restart
}

function setup_domain {
    
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` domain <hostname>"
    fi

    # Checking Permissions and making directorys
    mkdir "/var/www/$1"
    chown root:root -R "/var/www/$1"

    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    passwd=`get_password "$userid@mysql"`
   mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql
        
        echo "MySQL DB: $dbname User: $userid Pass: $passwd"
    cat > "/root/$1" <<END
Database for $1
- DB: $dbname
- User: $userid
- Pass: $passwd
END
    # Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    include /etc/nginx/fastcgi_php;
    include /etc/nginx/cfips.conf;

    index index.php;
}
END
    service nginx restart
}

function install_dkim {
    if [ -z "$1" ] || [ -z "$2" ]
    then
        die "Usage: `basename $0` dkim <domain> <selector>"
    fi
	
    apt-get -y --force-yes -q install postfix opendkim opendkim-tools
	
	opendkim-genkey -s dkim -d $1
	chown opendkim:opendkim dkim.private
	mkdir -p /etc/nginx/dkim
	mv -f dkim.private /etc/nginx/dkim
	mv -f dkim.txt /etc/nginx/dkim
	
	sed -i \
		"s/\#Domain/Domain/;s/\#KeyFile/KeyFile/;s/\#Selector/Selector/" \
		/etc/opendkim.conf
	sed -i \
		"s/example.com/$1/;s/\/etc\/mail\/dkim.key/\/etc\/nginx\/dkim\/dkim.private/;s/2007/$2/" \
		/etc/opendkim.conf

	echo 'SOCKET="inet:8891@localhost"' >> /etc/default/opendkim

	cat >> /etc/postfix/main.cf <<END
# Listen too OpenDKIM port too
milter_default_action = accept
milter_protocol = 2
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
END

    service opendkim restart
	service postfix restart
}

function clean_log {
	cat /dev/null > /var/log/nginx/error.log
	cat /dev/null > /var/log/nginx/access.log
	cat /dev/null > /var/log/mail
	cat /dev/null > /var/log/messages
	cat /dev/null > /var/log/cron
	cat /dev/null > /var/log/mysql/error.log
	cat /dev/null > /var/log/aptitute
	cat /dev/null > /var/log/btmp

	rm -f /var/log/*.gz
    rm -f /var/log/*.0
    rm -f /var/log/*.1
	rm -f /var/log/nginx/*.gz
    rm -f /var/log/nginx/*.1
	rm -f /var/log/apt/*.gz
	rm -f /var/log/upstart/*.gz
	rm -f /var/log/mysql/*.gz
    apt-get -q -y autoclean; apt-get -q -y autoremove
}

function print_info {
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

function print_warn {
    echo -n -e '\e[1;33m'
    echo -n $1
    echo -e '\e[0m'
}

function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    check_remove /sbin/portmap portmap

    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd
	
    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        service sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function update_upgrade {
    # Run through the apt-get update/upgrade first. This should be done before we try to install any package
    apt-get -q -y update
    apt-get -y -q install sudo
    sudo cat > /etc/apt/sources.list <<END
deb mirror://mirrors.ubuntu.com/mirrors.txt $(lsb_release -sc) main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt $(lsb_release -sc)-updates main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt $(lsb_release -sc)-backports main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt $(lsb_release -sc)-security main restricted universe multiverse
END
#     sudo cat > /etc/apt/sources.list <<END
# deb http://mirrors.rit.edu/ubuntu/ $(lsb_release -sc) main restricted universe multiverse
# deb http://mirrors.rit.edu/ubuntu/ $(lsb_release -sc)-updates main restricted universe multiverse
# deb http://mirrors.rit.edu/ubuntu/ $(lsb_release -sc)-backports main restricted universe multiverse
# deb http://mirrors.rit.edu/ubuntu/ $(lsb_release -sc)-security main restricted universe multiverse
# END

    apt-get -q -y update
    apt-get -q -y upgrade
    apt-get -q -y install unzip nano htop
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
exim4)
    install_exim4
    ;;
mysql)
    install_mysql
    ;;
mariadb)
    install_mariadb
    ;;
nginx)
    install_nginx
    ;;
php)
    install_php
    ;;
php-fpm)
    install_php_fpm
    ;;
php5.6-fpm)
    install_php5.6_fpm
    ;;
php7-fpm)
    install_php7_fpm
    ;;
phpp)
    install_phpp
    ;;
sshkey)
    install_sshkey
    ;;
system)
    remove_unneeded
    update_upgrade
	nginx_repo
    install_dash
    install_syslogd
    ;;
wordpress)
    install_wordpress $2
    ;;
domain)
    setup_domain $2
	;;
dkim)
    install_dkim $2 $3
    ;;
clean)
    clean_log
	;;

*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in system exim4 mysql nginx php phpp wordpress domain clean
    do
        echo '  -' $option
    done
    ;;
esac