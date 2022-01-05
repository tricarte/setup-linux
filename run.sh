#!/usr/bin/env bash

if [ "$(id -u)" == "0" ]; then
   echo "This script must not be run as root." 1>&2
   exit 1
fi

# https://devhints.io/bash For quick bash reference
# https://usedevbook.com stackoverflow and language documentation searcher.

# https://gist.githubusercontent.com/BAGELreflex/c04e7a25d64e989cbd9376a9134b8f6d/raw/eea51d63d32dc97ff434a75b192eccaf66609ffb/cdm_fio.sh
# Copy above fio script to bin and `cdm_fio.sh ./`. Change $LOOP variable. IO Benchmark

# TODO: 7G Firewall now supports nginx. It's a very easy installation.
# Just take care of accidental multiple inclusion of 7g conf files from both nginx.conf and
# virtual hosts.

# TODO: https://github.com/lemnos/theme.sh Easily change terminal colors

# I'm using git instead of stow for dotfiles.
# https://www.anand-iyer.com/blog/2018/a-simpler-way-to-manage-your-dotfiles.html

# SERVER: After configuring ssmtp or msmtp correctly, you do not have to touch php.ini.
# Because these smtp clients creates symlinks to sendmail which is used by PHP by default.

# TODO: Disable nginx and mariadb if this is a desktop.
# TODO: dropwatch
# TODO: https://github.com/rahulunair/repo-peek Tool to browse Github/Gitlab
# repo using vim.
# TODO: Change /etc/vnstat.conf interface name using GWIFACE. vnstat auto detects the
# outgoing interface. This is probably necessary for php-vnstat thing.
# TODO: apticron thing.
# TODO: You may consider disabling motd dynamic news. 
    # vim /etc/default/motd-news:
    # ENABLED=0
# TODO: https://github.com/meesaltena/SSHHeatmap
# TODO: Is nginx is installed disabled?
# TODO: https://github.com/vinceliuice/grub2-themes Use "tela" theme.
# TODO: disable performance_schema = off for mysql/mariadb
# TODO: mysql_secure_installation and mysqltuner after the installation.
# mysql_secure_installation can be scripted in SQL.
: "
#!/usr/bin/env bash

mysql -sfu root <<EOS
-- set root password
UPDATE mysql.user SET Password=PASSWORD('complex_password') WHERE User='root';
-- delete anonymous users
DELETE FROM mysql.user WHERE User='';
-- delete remote root capabilities
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- drop database 'test'
DROP DATABASE IF EXISTS test;
-- also make sure there are lingering permissions to it
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- make changes immediately
FLUSH PRIVILEGES;
EOS
"
# TODO: https://github.com/eafer/rdrview Command line html/webpage viewer.
# TODO: https://github.com/strizhechenko/netutils-linux This may be only useful for
# real servers. A set of tools for monitoring and tuning the network stack.
# TODO: https://github.com/skx/sysadmin-util
# TODO: Consider using shush or cronic instead of cron.
# TODO: golang can be installed with this script easily.
# https://github.com/udhos/update-golang
# TODO: themer.dev: Generate colorschemes for terminal, editors, wallpapers
# TODO:
# sudo vim /etc/systemd/journald.conf
# storage=volatile
# systemmaxfilesize=50M
# systemmaxfiles=5

# SSH Host Config Example
# Put this to .ssh/config
# Host racknerd
#     HostName remote-host-ip-address
#     User userName
#     Port portNumber
#     IdentityFile ~/.ssh/private-key-file
#     IdentitiesOnly yes

# Installing prerequisites
sudo apt install git software-properties-common rsync -y

GWIFACE=$(ip route | grep default | cut -d" " -f5)
IPADDR=$(hostname -I)

if [[ ! $GWIFACE =~ ^[we] ]]; then
    echo "You are not connected to the internet through wireless or ethernet card..."
    echo ""
    exit 1
fi

# Username and password are for gitlab. And they are only used when
# cloning private dotfiles_ng repository.
read -rp "Enter your github/gitlab username: " GITUSERNAME
# Not using password any more because of ssh keys. You must configure your
# gitlab ssh keys before running this script.
# read -rsp "Enter your github/gitlab password: " GITPASSWORD
echo
read -rp "Enter your email address: " GITEMAIL

echo "Is this a server or desktop?"
select machine in Server Desktop
do
    case $machine in
        Server)
        SERVER=1
        break
        ;;
        Desktop)
        SERVER=0
        break
        ;;
        *)
        echo "Select either 1 or 2."
        ;;
esac
done

# git ls-remote "https://$GITUSERNAME:$GITPASSWORD@gitlab.com/tricarte/dotfiles_ng.git" > /dev/null 2>&1 \
#     || ( echo "Gitlab credentials are not working. Exiting..."; exit 1; )
git ls-remote "git@gitlab.com:tricarte/dotfiles_ng.git" > /dev/null 2>&1 \
    || ( echo "Gitlab credentials are not working. Exiting..."; exit 1; )
    
if [[ $SERVER == 1 ]]; then
    read -rp "Would you like to create a new user with root privileges: (y/n) "
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        read -rp "Enter new user name: " USRNAME
        if [[ -n $USRNAME ]]; then
            sudo useradd -m "$USRNAME" -G sudo --shell /bin/bash
            sudo passwd "$USRNAME"
            sudo passwd -l root
        fi
    fi
fi

if [[ $SERVER == 1 ]]; then
    read -rp "What port would you like to use for the ssh server?: " SSHPORT
fi

# https://gist.github.com/lukechilds/a83e1d7127b78fef38c2914c4ececc3c
# Get the latest release version number of a github project.
get_latest_release() {
    curl --silent "https://api.github.com/repos/$1/releases/latest" | # Get latest release from GitHub api
        grep '"tag_name":' |                                            # Get tag line
        sed -E 's/.*"([^"]+)".*/\1/'                                    # Pluck JSON value
    }

##################
#  List of PPAs  #
##################
PPAS=(
    "ppa:ondrej/php"
    "ppa:ondrej/nginx"
    "ppa:jonathonf/vim-daily"
    "ppa:bashtop-monitor/bashtop"
)

for ppa in "${PPAS[@]}"
do
    sudo add-apt-repository -y "$ppa" -n
done

sudo apt update -y && sudo apt upgrade -y

if [[ $SERVER == 1 ]]; then
    # This may only be necessary in cloud servers.
    echo "Europe/Istanbul" | sudo tee /etc/timezone
    # Below command didn't reconfigure tzdata but the other one worked:
    # sudo dpkg-reconfigure tzdata
    sudo dpkg-reconfigure --frontend noninteractive tzdata
fi

# sysctl.conf settings
if [[ $SERVER == 1 ]]; then
    echo "
################################################################################
#  http://www.cyberciti.biz/tips/linux-unix-bsd-nginx-webserver-security.html  #
################################################################################

# Avoid a smurf attack
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Turn on protection for bad icmp error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Turn on syncookies for SYN flood attack protection
net.ipv4.tcp_syncookies = 1

# Turn on and log spoofed, source routed, and redirect packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# No source routed packets here
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Turn on reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Make sure no one can alter the routing tables
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Don't act as a router
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Turn on execshild (general worm or automated remote attack protection)
# dmesg | grep --color '[NX|DX]*protection' if you see "active", then
# this is the same as kernel.exec-shield = 1
# kernel.exec-shield = 1
kernel.randomize_va_space = 1

# Tune IPv6
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

# Allowed local port range
# https://easyengine.io/tutorials/linux/sysctl-conf/
# default is 32768 61000
net.ipv4.ip_local_port_range = 2000 65535

# http://www.linuxbrigade.com/reduce-time_wait-socket-connections/
# Decrease TIME_WAIT seconds
net.ipv4.tcp_fin_timeout = 30
# Recycle and Reuse TIME_WAIT sockets faster
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
# https://easyengine.io/tutorials/linux/sysctl-conf/
net.ipv4.tcp_max_tw_buckets = 1440000

# Decrease the time default value for connections to keep alive
# https://easyengine.io/tutorials/linux/sysctl-conf/
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Protect Against TCP Time-Wait assasination.
# This is an RFC not standard.
# There may be edge cases so disablet it for now.
# https://easyengine.io/tutorials/linux/sysctl-conf/
# net.ipv4.tcp_rfc1337 = 1

# Optimization for port usefor LBs
# Increase system file descriptor limit
fs.file-max = 65535

net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1

######################
#  End of cyberciti  #
######################

# Digital Ocean Recommended Settings:
# Maximum Socket Send Buffer
net.core.wmem_max=12582912
# Maximum Socket Receive Buffer
net.core.rmem_max=12582912
net.ipv4.tcp_rmem= 10240 87380 12582912
net.ipv4.tcp_wmem= 10240 87380 12582912

# Below network settings are coming from
# https://easyengine.io/tutorials/linux/sysctl-conf/

# Default Socket Receive Buffer
net.core.rmem_default = 31457280

# Default Socket Send Buffer
net.core.wmem_default = 31457280

# Increase number of incoming connections
net.core.somaxconn = 4096

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 65536

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 25165824

# Increase the maximum total buffer-space allocatable
# This is measured in units of pages (4096 bytes)
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384

vm.swappiness = 10
vm.vfs_cache_pressure=50

" | sudo tee -a /etc/sysctl.conf
fi

cd ~ || exit
sudo apt update -y && sudo apt upgrade -y

if [[ $SERVER == 1 ]]; then
    if [[ -f /etc/ssh/sshd_config ]]; then
        sudo sed -i -e "s/#Port 22/Port ${SSHPORT}/g" /etc/ssh/sshd_config
        # TODO: Other settings:
        # AddressFamily inet : to disable IPv6
        # PubkeyAuthentication yes
        # PasswordAuthentication no
        # PermitRootLogin no
        sudo systemctl restart ssh
    fi
fi

mkdir "$HOME/dotfiles-original"
cp .bashrc .profile "$HOME/dotfiles-original"

if [[ $SERVER == 1 ]]; then
    # Check these permissions from sshkeygen.io
    # Remember to chmod if you restore your backup keys
    # chmod 0600 $HOME/.ssh/private_key
    [ -d "$HOME/.ssh" ] || mkdir "$HOME/.ssh"
    chmod 0700 "$HOME/.ssh"
    touch "$HOME/.ssh/authorized_keys"
    chmod 0600 "$HOME/.ssh/authorized_keys"
fi

# NOTICE: Nearly 2GB swap is enabled by default in Ubuntu server.
# dd if=/dev/zero of=swap_file bs=1024k count=1536
# sudo chmod 0600 swap_file
# sudo chown root:root swap_file
# sudo mkswap swap_file
# sudo swapon swap_file

mkdir -p "$HOME/bin"  \
    "$HOME/.local/share/psysh" \
    "$HOME/repos"  \
    "$HOME/.npm-global"  \
    "$HOME/.vim-git-backups"  \
    "$HOME/sites" \
    "$HOME/.composer"

# renameutils provides imv that can rename files with long names easily.
# mtr-tiny:  Interactive traceroute alternative.
# pydf: More human friendly df.
# ncdu: Sort files by size.
# highlight: convert source code to formatted text.
# secure-delete: Provides srm instead of rm.
# libncurses5 is needed for nettop
# mailutils provide mailx which is used by ngxblocker to send its mails.
# darkstat can be an alternative to vnstat with web interface.
# You can use "gdebi" instead of "dpkg -i" to install packages with their dependencies.
# chkservice: list/start/stop systemd services.
# pv: pipe viewer
# hey: http load testing - alternative ab (apache benchmark)
sudo apt install -y python3-pip xsel mtr-tiny pydf \
  software-properties-common \
  build-essential libssl-dev cmake pkg-config \
  zip unzip autojump highlight par \
  ncdu htop vnstat iftop mosh ranger httpie \
  lnav atool silversearcher-ag lynx multitail \
  shellcheck sqlite3 dnstop libpcap-dev libncurses5-dev \
  libsqlite3-dev autoconf secure-delete \
  curl stow dnsutils git gawk mediainfo rlwrap ppa-purge \
  apache2-utils ntpdate watchman incron hey \
  renameutils libncurses5 mysqltuner gdebi-core mailutils \
  iotop lshw hwinfo pv libnss3-tools jq chkservice \
  optipng pngquant jpegoptim imagemagick

if [[ $SERVER == 1 ]]; then
    sudo chmod u+s /usr/sbin/ntpdate
    ntpdate -u ntp.ubuntu.com
fi

# Install nginx and php 7.4 both from ondrej/ppa
# This one uses nginx from ondrej.
sudo apt install -y nginx libnginx-mod-http-cache-purge php7.4-fpm php7.4-cli \
    php7.4-pgsql php7.4-sqlite3 php7.4-gd \
    php7.4-curl php-memcached \
    php7.4-mysql php7.4-mbstring php7.4-tidy \
    php7.4-xml php7.4-bcmath php7.4-soap \
    php7.4-intl php7.4-readline php-imagick \
    php-msgpack php-igbinary php7.4-dev php7.4-zip php7.4-imap \
    php7.4-gmp php-redis

# Build and install Vim
# It also has GVIM.
# sudo apt remove --purge vim vim-common vim-runtime vim-tiny -y
# sudo apt install -y libx11-dev libxpm-dev libxt-dev libncurses5-dev python3-dev libgtk-3-dev libatk1.0-dev libcairo2-dev libgnomeui-dev libgnome2-dev at-spi2-core
# wget -qO ~/repos/vim.zip https://github.com/vim/vim/archive/master.zip && cd ~/repos && unzip vim.zip && cd vim-master
# ./configure -q \
# --enable-python3interp=yes \
# --enable-cscope \
# --enable-multibyte \
# --enable-fontset \
# --with-features=huge \
# --with-x \
# --with-compiledby="Soner Agirbas" \
# --with-python3-config-dir=/usr/lib/python3.6/config-3.6m-x86_64-linux-gnu
# make -j4 VIMRUNTIMEDIR=/usr/local/share/vim/vim82
# sudo make install && cd || exit

# Install Vim PPA way which is updated daily.
# sudo add-apt-repository -y ppa:jonathonf/vim-daily
# This will also install some ruby stuff.
# +clientserver feature requires X11 so we use this package also in server environments.
sudo apt install -y vim-gtk3

if [[ $SERVER == 1 ]]; then
    sudo apt install -y certbot python3-certbot-nginx
fi

# sudo update-alternatives --install /usr/bin/editor editor /usr/local/bin/vim 1
# sudo update-alternatives --set editor /usr/local/bin/vim
# sudo update-alternatives --install /usr/bin/vi vi /usr/local/bin/vim 1
# sudo update-alternatives --set vi /usr/local/bin/vim
VIM=$(command -v vim)
sudo update-alternatives --install /usr/bin/editor editor $VIM 1
sudo update-alternatives --set editor $VIM
sudo update-alternatives --install /usr/bin/vi vi $VIM 1
sudo update-alternatives --set vi $VIM

# Build and install tmux
# sudo apt remove --purge tmux -y
# sudo apt install libevent-dev -y
# LATEST=$( get_latest_release "tmux/tmux" )
# cd ~/repos || exit
# wget "https://github.com/tmux/tmux/releases/download/$LATEST/tmux-$LATEST.tar.gz"
# tar zxvf "tmux-$LATEST.tar.gz" && cd "tmux-$LATEST" || exit
# ./configure
# sed -i "s/master/${LATEST}/g" Makefile
# make -j2 && sudo make uninstall && sudo make install
# rm -f "$HOME/repos/tmux-$LATEST.tar.gz"

# Or install directly
sudo apt install -y tmux

# Install cheat.sh cli client
curl https://cht.sh/:cht.sh > "$HOME/bin/cht.sh" && chmod +x "$HOME/bin/cht.sh"

# Install tldr bash client
# We are going to use tealdeer instead of tldr (see below)
# tldr: Community driven manual pages with useful examples
# wget -qO ~/bin/tldr https://4e4.win/tldr && chmod +x ~/bin/tldr

# Install tealdeer: tldr rust implementation
LATEST=$(get_latest_release "dbrgn/tealdeer")
wget -qO "$HOME/bin/tldr" "https://github.com/dbrgn/tealdeer/releases/download/$LATEST/tldr-linux-x86_64-musl" && \
    chmod +x "$HOME/bin/tldr" && tldr --update

# nettop: bandwidth usage by process
git clone "https://github.com/Emanem/nettop.git" "$HOME/repos/nettop" && \
cd "$HOME/repos/nettop" && make release && cp ./nettop "$HOME/bin" && cd

# Add php support for ctags
curl -Ss "https://raw.githubusercontent.com/vim-php/phpctags/gh-pages/install/phpctags.phar" > phpctags > "$HOME/bin/phpctags" && \
    chmod +x "$HOME/bin/phpctags"

# Install universal ctags
# This is also installable from package managers.
git clone "https://github.com/universal-ctags/ctags.git" "$HOME/repos/ctags" && \
cd "$HOME/repos/ctags" && ./autogen.sh && ./configure && make -j2 && sudo make install && cd

# PHP Documentation inside psysh using "doc array_push" for example
wget -qO "$HOME/.local/share/psysh/php_manual.sqlite" "http://psysh.org/manual/en/php_manual.sqlite"

# Install wpcli
curl -O "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar" && \
chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp

# Install composer
php -r "readfile('http://getcomposer.org/installer');" | sudo php -- --install-dir=/usr/bin/ --filename=composer

# Install psysh: PHP Repl
composer g require psy/psysh:@stable

# Setup composer global packages
# repman-io/composer-plugin will provide CDN support for php packages.
# sudo chown -R "$(whoami):$(whoami)" ~/.composer # This is not necessary.
composer config --global repo.packagist composer https://packagist.org
# composer global require hirak/prestissimo : This is no longer necessary because of composer v2.
composer global require "squizlabs/php_codesniffer=*" \
mnapoli/pretty \
seld/jsonlint \
friendsofphp/php-cs-fixer \
repman-io/composer-plugin
cd ~/bin || exit
# Note that this installs a specific version of phpunit.
# Prefer (below) installing from official repos.
# wget -O phpunit https://phar.phpunit.de/phpunit-9.phar && chmod +x phpunit
# ln -s phpunit.phar phpunit
sudo apt install -y phpunit

# Install wp cli admin command.
# This allows you to open site in your browser.
wp package install git@github.com:wp-cli/admin-command.git

# Install nodejs lts and npm (npm comes with nodejs)
# https://github.com/nodesource/distributions/blob/master/README.md#debinstall
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
# Above command updates the apt db.
sudo apt install -y nodejs

# Install yarn.
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt update -y && sudo apt install yarn -y

# degit: can install github repositories without its git history.
# also can download sub directory of a git repo.
npm install -g degit

# Install fd.
# This is for speeding up fuzzy search in ranger,
# as it is using fzf with 'find' command.
LATEST=$( get_latest_release "sharkdp/fd" )
cd ~ || exit
wget "https://github.com/sharkdp/fd/releases/download/$LATEST/fd_$( echo "$LATEST" | tr -d 'v' )_amd64.deb"
sudo dpkg -i "fd_$(echo "$LATEST" | tr -d 'v')_amd64.deb"

# Install ripgrep ( ack, ag alternative, written in Rust )
LATEST=$( get_latest_release "BurntSushi/ripgrep" )
cd ~ || exit
wget "https://github.com/BurntSushi/ripgrep/releases/download/$LATEST/ripgrep_${LATEST}_amd64.deb"
sudo dpkg -i "ripgrep_${LATEST}_amd64.deb"

# Install bandwhich - bandwidth by process
LATEST=$( get_latest_release "imsnif/bandwhich" )
cd ~ || exit
wget "https://github.com/imsnif/bandwhich/releases/download/$LATEST/bandwhich-v$( echo "$LATEST" | tr -d 'v' )-x86_64-unknown-linux-musl.tar.gz"
aunpack bandwhich* && mv bandwhich ~/bin && rm -f "bandwhich-v$( echo "$LATEST" | tr -d 'v' )-x86_64-unknown-linux-musl.tar.gz"

# Install bat (cat alternative).
LATEST=$( get_latest_release "sharkdp/bat" )
cd ~ || exit
wget "https://github.com/sharkdp/bat/releases/download/$LATEST/bat_$( echo "$LATEST" | tr -d 'v' )_amd64.deb"
sudo dpkg -i "bat_$(echo "$LATEST" | tr -d 'v')_amd64.deb"

# Install glow (Markdown viewer).
LATEST=$( get_latest_release "charmbracelet/glow" )
cd ~ || exit
wget "https://github.com/charmbracelet/glow/releases/download/$LATEST/glow_$( echo "$LATEST" | tr -d 'v' )_linux_amd64.deb"
sudo dpkg -i "glow_$(echo "$LATEST" | tr -d 'v')_linux_amd64.deb"

# Install piknik - clipboard over network
if [[ $SERVER == 1 ]]; then
    LATEST=$( get_latest_release "jedisct1/piknik" )
    cd ~ || exit
    wget "https://github.com/jedisct1/piknik/releases/download/$LATEST/piknik-linux_x86_64-$( echo "$LATEST" | tr -d 'v' ).tar.gz"
    aunpack piknik* && mv linux-x86_64/piknik ~/bin && rm -rf linux-x86_64
    sudo touch /etc/systemd/system/piknik.service
    sudo bash -c 'cat << EOF > /etc/systemd/system/piknik.service
    [Unit]
    Description=Piknik - clipboard over network
    After=network.target

    [Service]
    Type=simple
    User=artik
    WorkingDirectory=/home/artik/bin
    ExecStart=/home/artik/bin/piknik -server
    Restart=on-abort

    [Install]
    WantedBy=multi-user.target
    EOF'

# TODO: Before running piknik you need to generate ~/.piknik.toml files using
# piknik -genkey -password
# sudo service piknik start
# sudo systemctl enable piknik.service
fi

# Install vim-node-rpc
yarn global add vim-node-rpc

# Setup .gitconfig.
git config --global user.name "$GITUSERNAME"
git config --global user.email "$GITEMAIL"
git config --global core.editor vim
git config --global core.excludesfile ~/.gitignore_global

# Don't require password for these executables.
echo "$(whoami) ALL=NOPASSWD: /usr/sbin/iftop, /usr/bin/dnstop, /usr/sbin/iotop, /home/$(whoami)/repos/nettop/nettop" | sudo EDITOR='tee -a' visudo

# Install dotfiles (the old way using stow)
# cd ~ || exit
# git clone "https://$GITUSERNAME:$GITPASSWORD@gitlab.com/tricarte/dotfiles.git"
# cd ~/dotfiles || exit
# rm -f ~/.bashrc ~/.profile
# stow ag bash fonts npmrc ranger sqliterc tmux vim wpcli && stow --adopt bin
# source ~/.bashrc
# tmux new-session -d -s test && mkdir ~/.tmux/resurrect && cp ~/dotfiles/resurrect_last ~/.tmux/resurrect/last
# sed -i -e "s:change_me:$(whoami):g" ~/.tmux/resurrect/last
# sed -i -e "s:change_iface:$GWIFACE:g" ~/.tmux/resurrect/last
# tmux kill-session -t test

# Install dotfiles_ng
# git clone --separate-git-dir="$HOME/.dotfiles" "https://$GITUSERNAME:$GITPASSWORD@gitlab.com/tricarte/dotfiles_ng.git" tmpdotfiles
git clone --separate-git-dir="$HOME/.dotfiles" "git@gitlab.com:tricarte/dotfiles_ng.git" tmpdotfiles
rsync --recursive --verbose --exclude '.git' tmpdotfiles/ "$HOME/"
rm -r tmpdotfiles

# shellcheck source=/dev/null
source "$HOME/.bashrc"

tmux new-session -d -s test && mkdir "$HOME/.tmux/resurrect" && cp "$HOME/resurrect_last" "$HOME/.tmux/resurrect/last"
sed -i -e "s:change_me:$(whoami):g" "$HOME/.tmux/resurrect/last"
sed -i -e "s:change_iface:$GWIFACE:g" "$HOME/.tmux/resurrect/last"
sed -i -e "s:change_ip:$IPADDR:g" "$HOME/.tmux/resurrect/last"
tmux kill-session -t test

# Do not list untracked files and directories while "dotfiles status" in $HOME
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" config --local status.showUntrackedFiles no
# Switch from http to ssh for gitlab authentication.
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" remote set-url origin git@gitlab.com:tricarte/dotfiles_ng.git
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" config core.sshCommand "ssh -o IdentitiesOnly=yes -i ~/.ssh/github-id_rsa -F /dev/null"

# Install Mariadb
sudo apt install mariadb-server -y
# 'sudo mysql' drops you into sql shell by default.
# But you can't do anything admin related.

# It is recommended that you would better not touch the root authentication method
# which is based on unix_socket. Creating another admin user is a better idea.
# TODO: Script below...
# sudo mariadb
# GRANT ALL ON *.* TO 'admin'@'localhost' IDENTIFIED BY 'password' WITH GRANT OPTION;
# FLUSH PRIVILEGES;

# Check current authentication plugin:
# Try logging in using `sudo mysql` if unix_socket plugin is active.
# And then issue below SQL command.
# SELECT user,authentication_string,plugin,host FROM mysql.user;

# In 20.04 default password is blank for root.
# mysql.user 'plugin' column is by default set to unix_socket for root user.
# Meaning: mysql client process uid must match the mysql root user name which is root.
# Use: sudo mysql -u root -p
# At this point enter your user's password with root privileges and then hit enter
# for the blank password.
# After that:
# GRANT ALL PRIVILEGES on *.* to 'root'@'localhost' IDENTIFIED BY '<password>';
# FLUSH PRIVILEGES;
# After these, 'plugin' column becomes empty.
# Other authentication methods are explained here
# https://linuxize.com/post/how-to-install-mariadb-on-ubuntu-20-04/

# Above instructions are for Mariadb.
# Below can be used for MYSQL.
# ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'Password123#@!';
# For some clients caching_sha2_password plugin can be troublesome. Use
# mysql_native_password instead.

# TODO: Now do the mysql_secure_installation thing.

# /etc/mysql/mariadb.conf.d/50-server.cnf is the default config file.

# Create a custom mariadb config file
sudo touch /etc/mysql/mariadb.conf.d/60-server.cnf
echo "
[server]
slow-query-log=1
slow_query_log_file = /var/lib/mysql/mysql-slow.log
log_slow_verbosity     = query_plan,explain
long_query_time = 1
# Below will pollute the mysql-slow.log file as it will log nearly every query.
# log_queries_not_using_indexes=ON
skip-name-resolve

# This size should contain most of the active data set of your server so that
# SQL request can work directly with information in the buffer pool cache.
# Default is 128MB in bytes.
# innodb_buffer_pool_size=134217728

# Default is 151
# max_connections

# Default is the number of cores you have.
# thread_pool_size

# MariaDB uses temp tables for sorting. If you have a big sort (ORDER BY, GROUP BY etc.)
# that exceeds the limit set for temp tables, then MariaDB may have to page to
# disk, which is much slower.

# Default is 16MB in bytes.
# max_heap_table_size

# Used for sorting large tables.
# Default is 16MB in bytes.
# tmp_table_size

# Use below status variables to find out how much swapping has occured
# for tmp tables in memory.
# show status like 'Created_tmp_disk_tables' 
# show status like 'Created_tmp_disk'

# Enable query cache
query_cache_type=1
" | sudo tee -a /etc/mysql/mariadb.conf.d/60-server.cnf

# Install tokudb engine for mariadb
sudo apt install -y mariadb-plugin-tokudb

# TODO
# cat /sys/kernel/mm/transparent_hugepage/enabled
# Output must be never. To disable transparent_hugepage:
# vim /etc/default/grub
# GRUB_CMDLINE_LINUX_DEFAULT="transparent_hugepage=never"
# sudo update-grub2

# TODO
# Enable Tokudb using
# vim /etc/mysql/conf.d/tokudb.cnf
# plugin-load = ha_tokudb

# TODO
# SERVER
# Schedule auto renew Lets Encrypt certificates
# sudo crontab -e
# Every day at 03:15 AM.
# Every day at 03:15 AM.
# 15 3 * * * /usr/bin/certbot renew >/dev/null 2>&1

# Install bashtop
# sudo add-apt-repository -y ppa:bashtop-monitor/bashtop
sudo apt install -y bashtop

# needrestart is inspired by checkrestart which is in debian-goodies package.
sudo apt install -y needrestart
# Don't forget to set it to auto in /etc/needrestart/needrestart.conf

# Set total max journal log size to 100M
sudo sed -i -e 's/#SystemMaxUse=/SystemMaxUse=100M/g' /etc/systemd/journald.conf

# Install all desktop applications
if [[ $SERVER == 0 ]]; then
    # TODO: After installation notes:
    # Add below repo URL to Discover after installing plasma-discover-flatpak-backend.
    # https://flathub.org/repo/flathub.flatpakrepo

# ppa:graphics-drivers/ppa : Latest NVIDIA drivers
# ppa:kisak/kisak-mesa: Latest stable Mesa drivers
    PPAS=(
        "ppa:maarten-baert/simplescreenrecorder"
        "ppa:kisak/kisak-mesa"
        "ppa:mkusb/ppa"
        "ppa:ubuntuhandbook1/gimp"
        "ppa:kdenlive/kdenlive-stable"
        "ppa:slgobinath/safeeyes"
        "ppa:jonmagon/kdiskmark"
        "ppa:graphics-drivers/ppa"
    )

    for ppa in "${PPAS[@]}"
    do
        sudo add-apt-repository -y "$ppa" -n
    done

    sudo apt update -y && sudo apt upgrade -y

    # ubuntu-restricted-addons: For Intel Quick Sync accelerated video encoding in Kdenlive
    # feh: Fast image file viewer
    # dnsmasq: For valet-linux
    # barrier: Synergy alternative
    # appmenu-gtk2-module appmenu-gtk3-module: Global menu in KDE.
    sudo apt install -y \
        adb fastboot \
        appmenu-gtk2-module appmenu-gtk3-module \
        barrier \
        dnsmasq \
        feh \
        gimp gimp-gap gimp-gmic gimp-lensfun gimp-texturize \
        glmark2 \
        kdenlive \
        mkusb mkusb-nox usb-pack-efi \
        plasma-discover-flatpak-backend \
        safeeyes \
        simplescreenrecorder \
        sqlitebrowser \
        ubuntu-restricted-addons \
        filelight

        composer global require cpriego/valet-linux
        valet install

        cat <<EOT >> /etc/php/7.4/fpm/pool.d/valet.conf
php_value[max_execution_time] = 3600
php_value[max_input_time] = 300
php_value[memory_limit] = 1024M
php_value[error_reporting] = E_ALL
php_value[display_erros] = On
php_value[display_startup_errors] = On
php_value[error_log] = syslog
php_value[post_max_size] = 1000M
php_value[upload_max_filesize] = 1000M
php_value[date.timezone] = Europe/Istanbul
EOT

        # I have to use sudo because sed -i creates temp files in sites-available
        # so I need root privileges.
        sudo sed -i -e "/charset.*/a client_max_body_size 1500M;" /etc/nginx/sites-available/valet.conf

        # Create valet config from template
        mv "$HOME/.valet/config.json" "$HOME/.valet/config.json.orj"
        cp "$HOME/dotfiles-templates/valet/config.json" "$HOME/.valet/config.json"
        sed -i -e "s:change_me:$(whoami):g" "$HOME/.valet/config.json"

        # Download adminer to ~/valet-park/adminer
        [ -d "$HOME/valet-park/adminer" ] || mkdir -p "$HOME/valet-park/adminer"
        cd "$HOME/valet-park/adminer" || exit
        wget -qO index.php "https://www.adminer.org/latest-en.php"
        wget "https://raw.githubusercontent.com/Niyko/Hydra-Dark-Theme-for-Adminer/master/adminer.css"

        # Install wpsite
        git clone "https://github.com/tricarte/wpsite" "$HOME/repos/wpsite"
        git clone "https://github.com/tricarte/wpready3" "$HOME/repos/wpready3"
        chmod +x "$HOME/repos/wpsite/wpsite"
        ln -s "$HOME/repos/wpsite/wpsite" "$HOME/bin/wpsite"
        ln -s "$HOME/bin/wpsite" "$HOME/bin/wps"
        ln -s "$HOME/repos/wpsite/.wpsite-completion.bash" "$HOME/.wpsite-completion.bash"

fi # End of installation of desktop applications

# Not that important: A top like tool for Intel GPUs.
# It can give hints about 3D/Video GPU Utilization, gpu clock speed.
# sudo apt install -y intel-gpu-tools
# sudo intel_gpu_top

# Install Rust Lang
# Select default options. It will modify PATH with ~/.cargo/bin.
# So expect changes in .profile and .bashrc
# Download size is nearly 100M for version 1.53.
# https://rustup.rs/
