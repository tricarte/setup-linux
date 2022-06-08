#!/usr/bin/env bash
#-----------------------------------------------------------------------------------
# After server creation, from your local client issue the following command:
# ssh-copy-id -i identity-file -f root@remote-ip-addr; ssh root@remote-ipaddr; 
#
# After remote login succeeds;
# First run new_user.sh script. Log off, re-login using ssh new-user@remote-ip-addr.
#
# You have to copy your public key to the new user again,
# using ssh-copy-id like below:
# ssh-copy-id -i identity-file -f new-user@remote-ip-addr
#
# Then run this run.sh script. It will generate ssh keys if there isn't any,
# and will then exit. You have to copy the generated public key to your
# gitlab/github account. Re-run run.sh script to finish installation. After the
# installation, log off and connect using your preferred ssh host config
# or:
# ssh new-user@remote-ip-addr -Pnew_port -i ~/.ssh/identity-file
#-----------------------------------------------------------------------------------

if [ "$(id -u)" == "0" ]; then
   echo "This script must not be run as root." 1>&2
   exit 1
fi

GWIFACE=$(ip route | grep default | cut -d" " -f5)
IPADDR=$(hostname -I)

if [[ ! $GWIFACE =~ ^[we] ]]; then
    echo "You are not connected to the internet through wireless or ethernet card..."
    echo ""
    exit 1
fi

# Installing prerequisites
echo "Installing git..."
echo ""
sudo apt install git software-properties-common rsync -y
git config --global core.sshCommand "ssh -o IdentitiesOnly=yes -i ~/.ssh/github-id_rsa -F /dev/null"

# Credentials are for gitlab. And they are only used when
# cloning private dotfiles_ng repository.
while : ; do
    read -rp "Enter your github/gitlab username: " GITUSERNAME
    # Not using password any more because of ssh keys.
    # read -rsp "Enter your github/gitlab password: " GITPASSWORD
    read -rp "Enter your email address: " GITEMAIL
    echo ""
    echo "Gitlab/Github username: $GITUSERNAME"
    echo "Email: $GITEMAIL"

    echo ""
    read -p "Are these values correct?  (y/n): " -r
    echo ""
    [[ ! $REPLY =~ ^[Yy]$ ]] || break
done

if [[ ! -f ~/.ssh/github-id_rsa ]]; then
    echo "Generating key pair for use with github/gitlab..."
    ssh-keygen -t rsa -f ~/.ssh/github-id_rsa -b 4096 -C "$GITEMAIL" -q -P ""
    echo "Key pair created. Script will now exit."
    echo "Add the created public key to your gitlab/github account."
    echo "Then re-run the script again."
    exit
fi

echo "Checking Gitlab credentials..."
echo ""
git ls-remote "git@gitlab.com:tricarte/dotfiles_ng.git" > /dev/null 2>&1 \
    || ( echo "Gitlab credentials are not working. Exiting..."; exit 1; )
echo "Gitlab credentials are working!"
echo ""

read -rp "Enter your github access token: " GHTOKEN

if curl -H "Authorization: token ${GHTOKEN}" --silent "https://api.github.com" | grep -q "Bad credentials"; then
    echo "Your github access token is not valid!"
    exit 1
fi
    
echo "Is this a server or desktop?"
select machine_type in Server Desktop
do
    case $machine_type in
        Server)
        MACHINE="server"
        break
        ;;
        Desktop)
        MACHINE="desktop"
        break
        ;; *)
        echo "Select either 1 or 2."
        ;;
esac
done

read -p \
    "This machine is a $MACHINE. Proceed installation?  (y/n) (Default n): "  \
    -r -n1
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Installation aborted."
    exit 1
fi

start=$SECONDS

if [[ $MACHINE == "server" ]]; then
    echo ""
    read -rp "What port would you like to use for the ssh server?: " SSHPORT

    while [[ "$SSHPORT" -lt 1024 ||  "$SSHPORT" -gt 65535 ]]; do
        read -p "Enter a port number between 1024 and 65535: " -er SSHPORT
    done

    while : ; do
        echo ""
        echo "Specify MariaDB 'admin' user password: "
        read -rs DBPASSWORD

        echo "Reenter MariaDB 'admin' user password: "
        read -rs DBPASSWORDCHK

        if [[ $DBPASSWORD == "$DBPASSWORDCHK" ]]; then
            break
        else
            echo ""
            echo "Passwords do not match."
        fi
    done
fi

# https://gist.github.com/lukechilds/a83e1d7127b78fef38c2914c4ececc3c
# Get the latest release version number of a github project.
get_latest_release() {
    curl -H "Authorization: token ${GHTOKEN}" --silent \
        "https://api.github.com/repos/$1/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'                        
    }

##################
#  List of PPAs  #
##################

# Ubuntu 22.04 comes with PHP 8.1
PPAS=(
    "ppa:ondrej/php"
    "ppa:ondrej/nginx"
    "ppa:jonathonf/vim-daily"
)

echo "Adding necessary PPAs..."
echo ""
for ppa in "${PPAS[@]}"
do
    sudo add-apt-repository -y "$ppa" -n
done

sudo apt update -y && sudo apt upgrade -y

echo "Configuring timezone..."
echo ""
if [[ $MACHINE == "server" ]]; then
    # This may only be necessary in cloud servers.
    echo "Europe/Istanbul" | sudo tee /etc/timezone
    # Below command didn't reconfigure tzdata but the other one worked:
    # sudo dpkg-reconfigure tzdata
    sudo dpkg-reconfigure --frontend noninteractive tzdata
fi

# sysctl.conf settings
if [[ $MACHINE == "server" ]]; then
    echo "Applying sysctl.conf settings..."
    echo ""
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
# dmesg | grep --color '[NX|DX]*protection' if you see \"active\", then
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

if [[ $MACHINE == "server" ]]; then
    echo "Applying ssh server settings..."
    echo ""
    if [[ -f /etc/ssh/sshd_config ]]; then
        sudo sed -i -e "s/#Port 22/Port ${SSHPORT}/g" \
            -e "s/#AddressFamily any/AddressFamily inet/g" \
            -e "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" \
            -e "s/#PasswordAuthentication yes/PasswordAuthentication no/g" \
            -e "s/PermitRootLogin yes/PermitRootLogin no/g" \
            -e "s/#UseDNS no/UseDNS no/g" \
            /etc/ssh/sshd_config

        sudo systemctl restart ssh
    fi
fi

mkdir "$HOME/dotfiles-original"
cp .bashrc .profile "$HOME/dotfiles-original"

if [[ $MACHINE == "server" ]]; then
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

echo "Creating necessary HOME directories..."
echo ""
mkdir -p "$HOME/bin" \
    "$HOME/.local/share/psysh" \
    "$HOME/repos" \
    "$HOME/.npm-global" \
    "$HOME/.vim-git-backups" \
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
sudo apt install -y \
    python3-pip xsel mtr-tiny pydf \
    build-essential libssl-dev cmake pkg-config \
    zip unzip autojump highlight par xclip \
    ncdu htop vnstat iftop mosh ranger httpie \
    lnav atool silversearcher-ag lynx multitail \
    shellcheck sqlite3 dnstop libpcap-dev libncurses5-dev \
    libsqlite3-dev autoconf secure-delete \
    curl stow dnsutils gawk mediainfo rlwrap ppa-purge \
    apache2-utils ntpdate watchman incron hey \
    renameutils libncurses5 gdebi-core mailutils postfix- \
    iotop lshw hwinfo pv libnss3-tools jq chkservice \
    optipng pngquant jpegoptim imagemagick bat ripgrep

pip install --user tmuxp

if [[ $MACHINE == "server" ]]; then
    echo "Configuring ntpdate..."
    echo ""
    sudo chmod u+s /usr/sbin/ntpdate
    ntpdate -u ntp.ubuntu.com
fi

# Install nginx and PHP from ondrej PPA
echo "Installing Nginx with PHP support..."
echo ""
sudo apt install -y \
    nginx libnginx-mod-http-cache-purge php-fpm php-cli \
    php-pgsql php-sqlite3 php-gd php-curl php-memcached \
    php-mysql php-mbstring php-tidy php-xml php-bcmath php-soap \
    php-intl php-readline php-imagick php-msgpack php-igbinary \
    php-dev php-zip php-imap php-gmp php-redis php-apcu

# PHP 7.4 packages
# sudo apt install \
#     php7.4-{fpm,cli,pgsql,sqlite3,gd,curl,memcached,mysql,mbstring,tidy,\
# xml,bcmath,soap,intl,readline,imagick,msgpack,igbinary,dev,zip,imap,\
# gmp,redis,apcu}

# If you first install valet with a recent version of PHP
# Then switching back to an older PHP version breaks valet.
# valet use 7.4
# value use 8.1
# valet use default

phpfpmversion=$(
    php -r "printf('%d.%d', PHP_MAJOR_VERSION, PHP_MINOR_VERSION);"
)

# https://www.nginx.com/resources/wiki/start/topics/recipes/wordpress/
if [[ -f "/etc/php/${phpfpmversion}/fpm/php.ini" ]]; then
    sudo sed -i -e 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' \
        "/etc/php/${phpfpmversion}/fpm/php.ini"
fi

if [[ $MACHINE == "server" ]]; then
    # php.ini production settings
    if [[ -f "/etc/php/${phpfpmversion}/fpm/php.ini" ]]; then
        sudo sed -i -e 's/;realpath_cache_ttl = 120/realpath_cache_ttl = 300/g' \
            -e 's/upload_max_filesize = 2M/upload_max_filesize = 50M/g' \
            -e 's/post_max_size = 8M/post_max_size = 55M/g' \
            -e 's/;error_log = syslog/error_log = \/tmp\/php_error.log/g' \
            -e 's/;date.timezone =/date.timezone = Europe\/Istanbul/g' \
            "/etc/php/${phpfpmversion}/fpm/php.ini"
    fi

    if [[ ! -f "/etc/php/${phpfpmversion}/fpm/conf.d/10-opcache.ini" ]]; then
        sudo phpenmod -v "$phpfpmversion" -s fpm opcache
    fi

    if [[ -f "/etc/php/${phpfpmversion}/fpm/conf.d/10-opcache.ini" ]]; then
        echo "Applying PHP Opcache settings."
        echo "

opcache.memory_consumption=128

; Same string in one file can be used for other files to improve memory
; in MB
opcache.interned_strings_buffer=32

; Max cached files
opcache.max_accelerated_files=10000

; You have to manually invalidate cached files if this is 0
opcache.validate_timestamps=1

; If validate_timestamps is enabled
opcache.revalidate_freq=60
opcache.revalidate_path=0

opcache.fast_shutdown=1
opcache.enable_cli=1
opcache.enable_file_override=1
opcache.save_comments=1

; https://tideways.io/profiler/blog/fine-tune-your-opcache-configuration-to-avoid-caching-suprises
opcache.max_wasted_percentage=10
" | sudo tee -a "/etc/php/${phpfpmversion}/fpm/conf.d/10-opcache.ini"
    fi
fi

# Create separate user with non login shell to be the owner of /var/www
if [[ $MACHINE == "server" ]]; then
    sudo adduser webu --shell=/bin/false --disabled-login \
        --disabled-password --gecos ""

    if [[ -d /var/www ]]; then
        sudo chown webu:webu /var/www
    fi

    sudo -u webu git config --global user.name "$GITUSERNAME"
    sudo -u webu git config --global user.email "$GITEMAIL"
    sudo -u webu git config --global core.editor vim
fi

# Install Vim PPA way which is updated daily.
# sudo add-apt-repository -y ppa:jonathonf/vim-daily
# This will also install some ruby stuff.
# +clientserver feature requires X11
# so we use this package also in server environments.
echo "Installing VIM..."
echo ""
sudo apt install -y vim-gtk3

VIM=$(command -v vim)
sudo update-alternatives --install /usr/bin/editor editor "$VIM" 1
sudo update-alternatives --set editor "$VIM"
sudo update-alternatives --install /usr/bin/vi vi "$VIM" 1
sudo update-alternatives --set vi "$VIM"

if [[ $MACHINE == "server" ]]; then
    echo "Installing certbot..."
    echo ""
    sudo apt install -y certbot python3-certbot-nginx
fi

# Or install directly
echo "Installing tmux..."
echo ""
sudo apt install -y tmux

# Install cheat.sh cli client
curl https://cht.sh/:cht.sh > "$HOME/bin/cht.sh" && chmod +x "$HOME/bin/cht.sh"

# Install tealdeer: tldr rust implementation
LATEST=$(get_latest_release "dbrgn/tealdeer")
wget -qO "$HOME/bin/tldr" \
    "https://github.com/dbrgn/tealdeer/releases/download/$LATEST/tealdeer-linux-x86_64-musl" && \
    chmod +x "$HOME/bin/tldr"

# nettop: bandwidth usage by process
git clone "https://github.com/Emanem/nettop.git" "$HOME/repos/nettop" && \
cd "$HOME/repos/nettop" && make release && cp ./nettop "$HOME/bin" && cd

# Add php support for ctags
wget -qO "$HOME/bin/phpctags" \
    "https://raw.githubusercontent.com/vim-php/phpctags/gh-pages/install/phpctags.phar" \
    && chmod +x "$HOME/bin/phpctags"

# Install universal ctags
# This is also installable from package managers.
git clone "https://github.com/universal-ctags/ctags.git" "$HOME/repos/ctags" && \
    cd "$HOME/repos/ctags" && ./autogen.sh && ./configure && make -j2 && \
    sudo make install && cd

# PHP Documentation inside psysh using "doc array_push" for example
wget -qO "$HOME/.local/share/psysh/php_manual.sqlite" \
    "http://psysh.org/manual/en/php_manual.sqlite"

# Install wpcli (PHAR Way)
curl -O \
    "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar" && \
    chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp

# Install composer
php -r "readfile('http://getcomposer.org/installer');" \
    | sudo php -- --install-dir=/usr/bin/ --filename=composer

composer config --global github-oauth.github.com "$GHTOKEN"
composer config --global repo.packagist composer https://packagist.org
composer config --global allow-plugins.repman-io/composer-plugin true -n

# Install psysh: PHP Repl
composer g require psy/psysh:@stable

# Setup composer global packages
# repman-io/composer-plugin will provide CDN support for php packages.
# gordalina/cachetool opcache reset tool
composer global require "squizlabs/php_codesniffer=*" \
mnapoli/pretty \
seld/jsonlint \
friendsofphp/php-cs-fixer \
gordalina/cachetool \
repman-io/composer-plugin

echo "Installing phpunit..."
echo ""
sudo apt install -y phpunit

# Install wp cli admin command.
# This allows you to open site in your browser.
wp package install git@github.com:wp-cli/admin-command.git

# Install wp cli secure command.
wp package install git@github.com:igorhrcek/wp-cli-secure-command.git

# Install nodejs lts and npm (npm comes with nodejs)
# https://github.com/nodesource/distributions/blob/master/README.md#debinstall
echo "Installing NodeJS and yarn..."
echo ""
curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg \
    | gpg --dearmor | sudo tee /usr/share/keyrings/yarnkey.gpg >/dev/null
echo \
    "deb [signed-by=/usr/share/keyrings/yarnkey.gpg] https://dl.yarnpkg.com/debian stable main" \
    | sudo tee /etc/apt/sources.list.d/yarn.list
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
# Above command updates the apt db.
sudo apt install -y nodejs yarn

# degit: can install github repositories without its git history.
# also can download sub directory of a git repo.
echo "Installing degit..."
echo ""
npm install -g degit

# Install fd.
# This is for speeding up fuzzy search in ranger,
# as it is using fzf with 'find' command.
LATEST=$( get_latest_release "sharkdp/fd" )
cd ~ || exit
wget \
    "https://github.com/sharkdp/fd/releases/download/$LATEST/fd_$( echo "$LATEST" | tr -d'v' )_amd64.deb"
sudo dpkg -i "fd_$(echo "$LATEST" | tr -d'v')_amd64.deb"

# Install ripgrep ( ack, ag alternative, written in Rust )
# LATEST=$( get_latest_release "BurntSushi/ripgrep" )
# cd ~ || exit
# wget \
#     "https://github.com/BurntSushi/ripgrep/releases/download/$LATEST/ripgrep_${LATEST}_amd64.deb"
# sudo dpkg -i "ripgrep_${LATEST}_amd64.deb"

# Install bandwhich - bandwidth by process
LATEST=$( get_latest_release "imsnif/bandwhich" )
cd ~ || exit
wget \
    "https://github.com/imsnif/bandwhich/releases/download/$LATEST/bandwhich-v$( echo "$LATEST" | tr -d'v' )-x86_64-unknown-linux-musl.tar.gz"
aunpack bandwhich* && mv bandwhich ~/bin \
    && rm -f "bandwhich-v$( echo "$LATEST" | tr -d'v' )-x86_64-unknown-linux-musl.tar.gz"

# Install glow (Markdown viewer).
LATEST=$( get_latest_release "charmbracelet/glow" )
cd ~ || exit
wget \
    "https://github.com/charmbracelet/glow/releases/download/$LATEST/glow_$( echo "$LATEST" | tr -d'v' )_linux_amd64.deb"
sudo dpkg -i "glow_$(echo "$LATEST" | tr -d'v')_linux_amd64.deb"

# Install piknik - clipboard over network
if [[ $MACHINE == "server" ]]; then
    LATEST=$( get_latest_release "jedisct1/piknik" )
    cd ~ || exit
    wget \
        "https://github.com/jedisct1/piknik/releases/download/$LATEST/piknik-linux_x86_64-$( echo "$LATEST" | tr -d'v' ).tar.gz"
    aunpack piknik* && mv linux-x86_64/piknik ~/bin && rm -rf linux-x86_64
    echo "\
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
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/piknik.service

    # TODO: Before running piknik you need to generate ~/.piknik.toml files using
    # piknik -genkey -password
    # sudo service piknik start
    # sudo systemctl enable piknik.service
fi

# Install vim-node-rpc
yarn global add vim-node-rpc

# Setup .gitconfig.
echo "Configuring git..."
echo ""
git config --global user.name "$GITUSERNAME"
git config --global user.email "$GITEMAIL"
git config --global core.editor vim
git config --global core.excludesfile ~/.gitignore_global

# Don't require password for these executables.
echo \
    "$(whoami) ALL=NOPASSWD: /usr/sbin/iftop, /usr/bin/dnstop, /usr/sbin/iotop, /home/$(whoami)/repos/nettop/nettop" \
    | sudo EDITOR='tee -a' visudo
echo "Defaults:$(whoami) timestamp_timeout=30" | sudo EDITOR='tee -a' visudo

# Install dotfiles_ng
echo "Setting up dotfiles..."
echo ""
git clone --separate-git-dir="$HOME/.dotfiles" \
    "git@gitlab.com:tricarte/dotfiles_ng.git" tmpdotfiles
rsync --recursive --verbose --exclude '.git' tmpdotfiles/ "$HOME/"
rm -r tmpdotfiles

# shellcheck source=/dev/null
source "$HOME/.bashrc"

# Copy tmuxp config from dotfiles-templates to ~/.tmuxp/
if [[ ! -d "$HOME/.tmuxp" ]]; then
    mkdir "$HOME/.tmuxp"
fi

cp "$HOME/dotfiles-templates/tmuxp/mytmux.yaml" "$HOME/.tmuxp"
sed -i -e "s:change_iface:$GWIFACE:g" "$HOME/.tmuxp/mytmux.yaml"
sed -i -e "s:change_ip:$IPADDR:g" "$HOME/.tmuxp/mytmux.yaml"
# Now we can create a new tmux session based on mytmux.yaml file
# using: tmuxp load mytmux

# Create ranger bookmarks
cp "$HOME/dotfiles-templates/ranger/bookmarks" "$HOME/.local/share/ranger/bookmarks"
sed -i -e "s:change_me:$(whoami):g" "$HOME/.local/share/ranger/bookmarks"

# Do not list untracked files and directories while "dotfiles status" in $HOME
echo "Configuring git for dotfiles..."
echo ""
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" config \
    --local status.showUntrackedFiles no
# Switch from http to ssh for gitlab authentication.
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" remote \
    set-url origin git@gitlab.com:tricarte/dotfiles_ng.git
git --git-dir="$HOME/.dotfiles/" --work-tree="$HOME" config \
    core.sshCommand "ssh -o IdentitiesOnly=yes -i ~/.ssh/github-id_rsa -F /dev/null"

# Install Mariadb
echo "Installing MariaDB..."
echo ""
sudo apt purge mysql* mariadb* -y
sudo apt install mariadb-server mariadb-client -y
# 'sudo mysql' drops you into sql shell by default.
# But you can't do anything admin related.

# It is recommended that you would better not touch the root authentication method
# which is based on unix_socket. Creating another admin user is a better idea.
# sudo mariadb
# GRANT ALL ON *.* TO 'admin'@'localhost' IDENTIFIED BY 'password' WITH GRANT OPTION;
# FLUSH PRIVILEGES;
if [[ $MACHINE == "server" ]]; then
    sudo mariadb -e"GRANT ALL ON *.* TO 'admin'@'localhost' \
        IDENTIFIED BY '${DBPASSWORD}' WITH GRANT OPTION; FLUSH PRIVILEGES;"
else
    sudo mariadb -e"GRANT ALL ON *.* TO 'admin'@'localhost' \
        IDENTIFIED BY 'password' WITH GRANT OPTION; FLUSH PRIVILEGES;"
fi

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
# https://mariadb.com/kb/en/configuring-mariadb-with-option-files/#server-option-groups
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

# needrestart is inspired by checkrestart which is in debian-goodies package.
echo "Installing bashtop and needrestart..."
echo ""
sudo apt install -y bashtop needrestart

echo "Setting up max journal size..."
echo ""
sudo sed -i -e 's/#SystemMaxUse=/SystemMaxUse=100M/g' /etc/systemd/journald.conf

# Install all desktop applications
if [[ $MACHINE == "desktop" ]]; then
    # TODO: After installation notes:
    # Add below repo URL to Discover after installing plasma-discover-backend-flatpak.
    # https://flathub.org/repo/flathub.flatpakrepo

# ppa:graphics-drivers/ppa : Latest NVIDIA drivers
# ppa:maarten-baert/simplescreenrecorder" # This PPA does not exist for 2204
# ppa:kisak/kisak-mesa: Latest stable Mesa drivers
    PPAS=(
        "ppa:kisak/kisak-mesa"
        "ppa:mkusb/ppa"
        "ppa:savoury1/gimp"
        "ppa:kdenlive/kdenlive-stable"
        "ppa:slgobinath/safeeyes"
        "ppa:jonmagon/kdiskmark"
        "ppa:graphics-drivers/ppa"
        "ppa:libreoffice/ppa"
    )

    echo "Adding necessary PPAs for the desktop..."
    echo ""
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
    echo "Installing desktop related apps..."
    echo ""
    sudo apt install -y \
        adb fastboot \
        appmenu-gtk2-module appmenu-gtk3-module \
        barrier dnsmasq feh plasma-discover-backend-flatpak \
        gimp gimp-gap gimp-gmic gimp-lensfun gimp-texturize \
        glmark2 kdenlive mkusb mkusb-nox usb-pack-efi \
        safeeyes simplescreenrecorder sqlitebrowser \
        ubuntu-restricted-addons filelight libnotify-bin

        # Install MailHog
        # Run it as: ~/go/bin/MailHog
        # the HTTP server starts on port 8025
        # go get github.com/mailhog/MailHog
        LATEST=$(get_latest_release "mailhog/MailHog")
        wget -qO "$HOME/bin/MailHog" \
            "https://github.com/mailhog/MailHog/releases/download/${LATEST}/MailHog_linux_amd64" \
            && chmod +x "$HOME/bin/MailHog" && sudo mv "$HOME/bin/MailHog" /usr/local/bin/MailHog

        sudo tee /etc/systemd/system/mailhog.service <<EOL
[Unit]
Description=MailHog Service
After=network.service
[Service]
Type=simple
ExecStart=/usr/bin/env /usr/local/bin/MailHog > /dev/null 2>&1 &
[Install]
WantedBy=multi-user.target
EOL

fi # End of installation of desktop applications

# Install wpsite
echo "Installing wpsite..."
echo ""
git clone "https://github.com/tricarte/wpsite" "$HOME/repos/wpsite"
git clone "https://github.com/tricarte/wpready3" "$HOME/repos/wpready3"

# Add post-commit hook to run 'composer wpstarter'
echo "#!/usr/bin/env bash
export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\"
composer wpstarter" > "$HOME/repos/wpready3/.git/hooks/post-commit"
chmod +x "$HOME/repos/wpready3/.git/hooks/post-commit"

chmod +x "$HOME/repos/wpsite/wpsite"
# ln -s "$HOME/repos/wpsite/wpsite" "$HOME/bin/wpsite"
sudo ln -s "$HOME/repos/wpsite/wpsite" "/usr/local/bin/wpsite"
sudo ln -s "$HOME/repos/wpsite/wpsite" "/usr/local/bin/wps"
ln -s "$HOME/repos/wpsite/.wpsite-completion.bash" "$HOME/.wpsite-completion.bash"

# Lock root user
if [[ $MACHINE == "server" ]]; then
    if [[ 'root' != $(whoami) ]]; then
        sudo passwd --lock root
    fi
fi

# Add current user to www-data group
# This will be useful when using cli applications
# such as composer, wpcli with www-data owned files and directories.
if [[ $MACHINE == "server" ]]; then
    if [[ 'root' != $(whoami) ]]; then
        # Check www-data group exists
        getent group www-data > /dev/null 2>&1 
        if [[ ! $? ]]; then
            sudo usermod -aG www-data "$(whoami)"
        fi

        # Also be a member of "webu" group.
        # This is the group name of the owner of /var/www directory.
        getent group webu > /dev/null 2>&1 
        if [[ ! $? ]]; then
            sudo usermod -aG webu "$(whoami)"
        fi

        # Apply group membership changes
        su - "$USER"
    fi
fi

# Install Config Server Firewall - CSF
# By default it is not activated.
if [[ $MACHINE == "server" ]]; then
    echo "Installing Config Server Fireall - CSF"
    sudo apt install libwww-perl liblwp-protocol-https-perl libgd-graph-perl -y
    cd "$HOME/repos" || exit
    wget -q https://download.configserver.com/csf.tgz
    tar -xvzf csf.tgz
    cd csf || exit
    sudo bash install.sh
    cd "$HOME" || exit
fi

# Not that important: A top like tool for Intel GPUs.
# It can give hints about 3D/Video GPU Utilization, gpu clock speed.
# sudo apt install -y intel-gpu-tools
# sudo intel_gpu_top

# Install Rust Lang
# Select default options. It will modify PATH with ~/.cargo/bin.
# So expect changes in .profile and .bashrc
# Download size is nearly 100M for version 1.53.
# https://rustup.rs/

# Install valet-linux
if [[ $MACHINE == "desktop" ]]; then

    # valet-linux installation may break name resolution
    # So we first install adminer from internet.
    echo "Downloading adminer..."
    echo ""
    [ -d "$HOME/valet-park/adminer" ] || mkdir -p "$HOME/valet-park/adminer"
    cd "$HOME/valet-park/adminer" || exit
    wget -qO index.php "https://www.adminer.org/latest-en.php"
    wget \
        "https://raw.githubusercontent.com/Niyko/Hydra-Dark-Theme-for-Adminer/master/adminer.css"
    cd ~ || exit

    composer global require cpriego/valet-linux
    "$HOME/.composer/vendor/bin/valet" install

    cat <<EOT >> "/etc/php/${phpfpmversion}/fpm/pool.d/valet.conf"
; Memory limit 1G
php_value[memory_limit] =1073741824
php_value[post_max_size] =100M
php_value[upload_max_filesize] =50M

; Error Reporting Level
; E_ERROR | E_WARNING | E_PARSE | E_NOTICE
php_value[error_reporting] = 15

; Remove annoying error messages
; E_ALL & ~E_WARNING & ~E_NOTICE & ~E_DEPRECATED & ~E_USER_DEPRECATED
; php_value[error_reporting] = 8181

; E_ALL
; php_value[error_reporting] = 32767

; E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED
; php_value[error_reporting] = 8191

; E_ALL & ~E_WARNING & ~E_DEPRECATED & ~E_USER_DEPRECATED
; php_value[error_reporting] = 8189

; E_ERROR | E_WARNING | E_CORE_ERROR | E_CORE_WARNING | E_COMPILE_ERROR | E_COMPILE_WARNING | E_RECOVERABLE_ERROR
; php_value[error_reporting] = 4339

php_value[display_errors] = On
php_value[display_startup_errors] = On
php_value[ignore_repeated_errors] = On
php_value[ignore_repeated_source] = Off
php_value[log_errors_max_len] = 1024
php_value[log_errors] = On
php_value[html_errors] = On
php_value[error_log] = /tmp/php_error.log
php_value[date.timezone] = Europe/Istanbul

env[ADMINER_SERVER] = localhost
env[ADMINER_USERNAME] = admin
env[ADMINER_PASSWORD] = password

EOT

    if [[ -f /etc/nginx/sites-available/valet.conf ]]; then
        if ! grep -q client_max_body_size /etc/nginx/sites-available/valet.conf; then
            sudo sed -i -e "/charset.*/a client_max_body_size 1500M;" \
                /etc/nginx/sites-available/valet.conf
            sudo sed -i -e "/default_server;$/c\    localhost 80 default_server;" \
                /etc/nginx/sites-available/valet.conf
        fi
    fi

    if [[ -f /etc/dnsmasq.d/valet ]]; then
        echo "address=/.test/127.0.0.1" | sudo tee /etc/dnsmasq.d/valet
    fi

    echo "server=9.9.9.9" | sudo tee /etc/dnsmasq.d/server

    sudo systemctl restart dnsmasq.service

    # Create valet config from template
    mv "$HOME/.valet/config.json" "$HOME/.valet/config.json.orj"
    cp "$HOME/dotfiles-templates/valet/config.json" "$HOME/.valet/config.json"
    sed -i -e "s:change_me:$(whoami):g" "$HOME/.valet/config.json"

    if ! ping -c1 google.com > /dev/null 2>&1; then
        echo "Name resolution is broken."
        echo "Installation of valet-linux may have broken name resolution."
    fi
fi

end=$SECONDS
echo "Installation took $((end-start)) seconds to finish."

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
# Because these smtp clients create symlinks to sendmail which is used by PHP by default.

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
# TODO: Is nginx installed disabled?
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

