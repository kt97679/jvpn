#!/usr/bin/env ruby
require 'highline/import'
require 'mechanize'
require 'socket'

VPN_LOG_MAXSIZE = 1000000
VPN_DIR = ENV["HOME"] + "/.juniper_networks/network_connect"
VPN_BINARY = VPN_DIR + "/ncsvc"
VPN_LOG = VPN_BINARY + ".log"
VPN_MAX_FAILURES = 5  # how many times we would retry in a row before giving up
VPN_RETRY_TIMEOUT = 5 # timeout between reconnects

=begin
This wrapper script would allow you to connect to Juniper VPN without using browser and java.

There is well known issue with Juniper client software that it works correctly on 32 bit linux platforms
but fails on 64 bit platforms due to inability of 64 bit java to load 32 bit jni library. Here is
workaround if you want to use java and browser: http://ubuntuforums.org/showthread.php?p=11189826#post11189826%22

A lot of efforts were invested in resolution of this issue. The most importnat information can be found using links below:
http://makefile.com/.plan/2009/10/juniper-vpn-64-bit-linux-an-unsolved-mystery/
https://github.com/samm-git/jvpn

This script was created because perl jvpn script was not working for me (in order to get necessary cookies one more link
should be clicked). Solution with compiling of ncui worked, but it has security issue since everybody on your host can
see DSID you are using for connection.

This script emulates click on additional link and doesn't expose any sensitive information via environment variables or
command line options. Unfortunately you need to run it with root priveleges since vpn binary for some reason doesn't
restore /etc/resolv.conf and /etc/hosts after terminating vpn session.

Verified on Ubuntu 12.04 x64. In order to run this script you need to do following:

sudo apt-get install ruby1.9.3 libxml2-dev libxslt1-dev g++
sudo gem install mechanize
sudo gem install highline

Enjoy :)!
Kirill Timofeev <kt97679@gmail.com>
=end

def copy_configs(from, to)
    %w{resolv.conf hosts}.each do |file|
        FileUtils.cp("#{from}/#{file}", to)
    end
end

def save_configs
    copy_configs("/etc", VPN_DIR)
end

def restore_configs
    copy_configs(VPN_DIR, "/etc")
end

def rotate_logs
    if File.exist?(VPN_LOG) && File.stat(VPN_LOG).size > VPN_LOG_MAXSIZE
        FileUtils.mv(VPN_LOG, VPN_LOG + ".old")
    end
end

def vpn_start
    # we ask for vpn password, that is reused in case of disconnects
    password = ask('Vpn password: ') {|q| q.echo = '*'}
    if ! File.directory?(VPN_DIR)
        FileUtils.mkdir_p(VPN_DIR)
    end
    save_configs
    pid = fork
    if pid != nil
        exit # parent process exits here, forked child continues in background
    end
    md5hash = <<`    SHELL`.sub(/^.*=/, '').gsub(/:/, '').downcase.chomp
    echo | openssl s_client -connect #{VPN_HOST}:443 2>/dev/null| \
    openssl x509 -md5 -noout -fingerprint
    SHELL
    reconnect = true
    Signal.trap("TERM") do # in order to stop reconnecting this script should recieve SIGTERM
        reconnect = false
    end
    failures = 0 # number of failures in a row while communicating with vpn web frontend
    while reconnect
        begin
            cookies = vpn_emulate_browser(password)
            failures = 0
        rescue
            failures += 1                  # failures can happen, for example, while restoring vpn connection after resuming computer from sleep
            if failures > VPN_MAX_FAILURES # if there were more than 5 failures
                reconnect = false          # something is wrong, cancelling reconnect attempts
            else
                sleep VPN_RETRY_TIMEOUT    # let's pause between reconnect attempts
            end
            next
        end
        vpn_connect(md5hash, cookies)
    end
    restore_configs
    rotate_logs
end

def vpn_stop
    # let's send SIGTERM signal to ruby wrapper to stop reconnect attempts
    # after that let's stop vpn binary
    system("pkill -f \"#{$0} *start\" && #{VPN_BINARY} -K")
end

def vpn_connected?
    # if vpn connection is up we should have tunX network device
    system("ifconfig -s|grep -q ^tun")
end

def vpn_status
    if vpn_connected?
        puts "vpn connected"
    else
        puts "vpn disconnected"
    end
end

def vpn_connect(md5hash, cookies)
    pid = spawn("#{VPN_BINARY} >/dev/null 2>&1")
    sleep 3
    s = TCPSocket.open('127.0.0.1', 4242)
    # binary data below was obtained by author of jvpn.pl using tcpdump
    # protocol is mostly unknown especially vpn executable responses
    data = "\0\0\0\0\0\0\0\x64\x01\0\0\0\0\0\0\0\0\0\0\0"
    s.send(data, 0)
    s.recv(2048)
    data = "\0\0\0\0\0\0\0\x7c\x01\0\0\0\x01\0\0\0\0\0\0\x10\0\0\0\0\0\x0a\0\0\0\0\0\x04\0\0\0\0"
    s.send(data, 0)
    s.recv(2048)
    data = "\0\x01\0\0\0" +
        (VPN_HOST.size + 1).chr + VPN_HOST +
        "\0\0\x02\0\0\0" +
        (cookies.size + 1).chr + cookies +
        "\0\0\x0a\0\0\0" +
        (md5hash.size + 1).chr + md5hash +
        "\0"
    len1 = [data.size + 6].pack("I")
    len2 = [data.size].pack("I")
    data = "\0\0\0\0\0\0\0\x66\x01\0\0\0\x01\0\0\0\0\0" + len1[1] + len1[0] + "\0\xcb\0\0" + len2[1] + len2[0] + data
    s.send(data, 0)
    s.recv(2048)
    Process.wait(pid)
    s.close
end

def vpn_emulate_browser(password)
    a = Mechanize.new
    login_form = a.get("https://" + VPN_HOST).form_with :name => 'frmLogin'
    login_form.field_with(:name => 'username').value = VPN_USER
    login_form.field_with(:name => 'password').value = password
    login_form.field_with(:name => 'realm').value = VPN_REALM
    a.submit(login_form).link_with(:text => 'Office_Users').click
    if !File.exist? VPN_BINARY
        Dir.chdir(VPN_DIR)
        a.get("https://#{VPN_HOST}/dana-cached/nc/ncLinuxApp.jar").save
        system("unzip ncLinuxApp.jar ncsvc >/dev/null 2>&1")
        File.unlink("ncLinuxApp.jar")
        FileUtils.chmod(0755, VPN_BINARY)
    end
    # original implementation feeds all cookies to vpn binary
    # but it looks like we actually need only DSID
    a.cookies.select {|x| x.name == 'DSID' }[0].to_s
end

def check_uid
    if Process.euid != 0
        puts "In order to use this option please run this script as root"
        exit
    end
end

def get_value(error_message, default = nil)
    value = ARGV.shift || default
    if value == nil || value.size == 0
        puts error_message
        exit
    end
    value
end

def check_running
    if `pgrep -cf "ruby *#{$0} *start"`.to_i != 1
        puts "#{$0} already running"
        exit
    end
end

case ARGV.shift
    when "start"
        check_running
        VPN_HOST = get_value("Vpn host not specified, can't continue")
        VPN_REALM = get_value("Vpn realm not specified, can't continue")
        VPN_USER = get_value("Vpn user not specified, can't continue", ENV["USER"])
        check_uid
        vpn_start
    when "stop"
        check_uid
        vpn_stop
    when "status"
        vpn_status
    else
        puts "Usage: #{$0} start <vpn_host> <vpn_realm> [vpn_user]\n" +
             "       #{$0} stop\n" +
             "       #{$0} status\n\n" +
             "start and stop options require superuser priveleges\n" +
             "vpn_user parameter can be omitted, USER env variable would be used in this case"
end


