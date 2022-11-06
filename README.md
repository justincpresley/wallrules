# wallrules: Clean, Secure, Custom Rules for iptables

**iptables** is the #1 utility tool that allows system administrators to configure the IP packet filter rules of the Linux kernel firewall. There are many tools that are built on-top of iptables such as ufw that attempt to make it easier to configure a host-based firewall. However, hiding the complexity also limits configurability and secureness.

***wallrules*** attempts to make it easy to get started with iptables by providing scripts to develop a clean, secure, and custom configuration for iptables.

## Usage

In order to ease into security, I have provided two scripts: `fencerules.sh` and `wallrules.sh`.
The former being less secure but easier to use, and the latter being more secure but more specific and detailed.
Unlike `fencerules.sh`, You must modify `wallrules.sh` and include your services as it will block them.

To use these scripts, simply copy one of them to a directory of choice and run it. I prefer the directory `/root/bin` due to it being root's home. Please note, `iptables` is NOT persistence. Therefore, your rules will disappear upon reboot. Please read on for more details.

You can also ensure that you have the rules installed if the command `iptables -L` fills your console.

## Ensuring Persistence After Reboot

There are two provided ways to ensure persistence of your rules after reboot: `crontab` and `systemd`. I prefer `systemd`.

### Crontab

Some Linux OS's will allow you to create a cron job that will specifically run at reboot.
```
$ sudo crontab -e
```

Choose your favorite editor (if you haven't already) and put the following at the end where SCRIPT is the absolute path of your script e.g. "/root/bin/wallrules.sh".
```
@reboot root sh SCRIPT
```

### Systemd

To create a service that systemd will recongize and will start, you need to have a service script. Forunately for you, I have provided both wallrules and fencerules service scripts. Simply, put the ".service" script inside "/etc/systemd/system" and give it execute permissions.

After that, you must enable the service with the following where SERVICE is the description found in the service script.
```
$ sudo systemctl enable SERVICE
```

## Protecting Your Rules

We can apply some hardening techniques to make our script secure from local users.
1. Permissions: `chmod 100 SCRIPT`
2. Immuntable: `chattr +i SCRIPT`
3. Access: Disabling root (`vim /etc/passwd` and orange text on the first line (end of the line) `/sbin/nologin`.

## HELP! I Can't use Apt Install!

Yes. Yes, then the firewall is doing it's job. Goodluck!

Alright, alright. You have two options here with the second being preferred.
1. You can permanently open the necessary ports for apt (http(80), https(443), ftp(21)).
2. You can flush your rules with `iptables -F`, apply updates and do what you need to do, and then reboot/rerun the script.
