#!/bin/bash

##################################
### CREATED 25 JANUARY 2019
##	AUTHOR: ISAAC CHRISTENSEN
##	OS: FEDORA 29
##	PURPOSE: STIGGING -- BASED OFF OF RHEL7 STIGS - DATED 27 JULY 2018
##################################



###########
# GNOME GUI RELATED
#	VULN ID's
#	V-71859
#	V-71861
#	V-71891
#	V-71893
#	V-71899
#	V-71901
#	V-71953
#	V-71955
#	V-71993

###########
# Preset Configurations (Already Configured, no need to change, just verify)
#	VULN ID's
#	V-71919
#	V-71921
#	V-71923
#	V-71927
#	V-71931
#	V-71933
#	V-71963
# 	V-71985 -- autofs is not installed in fedora by default
#	V-71997
#	V-72003
#	V-72005
#	V-72007 #	V-72009 #	V-72011 #	V-72015
#	V-72017 #	V-72019 #	V-72021 #	V-72023
#	V-72025 #	V-72027 #	V-72029 #	V-72031
#	V-72033 #	V-72035 #	V-72037 #	V-72039
#	V-72041 #	V-72043 #	V-72045 #	V-72047
#	V-72049 #	V-72051 #	V-72053 #	V-72057
#	V-72059 #	V-72075	#	V-72211 #	V-72211
#	V-72295



############
# Policy Configurations
# VULN ID's
#	V-71999 -- Required to apply patch updates within 30 days of release --> CRONJOB?


###########
## BIOS ONLY VULNs
#	V-71961 (grep -i ^password_pbkdf2 /boot/grub2/grub.cfg)


########################################
# CONFIGURATIONS IF USING AD/LDAP
#
#	V-72227
# grep -i "start_tls" /etc/sssd/sssd.conf
# if ldap_id_use_start_tls is not true, this is a finding
#
#
##	V-72229
# grep -i tls_reqcert /etc/sssd/sssd.conf
# if ldap_tls_reqcert is not set to demand or hard, this is a finding
#
#
##	V-72231
# grep -i tls_cacert /etc/sssd/sssd.conf
# if ldap_tls_cacert does not point to a valid CA cert, this is a finding
##
#
#
##	V-72231
# grep -i tls_cacert /etc/sssd/sssd.conf
# if ldap_tls_cacert does not point to a valid CA cert, this is a finding
#
#
#########################################


Validate_Packages() {
local total_num_packages=0
local failed_packages=0

# Checks Proper Permissions
# VUL ID:
#	V-71849
# for package in `rpm -qa --qf "%{NAME}\n"`;
# do 
# ((total_num_packages++))
# # rpm --setperms $package || ((failed_packages++))
# # rpm --setugids $package || ((failed_packages++))
# done

# echo "Total Packages:          $total_num_packages"
# echo "Failed Packages:         $failed_packages"


# Checks Proper Cryptographic Hash
# VUL ID:
#	V-71855
local crypto=`rpm -Va | grep '^..5'`
if ((`$crypt | wc -l` > 0))
then
local crypto_files_to_fix=$crypto

# Let's just reinstall everything, then make sure all packages have the proper permissions
#dnf reinstall \* -y

#for package in `rpm -qa --qf "%{NAME}\n"`
#do 
#	rpm --setperms $package
#	rpm --setugids $package
#done

fi
}


# Checks Proper Cryptographic Hash
# VUL ID:
#	V-71863
#	V-72225
Login_Banner() {
rm /etc/issue
if ! grep -q "U.S. Government" /etc/issue; then cat << EOF >> /etc/issue 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

\U
\t
\o


EOF
fi

sed -i 's/.*Banner.*/Banner \/etc\/issue/' /etc/ssh/sshd_config

}

# Checks Password Defaults and Changes if not implemented already
# VUL ID:
#	V-71903
#	V-71905
#	V-71907
#	V-71909
#	V-71911
#	V-71913
#	V-71915
#	V-71917
#	V-71919
#	V-72001
Set_Password_Defaults() {

sed -i 's/# ucredit = 0/ucredit = -1/' /etc/security/pwquality.conf #	V-71903
sed -i 's/# lcredit = 0/lcredit = -1/' /etc/security/pwquality.conf #	V-71905
sed -i 's/# dcredit = 0/dcredit = -1/' /etc/security/pwquality.conf #	V-71907
sed -i 's/# ocredit = 0/ocredit = -1/' /etc/security/pwquality.conf #	V-71909
sed -i 's/# difok = 1/difok = 8/' /etc/security/pwquality.conf #	V-71911
sed -i 's/# minclass = 0/minclass = 4/' /etc/security/pwquality.conf #	V-71913
sed -i 's/# maxclass = 0/maxclass = 3/' /etc/security/pwquality.conf #	V-71915
sed -i 's/# maxclassrepeat = 0/maxclassrepeat = 4/' /etc/security/pwquality.conf #	V-71917	
sed -i 's/# minlen = 8/minlen = 15/' /etc/security/pwquality.conf #	V-71935

# Check if necessary!!
#sed -i '20 s/^/#/' /etc/pam.d/system-auth
#sed -i '22 s/^/#/' /etc/pam.d/system-auth
#sed -i '23 s/^/#/' /etc/pam.d/system-auth
#sed -i '24 s/^/&\n/g' /etc/pam.d/system-auth
sed -i 's/PASS_MIN_DAYS.*0/PASS_MIN_DAYS   1/' /etc/login.defs #	V-71925
sed -i 's/PASS_MAX_DAYS.*99999/PASS_MAX_DAYS   60/' /etc/login.defs #	V-71929
grep -q "FAIL_DELAY" /etc/login.defs && sed -i 's/FAIL_DELAY.*/FAIL_DELAY 4/' /etc/login.defs || echo "FAIL_DELAY 4" >> /etc/login.defs  # V-71951

if ! grep -q 'pam_pwhistory.so' /etc/pam.d/system-auth; then echo "password    requisite                                    pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/system-auth;fi
if ! grep -q 'pam_pwhistory.so' /etc/pam.d/password-auth; then echo "password    requisite                                    pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/password-auth;fi

sed -i 's/nullok //' /etc/pam.d/system-auth #	V-71937
sed -i 's/nullok //' /etc/pam.d/password-auth #	V-71937

grep -q "PermitEmptyPasswords no" /etc/ssh/sshd_config && sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config  # V-71941
grep -q "PermitUserEnvironment no" /etc/ssh/sshd_config && sed -i 's/#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config  # V-71941
grep -q "HostbasedAuthentication no" /etc/ssh/sshd_config && sed -i 's/#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config  # V-71941

# V-71943
# V-71945
if ! grep -q "pam_faillock.so" /etc/pam.d/password-auth; then echo << EOF >> /etc/pam.d/password-auth 
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so 
EOF
fi

if ! grep -q "pam_faillock.so" /etc/pam.d/password-auth;then echo << EOF >> /etc/pam.d/password-auth 
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so
EOF
fi
	sed -i 's/NOPASSWD: ALL//' /etc/sudoers #	V-71947
	sed -i 's/!authenticate//' /etc/sudoers #	V-71949

	# Replace all unnecessary accounts
	sed -i 's/games.*//' /etc/passwd 
	sed -i 's/gopher.*//' /etc/passwd 
	sed -i 's/sync.*//' /etc/passwd 
}



###
# Install/Modify Grub
###
Grub() {

echo -n -e "\n\nEnter GRUB password for $HOSTNAME: "
read -s GRUB_PASSWORD

echo "$GRUB_PASSWORD"

GRUB_PBKDF_HASH=`echo -e '$GRUB_PASSWORD\n$GRUB_PASSWORD' | grub2-mkpasswd-pbkdf2 | awk '/grub.pbkdf/{print$NF}'`

rm -f /etc/grub.d/40_custom

local GRUB_SET_SUPERUSER_IF_EXIST=
local GRUB_EXPORT_SUPERUSER_IF_EXIST=
local GRUB_PBKDF_HASH_PASSWORD_IF_EXIST='password_pbkdf2 root'
local BOOT_DEVICE_UUID=$(blkid /dev/sda1 | cut -d' ' -f3 | tr -d '"')

# Check /boot/efi/EFI/fedora/grub.cfg for valid entry
# VULN ID: 
#	V-81005 (BIOS)
#	V-81007 (UEFI)

# Check if Fedora Server
if [ ! -d "/boot/efi/EFI/fedora" ]; then 
if ! grep -q $GRUB_SET_SUPERUSER_IF_EXIST /boot/efi/EFI/fedora/grub.cfg; then echo "$GRUB_SET_SUPERUSER_IF_EXIST  <=== DOES NOT EXIST, PLEASE MANUALLY ENTER IN THE /\ ### BEGIN /etc/grub.d/01_users ### /\ section" ; fi
if ! grep -q $GRUB_EXPORT_SUPERUSER_IF_EXIST /boot/efi/EFI/fedora/grub.cfg; then echo "$GRUB_EXPORT_SUPERUSER_IF_EXIST  <=== DOES NOT EXIST, PLEASE MANUALLY ENTER IN THE /\ ### BEGIN /etc/grub.d/01_users ### /\ section"; fi
fi

#Check if Redhat Server
if [ ! -d "/boot/efi/EFI/redhat" ]; then 
if ! grep -q $GRUB_SET_SUPERUSER_IF_EXIST /boot/efi/EFI/redhat/grub.cfg; then echo "$GRUB_SET_SUPERUSER_IF_EXIST  <=== DOES NOT EXIST, PLEASE MANUALLY ENTER IN THE /\ ### BEGIN /etc/grub.d/01_users ### /\ section" ; fi
if ! grep -q $GRUB_EXPORT_SUPERUSER_IF_EXIST /boot/efi/EFI/redhat/grub.cfg; then echo "$GRUB_EXPORT_SUPERUSER_IF_EXIST  <=== DOES NOT EXIST, PLEASE MANUALLY ENTER IN THE /\ ### BEGIN /etc/grub.d/01_users ### /\ section"; fi
fi

# Check /etc/grub.d/40_custom for valid entry
# VULN ID: 
#	V-71961 (BIOS)
#	V-71963 (UEFI)
if ! grep -q 'set superusers="root"' /etc/grub.d/40_custom; then echo 'set superusers="root"' >> /etc/grub.d/40_custom; fi
if ! grep -q 'export superusers' /etc/grub.d/40_custom; then echo 'export superusers' >> /etc/grub.d/40_custom; fi


# Check /etc/default/grub for valid entry
# VULN ID: 
#	V-72067 (BIOS) & (UEFI)
if ! grep -q 'fips=1' /etc/default/grub; then sed -i 's/GRUB_CMDLINE_LINUX="[^"]*/& fips=1/' /etc/default/grub; fi


##### Create new GRUB boot config

# Add boot option
# VULN ID:
#	V-
if ! grep -q $BOOT_DEVICE_UUID /etc/default/grub; then sed -i 's/GRUB_CMDLINE_LINUX="[^"]*/& '"$BOOT_DEVICE_UUID"'/' /etc/default/grub; fi

# Generate the GRUB boot file
if [ -d '/boot/efi/EFI/fedora' ]; then grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg; fi
if [ -d '/boot/efi/EFI/redhat' ]; then grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg; fi


echo -e "\e[92mFinished Configuring GRUB and generating new GRUB boot file\e[0m"
}


# Checks for installed packages
# VUL ID:
#	V-71897
#	V-71967
#	V-71969
#	V-71973
#	V-72077
#	V-72213
#	V-72213
Install_Required_Programs() {
dnf install -y screen \
			authconfig \
			openssh-server \
			dconf \
			aide  \
			dracut-fips \
			audispd-plugins \
			rsyslog \
			clamav \
			clamav-server \
			clamav-data \
			clamav-filesystem \
			clamav-lib \
			clamav-update \
			clamav-devel \
			ntp \
			esc \
			authconfig 


dnf remove -y rsh-server \
			ypserv \
			telnet-server


	systemctl enable sshd

# CronJobs -- List 
#	V-71973
#	V-71975

cat << EOF >> /etc/cron.daily/aide 
#!/bin/bash

/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@$HOSTNAME"
EOF

dnf update -y


echo -e "\e[92mFinished Installing/Applying Required Programs and their configs\e[0m"
}

# Checks Proper Cryptographic Hash
# VUL ID:
#	V-71977 #	V-71979 #	V-71983 #	V-71987
#	V-71989 #	V-71991 #	V-72057 #	V-72069
#	V-72071 #	V-72073 #	V-72085 #	V-72087
#	V-72089 #	V-72091 #	V-72093 #	V-72095
#	V-72097 #	V-72099 #	V-72101 #	V-72103
#	V-72101 #	V-72103 #	V-72105 #	V-72107
#	V-72109 #	V-72111 #	V-72113 #	V-72115
#	V-72117 #	V-72119 #	V-72121 #	V-72123
#	V-72125 #	V-72127 #	V-72129 #	V-72131
#	V-72133 #	V-72135 #	V-72137 #	V-72139
#	V-72141 #	V-72143 #	V-72145 #	V-72147
#	V-72149 #	V-72151 #	V-72153 #	V-72155
#	V-72157 #	V-72159 #	V-72161 #	V-72163
#	V-72165 #	V-72167 #	V-72171 #	V-72173
#	V-72175 #	V-72177 #	V-72179 #	V-72183
#	V-72185 #	V-72187 #	V-72189 #	V-72191
#	V-72193 #	V-72197 #	V-72199 #	V-72201
#	V-72203 #	V-72205 #	V-72207 #	V-72209
#	V-72217 #	V-72217 #	V-72219 #	V-72221
#	V-72223 #	V-72217 #	V-72219 #	V-72221


Config_Check() {
sed -i 's/.*gpgcheck=1.*/gpgcheck=1/' /etc/dnf/dnf.conf
sed -i 's/.*localpkg_gpgcheck=1.*/localpkg_gpgcheck=1/' /etc/dnf/dnf.conf
sed -i 's/.*clean_requirements_on_remove=\(1\|[Tt]rue\).*/clean_requirements_on_remove=true/' /etc/dnf/dnf.conf

if [ ! -f /etc/modprobe.d/blacklist.conf ]; then  >/etc/modprobe.d/blacklist.conf;fi
if ! grep -q "blacklist storage" /etc/modprobe.d/blacklist.conf; then echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf; fi

sed -i 's/.*SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/.*SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
sed -i 's/.*UMASK.*/UMASK	077/' /etc/login.defs
sed -i 's/.*CREATE_HOME.*/CREATE_HOME yes/' /etc/login.defs

if ! grep -q "Fedora release 29 (Twenty Nine)" /etc/redhat-release; then echo -e "\e[91mCould not find the release information. Verify the release version in /etc/redhat-release.\e[0m";fi


# Disables Core Dump -- If its necessary, comment out line #1  and uncomment line #2
systemctl stop kdump.service && systemctl disable kdump.service ##Line 1
# systemctl enable kdump.service && systemctl start kdump.service ##Line 2

if ! grep -q "ALL" /etc/aide.conf; then echo -e "All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux\n/bin All\n/sbin All" >> /etc/aide.conf; fi

systemctl enable auditd.service
systemctl start auditd.service

if ! grep -q "enable_krb5" /etc/audit/audisp-remote; then echo -e "enable_krb5 = yes" >> /etc/audit/audisp-remote.conf; fi
sed -i 's/.*disk_full_action.*/disk_full_action = single/' /etc/audit/audisp-remote.conf || echo "disk_full_action = single" >> /etc/audit/audisp-remote.conf
sed -i 's/.*space_left\s.*/space_left = 25/' /etc/audit/auditd.conf || echo "space_left = 25" >> /etc/audit/auditd.conf
sed -i 's/.*space_left_.*/space_left = email/' /etc/audit/auditd.conf || echo "space_left = 25" >> /etc/audit/auditd.conf
sed -i 's/.*action_mail_root.*/action_mail_acct = root/' /etc/audit/auditd.conf || echo "space_left = 25" >> /etc/audit/auditd.conf

# Add Rules to /etc/audit/audit.rules
cat << EOF >> /etc/audit/rules.d/audit.rules 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid 
-a always,exit -F arch=b64 -S execve -C uid!=egid -F egid=0 -k setgid 
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k acces 
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change
-w /var/run/faillock -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-w /etc/sudoers -p wa -k privileged-actions
-w /etc/sudoers.d/ -p wa -k privileged-actions
-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change
-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=4294967295 -k privileged-postfix
-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=4294967295 -k privileged-postfix
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=4294967295 -k privileged-ssh
-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=4294967295 -k privileged-cron
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=4294967295 -k privileged-pam
-a always,exit -F arch=b64 -S init_module -k module-change
-a always,exit -F arch=b64 -S delete_module -k module-change
-w /usr/bin/kmod -p x -F auid!=4294967295 -k module-change
-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S create_module -k module-change
-a always,exit -F arch=b64 -S finit_module -k module-change

EOF

echo -e -n "\n\nEnter the hostname or ip_address:port_number"
read -s SYSLOG_AGG_SITE

echo "*.* @@$SYSLOG_AGG_SITE" >> /etc/rsyslog.d/mil.conf
echo -e "*\thard\tmaxlogins\t10" >> /etc/security/limits.conf


firewall-cmd --set-default-zone=trusted
firewall-cmd --reload

firewall-cmd --zone=trusted --change-interface=ens32
#firewall-cmd --permanent --add-service=cockpit
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload

if ! grep -i timout /etc/profile.d/*; then cat << EOF >> /etc/profile.d/timeout.sh 
#!/bin/bash
TMOUT=600
readonly TMOUT
export TMOUT
EOF
fi

if ! grep -q "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" /etc/ssh/sshd_config; then echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_conf; fi
if ! grep -q "MACs hmac-sha2-256,hmac-sha2-512" /etc/ssh/sshd_config; then echo "MACs hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_conf; fi

sed -i 's/.*ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config
sed -i 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
sed -i 's/.*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/.*PrintLastLog.*/PrintLastLog yes/' /etc/ssh/sshd_config
sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/.*IgnoreUserKnownHosts.*/IgnoreUserKnownHosts yes/' /etc/ssh/sshd_config
sed -i 's/.*IgnoreUserKnownHosts.*/IgnoreUserKnownHosts yes/' /etc/ssh/sshd_config
sed -i 's/.*Protocol .*/Protocol 2/' /etc/ssh/sshd_config
sed -i 's/.*GSSAPIAuthentication .*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
sed -i 's/.*KerberosAuthentication .*/KerberosAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/.*StrictModes .*/StrictModes yes/' /etc/ssh/sshd_config
sed -i 's/.*UsePrivilegeSeparation .*/UsePrivilegeSeparation sandbox/' /etc/ssh/sshd_config
sed -i 's/.*Compression .*/Compression delayed/' /etc/ssh/sshd_config


chmod 0644 /etc/ssh/*.key.pub


if ! grep -i maxpoll /etc/ntp.conf; then echo "maxpoll 10" >> /etc/ntp.conf; fi
	systemctl enable ntpd
	systemctl start ntpd
if ! grep  'net.ipv4.tcp_invalid_ratelimit' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.tcp_invalid_ratelimit = 500" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.default.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.default.accept_source_route = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.icmp_echo_ignore_broadcasts' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.conf.default.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.conf.default.send_redirects' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.ip_forward' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf; fi
if ! grep  'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/*; then echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf; fi
if ! grep  'kernel.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/*; then echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf; fi
if ! grep  "session required pam_lastlog.so showfailed" /etc/sysctl.conf /etc/sysctl.d/*; then echo "session required pam_lastlog.so showfailed" >> /etc/sysctl.conf; fi
if ! grep  "password required pam_pwquality.so retry=3" /etc/sysctl.conf /etc/sysctl.d/*; then echo "password required pam_pwquality.so retry=3" >> /etc/sysctl.conf; fi

#echo "session required pam_lastlog.so showfailed" >> /etc/pam.d/postlogin
#echo "password required pam_pwquality.so retry=3" >> /etc/pam.d/system-auth

sed -i 's/.*network_failure_action.*/network_failure_action = syslog/' /etc/clamd.d/scan.conf

echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf && echo "blacklist dccp" >> /etc/modprobe.d/blacklist.conf 

sed -i "s/ExecStart=-*/&\/usr\/sbin\/sulogin;/" /usr/lib/systemd/system/rescue.service
sed -i 's/.*active .*/active = yes/' /etc/audit/auditd.conf
sed -i 's/.*name_format .*/name_format = hostname/' /etc/audit/auditd.conf


echo -e "\e[92mFinished applying Configuration Changes\e[0m"
}

# Configures ClamAV and enables it
# VUL ID:
#	V-72211
Configure_ClamAV() {
# Edit clamd configuration
cp /etc/clamd.d/scan.conf /etc/clamd.d/scan.conf.backup
sed -i 's/.*Example/#Example/' /etc/clamd.d/scan.conf
sed -i 's/.*LogFile \/var\/log\/clamd.scan/LogFile \/var\/log\/clamd.scan/' /etc/clamd.d/scan.conf
sed -i 's/.*LogFileUnlock yes/LogFileUnlock yes/' /etc/clamd.d/scan.conf
sed -i 's/.*LogTime yes/LogTime yes/' /etc/clamd.d/scan.conf
sed -i 's/.*LogSyslog yes/LogSyslog yes/' /etc/clamd.d/scan.conf
sed -i 's/.*LogVerbose yes/LogVerbose yes/' /etc/clamd.d/scan.conf
sed -i 's/#LogFileUnlock yes/LogFileUnlock yes/' /etc/clamd.d/scan.conf
sed -i 's/#PidFile.*/PidFile \/var\/run\/clamd.scane\/clamd.pid/' /etc/clamd.d/scan.conf
sed -i 's/.*SelfCheck.*/SelfCheck 43200/' /etc/clamd.d/scan.conf
sed -i 's/.*User clamscan/User clamscan/' /etc/clamd.d/scan.conf
sed -i 's/.*ScanArchive yes/ScanArchive yes/' /etc/clamd.d/scan.conf
sed -i 's/.*ScanArchive yes/ScanArchive yes/' /etc/clamd.d/scan.conf
sed -i 's/.*Bytecode yes/Bytecode yes/' /etc/clamd.d/scan.conf

# Edit freshclam configuration (antivirus updates)
cp /etc/freshclam.conf /etc/freshclam.conf.backup
sed -i '/^Example/d' /etc/freshclam.conf

cat << EOF >> /usr/lib/systemd/system/clam-freshclam.service 
# Run the freshclam as daemon
[Unit]
Description = freshclam scanner
After = network.target

[Service]
Type = forking
ExecStart = /usr/bin/freshclam -d -c 4
Restart = on-failure
PrivateTmp = true

[Install]
WantedBy=multi-user.target

EOF

cat << EOF >> /etc/init.d/clamd 
#!/bin/sh
case "$1" in
start)
echo -n "Starting Clam AntiVirus Daemon... "
/usr/sbin/clamd
RETVAL=$?
echo
[ $RETVAL -eq 0 ] && touch /var/lock/subsys/clamd
;;
stop)
echo -n "Stopping Clam AntiVirus Daemon... "
pkill clamd
rm -f /var/run/clamav/clamd.sock
rm -f /var/run/clamav/clamd.pid
RETVAL=$?
echo
[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/clamd
;;
esac

EOF
ln -s /etc/init.d/clamd /etc/rc.d/

systemctl enable clam-freshclam.service
systemctl start clam-freshclam.service

systemctl enable clamd@scan.service
systemctl start clamd@scan.service
}

Install_Required_Programs
Grub
Config_Check
Validate_Packages
Login_Banner
Set_Password_Defaults
#Configure_ClamAV


echo -e "\n Ensure that /var is on its on file system with the attributes of: 'ext4 noatime,nobarrier 1 2' #V-72061" #V-72061
#sed -i 's/.*\/var .*defaults.*/\/dev\/mapper\/fedora-var  \/var xfs noatime,nobarrier 0 0 /' /etc/fstab
echo -e "\n Ensure that /tmp is on its on file system with the attributes of: 'ext4 default 1 2' #V-72063"
echo -e "\n Ensure that /var/log/audit is on its on file system with the attributes of: 'ext4 default 1 2' #V-72063\n\n"
cat /etc/fstab

now=$(date+ + "%T")
version=$(cat /etc/redhat-release)

echo -e "\e[92m\nStigging of $HOSTNAME was completed at $now for $version"