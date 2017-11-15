#!/bin/bash

#   __      __        _       _     _      
#   \ \    / /       (_)     | |   | |     
#    \ \  / /_ _ _ __ _  __ _| |__ | | ___ 
#     \ \/ / _` | '__| |/ _` | '_ \| |/ _ \
#      \  / (_| | |  | | (_| | |_) | |  __/
#       \/ \__,_|_|  |_|\__,_|_.__/|_|\___|
#                                          
#     


#System
declare -r app_version='BETA 3.1'


#Auto Update Script
set -o errexit
UPDATE_BASE=https://raw.githubusercontent.com/exrienz/s1mpl3/master/s1mpl3.sh
SELF=$(basename $0)

reldir=`dirname $0`
cd $reldir
default_directory=`pwd`

#Current LAN IP
declare -r ip_local=$(ip -4 route get 8.8.8.8 | awk {'print $7'} | tr -d '\n')


#COLOR CODE
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'


#SYSTEM SETTING
declare -r application_path='Application/'
declare -r report_path='Report/'
declare -r port_analysis_path='Port_Analysis/'
declare -r bin_path='/usr/local/bin'

#URL VARIABLE
declare -r pa_whois_url="http://whois.domaintools.com/"
declare -r pa_nmap_url="https://suip.biz/?act=nmap"
declare -r pa_hosmap_url="https://suip.biz/?act=hostmap"
declare -r pa_nikto_url="https://suip.biz/?act=nikto"
declare -r pa_whatsweb_url="https://suip.biz/?act=whatweb"
declare -r pa_wpscan_url="https://suip.biz/?act=wpscan"
declare -r pa_droopescan_url="https://suip.biz/?act=droopescan"
declare -r pa_sqlmap_url="https://suip.biz/?act=sqlmap"
declare -r pa_aio_url="http://pentest-tools.security-audit.com/test/index.php"
declare -r pa_dnsdumpster_url="https://dnsdumpster.com/"
declare -r pa_aio_view_dns_url_i="http://viewdns.info/"
declare -r pa_aio_view_dns_url_ii="http://www.gwebtools.com.br/"


#APPLICATION SETTING

declare -r theHarvester_git='https://github.com/laramies/theHarvester.git'
declare -r theHarvester_folder='theHarvester'

#AUTOINSTALL APPLICATION
declare -a required_apps=("nmap" 
						"nikto" 
						"sniper" 
						"./$application_path$wig_folder/wig.py"
						"./$application_path$arachni_folder/arachni_web"
						"/etc/init.d/nessusd"
						"./$application_path$joomlavs_folder/joomlavs.rb"
						"./$application_path$liferayscan_folder/LiferayScan"
						"./$application_path$droopescan_folder/droopescan"
						"./$application_path$theHarvester_folder/theHarvester.py"
						)						

#WORDLIST CONFIGURATION
declare -a wordlist_path=("/usr/share/wordlists/wfuzz/general/common.txt"
						"/usr/share/wordlists/wfuzz/general/medium.txt"
						"/usr/share/wordlists/wfuzz/general/big.txt"
						"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
						"/usr/share/wordlists/fasttrack.txt")


########################################################################################################################################################
#    _    _ _   _ _     
#   | |  | | | (_) |    
#   | |  | | |_ _| |___ 
#   | |  | | __| | / __|
#   | |__| | |_| | \__ \
#    \____/ \__|_|_|___/
#                       
#                       


function apps_exist {
	type "$1" &> /dev/null ;
	}


function install_git {
	xterm -e "git clone $1 $application_path$2" &
	wait
	}

	
function install_message {
	#Download and install nmap
	echo -e "$OKGREEN	[-]::[Installing]: Downloading $1..Please Wait.... $RESET"
	}

	
function create_dir (){
	mkdir -p $report_path$1
	}


function wordlist (){
	echo
	echo -e "$OKORANGE	Common Wordlist Path: $RESET"
	echo "	"
	for i in "${wordlist_path[@]}"
		do
			echo -e "$OKORANGE	$i $RESET"
		done
	echo
	}

	
#Convert NMAP XML to HTML
function xml2html () {
	xsltproc $report_path$1/$2.xml -o $report_path$1/$2.html 2> /dev/null
	rm $report_path$1/$2.xml 2> /dev/null
	x-www-browser $report_path$1/$2.html 2> /dev/null &
	}

	
#Install missing application
function install_apps {
	case "$1" in
	"sniper")
		#Download and install sn1per
		install_message $1
		install_git $sniper_git $sniper_folder
		chmod 777 $application_path$sniper_folder/install.sh &> /dev/null
		chmod 777 $application_path$sniper_folder/sniper &> /dev/null
		gnome-terminal -x "./$application_path$sniper_folder/install.sh" &
		wait
		rm -r $application_path$sniper_folder
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"		
		;;
	"./$application_path$theHarvester_folder/theHarvester.py")
		#Download and install theHarvester
		install_message theHarvester
		install_git $theHarvester_git $theHarvester_folder
		#Install apps
		chmod +x $application_path$theHarvester_folder/theHarvester.py &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: theHarvester $RESET"
		;;
	"./$application_path$arachni_folder/arachni_web")
		#Download and install arachni
		install_message arachni
		#Remove incase download error
		rm -f $application_path/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz 
		rm -f -r $application_path/arachni
		xterm -e "wget $arachni_git -P $application_path" &
		wait
		xterm -e "tar -xvzf $application_path/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -C $application_path" &
		wait
		mv $application_path/arachni-1.5.1-0.5.12 $application_path/arachni
		rm $application_path/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"/etc/init.d/nessusd")
		#Remove corrupted downloaded file
		rm -f $application_path/Nessus-6.10.5-debian6_amd64.deb
		#Download and install Nessus
		install_message Nessus &> /dev/null
		xterm -e "wget $nessus_git -P $application_path && dpkg -i $application_path/Nessus-6.10.5-debian6_amd64.deb" &
		wait
		rm $application_path/Nessus-6.10.5-debian6_amd64.deb
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"./$application_path$joomlavs_folder/joomlavs.rb")
		#Installing Joomlavs
		install_message Joomlavs &> /dev/null
		#Remove Corrupted Joomlavs
		rm -f -r $application_path$joomlavs_folder
		install_git $joomlavs_git $joomlavs_folder
		# CD to apps dir
		xterm -e "cd $application_path$joomlavs_folder; gem install bundler; bundle install; chmod +x joomlavs.rb;cd $default_directory" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"./$application_path$liferayscan_folder/LiferayScan")
		#Installing LiferayScan
		install_message LiferayScan &> /dev/null
		#Remove Corrupted Files
		rm -f -r $application_path$liferayscan_folder 
		install_git $liferayscan_git $liferayscan_folder_main 
		xterm -e "cd $application_path$liferayscan_folder_main; bundle install; gem build LiferayScan.gemspec; gem install --local LiferayScan-0.0.1.gem; cd $default_directory" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"./$application_path$droopescan_folder/droopescan")
		#Installing Droopescan
		install_message Droopescan &> /dev/null
		#Remove Corrupted Files
		rm -f -r $application_path$droopescan_folder
		install_git $droopescan_git $droopescan_folder 
		xterm -e "cd $application_path$droopescan_folder; pip install -r requirements.txt; cd $default_directory" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
		*)
			va_scanning
			;;
		esac
		;;
	*)
		echo ""
		echo -e "$OKGREEN Enjoy! $RESET"
		echo ""
		;;
	esac	
	}
	
	
runSelfUpdate() {
	echo "Performing self-update..."

	# Download new version
	echo -n "Downloading latest version..."
	if ! wget --quiet --output-document="$0.tmp" $UPDATE_BASE > $SELF ; then
		echo "Failed: Error while trying to wget new version!"
		echo "File requested: $UPDATE_BASE/$SELF"
		exit 1
	fi
	echo "Done"
  
	echo "Update Success! Restarting Script..."
	sleep 5

	# Copy over modes from old version
	OCTAL_MODE=$(stat -c '%a' $SELF)
	if ! chmod $OCTAL_MODE "$0.tmp" ; then
		echo "Failed: Error while trying to set mode on $0.tmp."
		exit 1
	fi

	# Spawn update script
	cat > updateScript.sh << EOF
#!/bin/bash
# Overwrite old file with new
if mv "$0.tmp" "$0"; then
  echo "Done. Update complete."
  rm \$0
  ./$SELF
else
  echo "Failed!"
fi
EOF
	echo -n "Inserting update process..."
	chmod +x updateScript.sh
	exec /bin/bash updateScript.sh
	}








########################################################################################################################################################
#             _____   ______                _   _             
#       /\   / ____| |  ____|              | | (_)            
#      /  \ | |      | |__ _   _ _ __   ___| |_ _  ___  _ __  
#     / /\ \| |      |  __| | | | '_ \ / __| __| |/ _ \| '_ \ 
#    / ____ \ |____  | |  | |_| | | | | (__| |_| | (_) | | | |
#   /_/    \_\_____| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|
#                                                             
#                                                             

function nmap_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Intense_Scan_Report"
	nmap -T4 -A -v --script=whois-ip,banner,iscsi-brute,isns-info,ntp-info,fingerprint-strings,HTTPAuth,HTTPtrace $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}

function nmap_stealth_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Stealth_Scan_Report"
	nmap --mtu 24 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}	
	
function nmap_udp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_UDP_Scan_Report"
	nmap -sU $hosts --script=banner -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}

	
function nmap_aio_enum_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your http port? \c"
	read portz
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Http_Enum_Scan_Report"
	#nmap -p $portz -sV -sC --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-enum,http-headers,http-server-header,http-php-version,http-iis-webdav-vuln,http-vuln-*,http-phpmyadmin-dir-traversal--script=http-title,http-method-tamper,http-traceroute,http-waf-detect,http-waf-fingerprint,http-internal-ip-disclosure,http-server-header,whois-ip,http-exif-spider,http-headers,http-referer-checker,http-enum,http-open-redirect,http-phpself-xss,http-xssed,http-userdir-enum,http-sitemap-generator,http-svn-info,http-unsafe-output-escaping,http-default-accounts,http-aspnet-debug,http-php-version,http-cross-domain-policy,http-comments-displayer,http-backup-finder,http-auth-finder,http-apache-server-status,http-ls,http-mcmp,http-mobileversion-checker,http-robtex-shared-ns,http-rfi-spider,http-vhosts,firewalk --traceroute $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	nmap -p $portz -sV -sC --script=http-iis-webdav-vuln,http-vuln-*,http-phpmyadmin-dir-traversal,http-title,http-method-tamper,http-traceroute,http-waf-detect,http-waf-fingerprint,http-internal-ip-disclosure,http-server-header,whois-ip,http-exif-spider,http-headers,http-referer-checker,http-enum,http-open-redirect,http-phpself-xss,http-xssed,http-userdir-enum,http-sitemap-generator,http-svn-info,http-unsafe-output-escaping,http-default-accounts,http-aspnet-debug,http-php-version,http-cross-domain-policy,http-comments-displayer,http-backup-finder,http-auth-finder,http-apache-server-status,http-ls,http-mcmp,http-mobileversion-checker,http-robtex-shared-ns,http-rfi-spider,http-vhosts,firewalk --traceroute  $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}
	
	

function nmap_aio_cve_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Common_Http_CVE_Scan_Report"
	nmap --script=http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-5638 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}

	
function nmap_aio_ssl_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your ssl port? \c"
	read port
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Http_SSL_Scan_Report"
	nmap -sV -sC --version-light -p $port --script=ssl-cert-intaddr,ssl-ccs-injection,ssl-dh-params,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2-drown $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}
	
function nmap_email_enumerator_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your web port? (e.g. 80) \c"
	read port
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_email_enumerator_Report"
	nmap -p $port $hosts --script http-grep --script-args='match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",breakonmatch' -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}


function common_port_ftp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your FTP port (Default : 21)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="FTP_analysis_Report"
	nmap -sV -sC --script firewall-bypass,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p $port --script-args firewall-bypass.helper="ftp"  $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}

function common_port_imap_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your IMAP port (Default : 143)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="IMAP_analysis_Report"
	nmap --script imap-ntlm-info -p $port $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}	

function common_port_mssql_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your MSSQL port (Default : 1433)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="MSSQL_analysis_Report"
	nmap -p $port --script ms-sql-info,broadcast-ms-sql-discover,ms-sql-ntlm-info,ms-sql-xp-cmdshell,ms-sql-dump-hashes,ms-sql-empty-password --script-args mssql.instance-all $hosts -oX $new_path$output.xml 2> /dev/null 
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}	

function common_port_mysql_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your MYSQL port (Default : 3306)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="MYSQL_analysis_Report"
	nmap -sV -sC  -p $port --script=mysql-enum,mysql-brute,mysql-empty-password,mysql-users,mysql-databases,mysql-vuln-cve2012-2122 $hosts -oX $new_path$output.xml 2> /dev/null 
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}	


function common_port_netbios_module {
	echo -e "What is your internal ip? e.g. 192.168.0.1  \c"
	read hosts
	echo -e "What is prefix? e.g. /24  \c"
	read prefix
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="Netbios_analysis_Report"
	nbtscan $hosts$prefix |& tee -a $new_path$output.txt
	xterm -e "cat $new_path$output.txt" &
	active_recon_common_port_interface
	}	

function common_port_pop3_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your POP3 port (Default : 110)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="POP3_analysis_Report"
	nmap -sV -sC --script pop3-ntlm-info -p $port $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}
	
function common_port_smb_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your SMB port (Default : 445)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="SMB_analysis_Report"
	nmap -A -sV -Pn -T4 -p $port --script=smb-os-discovery,smb-server-stats,smb-ls,smb-enum-domains,smbv2-enabled,smb-psexec,smb-enum-groups,smb-enum-processes,smb-brute,smb-print-text,smb-security-mode,smb-enum-sessions,smb-mbenum,smb-enum-users,smb-enum-shares,smb-system-info,smb-vuln-ms10-054,smb-vuln-ms10-061 $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}
	
