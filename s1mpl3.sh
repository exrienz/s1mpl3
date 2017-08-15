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
declare -r app_version='BETA'


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
DISABLE_POSTGRESQL="true" # disabling postgresql startup, assuming it's running already

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
	"nmap")
		install_message $1
		xterm -e "apt-get install nmap && yes" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"nikto")
		#Download and install nikto	
		install_message $1
		xterm -e "apt-get install nikto && yes" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
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
	"./$application_path$wig_folder/wig.py")
		#Download and install Wig
		install_message wig
		install_git $wig_git $wig_folder
		#Install apps
		cd $application_path$wig_folder
		chmod +x setup.py wig.py &> /dev/null
		xterm -e "python $application_path$wig_folder/setup.py install"  &
		wait
		cd $default_directory
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
	"openvas-start")
		echo -e "OpenVas module is not available, install now? (It might take a looong time!) y/n \c"
		read actions
		case "$actions" in
		"y")
			#Download and install OpenVas
			install_message openvas &> /dev/null
			#xterm -e "apt-get update -y" &
			#wait
			#xterm -e "apt-get upgrade -y" &
			#wait
			gnome-terminal -x "apt-get install openvas" &
			wait
			gnome-terminal -x "openvas-setup" &
			wait
			echo -e "$OKGREEN	[✔-OK!]::[Apps]: OpenVas $RESET"
			va_scanning
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
#    _____          ______                _   _             
#   |  __ \ /\     |  ____|              | | (_)            
#   | |__) /  \    | |__ _   _ _ __   ___| |_ _  ___  _ __  
#   |  ___/ /\ \   |  __| | | | '_ \ / __| __| |/ _ \| '_ \ 
#   | |  / ____ \  | |  | |_| | | | | (__| |_| | (_) | | | |
#   |_| /_/    \_\ |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|
#                                                           
#                                                           


#Passive Enumeration Whois
function pa_whois(){
	echo -e "What is your host? e.g. example.com  \c"
	read hosts
	x-www-browser --new-tab $pa_whois_url$hosts &
	passive_recon_interface
}


#Passive Google Dorks
function pa_google_dork {
	echo -e "$OKRED"
	echo -e "This module open lots of tab. Is it ok? [y/n] \c"
	read actions
	echo -e "$RESET"
	case "$actions" in
	"y")
		
	echo -e "What is your host? e.g example.com  \c"
	read hosts

	declare -a dorks=(" -url https://www.google.com/search?q=site:$hosts+intitle:index.of"
					" -url https://www.google.com/search?q=site:$hosts+ext:xml+|+ext:conf+|+ext:cnf+|+ext:reg+|+ext:inf+|+ext:rdp+|+ext:cfg+|+ext:txt+|+ext:ora+|+ext:ini+|+ext:sql+|+ext:dbf+|+ext:mdb+|+ext:log+|+ext:bkf+|+ext:bkp+|+ext:bak+|+ext:old+|+ext:backup"
					" -url https://www.google.com/search?q=site:$hosts+inurl:login"
					" -url https://www.google.com/search?q=site:$hosts+ext:doc+|+ext:docx+|+ext:odt+|+ext:pdf+|+ext:rtf+|+ext:sxw+|+ext:psw+|+ext:ppt+|+ext:pptx+|+ext:pps+|+ext:csv"
					" -url https://www.google.com/search?q=site:$hosts+ext:action+OR+struts+OR+ext:do"
					" -url https://www.google.com/search?q=site:$hosts+inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http"
					" -url https://www.google.com/search?q=site:$hosts+inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download"
					" -url https://www.google.com/search?q=site:$hosts+inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config"
					" -url https://www.google.com/search?q=site:$hosts+inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor"
					" -url https://www.google.com/search?q=site:$hosts+username+OR+password+OR+login+OR+root+OR+admin"	
					" -url https://www.google.com/search?q=site:$hosts+ext:php+intitle:phpinfo+%22published+by+the+PHP+Group%22"
					" -url https://www.google.com/search?q=site:$hosts+intext:%22sql+syntax+near%22+|+intext:%22syntax+error+has+occurred%22+|+intext:%22incorrect+syntax+near%22+|+intext:%22unexpected+end+of+SQL+command%22+|+intext:%22Warning:+mysql_connect()%22+|+intext:%22Warning:+mysql_query()%22+|+intext:%22Warning:+pg_connect()%22"
					" -url https://www.google.com/search?q=site:pastebin.com+$hosts"
					" -url https://www.google.com/search?q=site:linkedin.com+employees+$hosts"
					" -url https://www.google.com/search?q=site:*.*.$hosts"
					" -url https://www.google.com/search?q=inurl:'/phpinfo.php'+$hosts"
					" -url https://www.google.com/search?q=inurl:'/phpinfo.php'+OR+inurl:'.htaccess'+OR+inurl:'/.git'+$hosts+-github"
					)
					
		x-www-browser --new-tab ${dorks[@]} 2> /dev/null &
		
		passive_recon_interface
		;;
	*)
		passive_recon_interface
		;;
	esac
	}

	
#Passive AIO Site Information
function pa_aio_site {
	echo -e "$OKRED"
	echo -e "This module open lots of tab. Is it ok? [y/n] \c"
	read actions
	echo -e "$RESET"
	case "$actions" in
	"y")
		
	echo -e "What is your host? e.g example.com  \c"
	read hosts

	declare -a dorks=(" -url https://www.threatcrowd.org/domain.php?domain=$hosts"
					" -url https://www.tcpiputils.com/browse/domain/$hosts"
					" -url http://toolbar.netcraft.com/site_report?url=$hosts"
					" -url https://www.shodan.io/search?query=$hosts"
					" -url https://www.censys.io/ipv4?q=$hosts"
					" -url https://www.builtwith.com/$hosts"
					" -url https://web.archive.org/web/*/$hosts"
					" -url https://securityheaders.io/?q=$hosts"
					" -url https://www.openbugbounty.org/search/?search=$hosts&type=hosts"
					" -url https://crt.sh/?q=$hosts"
					" -url https://www.ssllabs.com/ssltest/analyze.html?d=$hosts&latest")
					
		x-www-browser --new-tab ${dorks[@]} 2> /dev/null &
		
		passive_recon_interface
		;;
	*)
		passive_recon_interface
		;;
	esac
	}
	
	
#Passive Online Tools
function pa_online_tools {		
	x-www-browser --new-tab -url "$1" 2> /dev/null &
}


#Passive Online Credential Harvester
function pa_harvester {
	echo -e "What is your host? e.g. example.com  \c"
	read hosts
	output="Email_Domain_Harvest_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	xterm -e "python $application_path$theHarvester_folder/theHarvester.py -d $hosts -l 500 -b all -f $output.html; mv $output.html $report_path$hosts; rm -f $output.xml; x-www-browser --new-tab -url '$report_path$hosts/$output.html'" &
	passive_recon_interface
	}
	
	
function pa_basic {
	echo -e "What is your host? e.g. example.com  \c"
	read hosts
	output="Basic_Passive_Report"
	# site_ip=dig +short $hosts | awk '{ print ; exit }'
	mkdir -p $report_path$hosts 2> /dev/null
	#rm $report_path$hosts/$output.txt 2> /dev/null	# Remove if exist
	echo
	echo "Whois Info============================================">> $report_path$hosts/$output.txt;
	curl http://api.hackertarget.com/whois/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "Search Host============================================">> $report_path$hosts/$output.txt; 
	curl http://api.hackertarget.com/hostsearch/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "NMap Data (Default Scan)============================================">> $report_path$hosts/$output.txt;
	curl http://api.hackertarget.com/nmap/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "HTTP Header============================================">> $report_path$hosts/$output.txt; 
	curl http://api.hackertarget.com/httpheaders/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "Geolocation============================================">> $report_path$hosts/$output.txt;
	curl http://api.hackertarget.com/geoip/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "URL List============================================">> $report_path$hosts/$output.txt; 
	curl https://api.hackertarget.com/pagelinks/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "Traceroute============================================">> $report_path$hosts/$output.txt; 
	curl https://api.hackertarget.com/mtr/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "DNS Lookup============================================">> $report_path$hosts/$output.txt; 
	curl http://api.hackertarget.com/dnslookup/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	echo "Reverse DNS============================================">> $report_path$hosts/$output.txt; 
	curl https://api.hackertarget.com/reversedns/?q=$hosts >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;echo >> $report_path$hosts/$output.txt;
	# echo "Reverse IP Lookup============================================">> $report_path$hosts/$output.txt; 
	# curl http://api.hackertarget.com/reverseiplookup/?q=$hosts >> $report_path$hosts/$output.txt; 
	
	x-www-browser --new-tab -url $report_path$hosts/$output.txt &
	passive_recon_interface

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
	#nmap -T4 -A -v --script=whois-ip,banner,iscsi-brute,isns-info,ntp-info,fingerprint-strings,HTTPAuth,HTTPtrace $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	nmap -T4 -A -v --script=whois-ip,banner,iscsi-brute,isns-info,ntp-info,fingerprint-strings $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}

function nmap_stealth_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Stealth_Scan_Report"
	nmap --mtu 24 -A -v  $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
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
	nmap -p $portz -sV -sC --script=http-title,http-method-tamper,http-traceroute,http-waf-detect,http-waf-fingerprint,http-internal-ip-disclosure,http-server-header,whois-ip,http-exif-spider,http-headers,http-referer-checker,http-enum,http-open-redirect,http-phpself-xss,http-xssed,http-userdir-enum,http-sitemap-generator,http-svn-info,http-unsafe-output-escaping,http-default-accounts,http-aspnet-debug,http-php-version,http-cross-domain-policy,http-comments-displayer,http-backup-finder,http-auth-finder,http-apache-server-status,http-ls,http-mcmp,http-mobileversion-checker,http-robtex-shared-ns,http-rfi-spider,http-vhosts,firewalk --traceroute $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
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



#################################################Common Port

# 1  : FTP (Normally Port 21)
	# 2  : IMAP (Normally Port 143)
	# 3  : MSSQL (Normally Port 1433)
	# 4  : MYSQL (Normally Port 3306)
	# 5  : NetBios (Normally Port 137) (For internal pentest)
	# 6  : POP3 (Normally Port 110)
	# 7  : SMB (Normally Port 445)
	# 8  : SMTP (Normally Port 445,465,587)
	# 9  : SNMP (Normally UDP Port 161) --BETA--
	# 10 : SSH (Normally Port 22)
	# 11 : Telnet (Normally Port 23)
	# 12 : TFTP (Normally Port 69)
	# 13 : VMWARE
	# 14 : VNC (Normally Port 5900)

function common_port_ftp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your FTP port (Default : 21)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="FTP_analysis_Report"
	#nmap -sV -sC --script firewall-bypass,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p $port --script-args firewall-bypass.helper="ftp"  $hosts -oX $new_path$output.xml 2> /dev/null
	nmap -sV -sC --script firewall-bypass,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p $port --script-args firewall-bypass.helper="ftp"  $hosts -oX $new_path$output.xml 2> /dev/null
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
	#nmap -sV -sC  -p $port --script=mysql-enum,mysql-brute,mysql-empty-password,mysql-users,mysql-databases,mysql-vuln-cve2012-2122 $hosts -oX $new_path$output.xml 2> /dev/null 
	nmap -sV -sC  -p $port --script=mysql-enum,mysql-empty-password,mysql-users,mysql-databases,mysql-vuln-cve2012-2122 $hosts -oX $new_path$output.xml 2> /dev/null 
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
	nbtscan $hosts$prefix > $new_path/$output.txt
	leafpad $new_path/$output.txt &
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

	
function common_port_smtp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your SMB port (Default : 25,465,587)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="SMTP_analysis_Report"
	xterm -e "service postgresql start;"
	smtp-user-enum -M VRFY -U /usr/share/brutex/wordlists/simple-users.txt -t $hosts   | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $new_path$output.txt;
	echo "" >> $new_path$output.txt;echo "" >> $new_path$output.txt;echo "" >> $new_path$output.txt;
	msfconsole -x "use scanner/smtp/smtp_enum; setg RHOSTS "$hosts"; setg RHOST "$hosts"; setg RPORT "$port"; run;use auxiliary/scanner/smtp/smtp_relay; setg EXTENDED true; run; exit;"  | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $new_path$output.txt; 
	x-www-browser $new_path$output.txt 2> /dev/null &
	active_recon_common_port_interface
	}

	
function common_port_snmp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your snmp port (Default : 161)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="SNMP_analysis_Report"
	nmap -sU -p $port --script=snmp-interfaces,snmp-netstat,snmp-brute,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}
	
function common_port_ssh_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your SSH port (Default : 22)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="SSH_analysis_Report"
	nmap -sV -sC -p $port --script ssh2-enum-algos $hosts -oX $new_path$output.xml 2> /dev/null
	xml2html $hosts/$port_analysis_path $output
	active_recon_common_port_interface
	}

	
function common_port_telnet_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your Telnet port (Default : 23)? \c"
	read port
	new_path="$report_path$hosts/$port_analysis_path"
	mkdir -p $new_path 2> /dev/null
	output="Telnet_analysis_Report"
	output2="Telnet_analysis_Report_II"	
	xterm -e "service postgresql start;"
	nmap -sV -sC -p $port --script telnet-ntlm-info $hosts -oX $new_path$output.xml 2> /dev/null
	cisco-torch -A $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $new_path$output2.txt;
	echo "" >> $new_path$output2.txt;echo "" >> $new_path$output2.txt;echo "" >> $new_path$output2.txt;
	msfconsole -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$hosts"; setg RHOST "$hosts"; run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;"    | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $new_path$output2.txt;
	xml2html $hosts/$port_analysis_path $output
	x-www-browser $new_path$output2.txt 2> /dev/null &
	active_recon_common_port_interface
	}
	

function active_recon_dns {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="DNS_Report"
	dnsrecon -d $hosts >> $report_path$hosts/$output.txt;
	echo "================================================================" >> $report_path$hosts/$output.txt;
	dnsrecon -d $hosts -t axfr >> $report_path$hosts/$output.txt;
	echo "================================================================" >> $report_path$hosts/$output.txt;
	dnsrecon -d $hosts -t zonewalk >> $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null &
	active_recon_interface
	}

	
function active_recon_nikto_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Nikto_Report"
	rm -f $report_path$hosts/$output.html
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	nikto -h $protocols://$hosts -F htm -output $output.html
	mv $output.html $report_path$hosts/$output.html
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	active_recon_interface
	}

	
function active_recon_load_balancer_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Load_balancer_report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	lbd $hosts |& tee -a $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null &
	active_recon_interface
	}
	

function active_recon_wafw00f_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="WAF_report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	wafw00f $hosts |& tee -a $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null &
	active_recon_interface
	}

	
function active_cms_identifier_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Site_Engine_Identifier_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	whatweb -a 3 -v $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null &
	active_recon_interface
	}	

	
function active_web_crawler_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "Got Cookies? [y/n] \c"
	read auth_cookies
	
	case "$auth_cookies" in
	"y")
		echo -e "Insert The Cookie Values \c"
		read cookies_value
		the_cookies="-C name=$cookies_value"
		;;
	*)
		the_cookies=""
		;;
	esac
	
	echo -e "How deep you want to crawl? e.g. (Max:16)  \c"
	read depth
	output="Web_Crawler"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	skipfish -d $depth $the_cookies -o $report_path$hosts/$output $protocols://$hosts;
	x-www-browser $report_path$hosts/$output/index.html 2> /dev/null &
	active_recon_interface
	}

	
function active_http_method_module {
	response='y'  
	while [ ${response:0:1} != n ]  
	do  
		output="HTTP_Method_Report"
		# Command(s) 
		echo
		#echo -e "Enter Link to test (e.g: www.example.com)  \c"
		#read links
		echo -e "Enter Link to test (e.g: www.example.com)  \c"
		read hosts
		mkdir -p $report_path$hosts 2> /dev/null
		echo -e "Please provide list of URL to be checked [PATH]:  \c"
		read links
		while IFS= read line
		do
			# display $line or do somthing with $line
			# echo "$line"
			echo "URL : $line" >> $report_path$hosts/$output.txt
			curl -i -X OPTIONS $line >> $report_path$hosts/$output.txt
			echo >> $report_path$hosts/$output.txt
			echo
			echo 
			echo
		done <"$links"
		
		read -p "Test again? Y/n " response 		
		[[ ${#response} -eq 0 ]] && response='y'  
	done 	
	xdg-open $report_path$hosts/$output.txt 2> /dev/null &
	active_recon_interface
	}	

	
function active_brute_dir_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	wordlist
	echo -e "Use wordlist path:  \c"
	read use_word_list
	mkdir -p $report_path$hosts 2> /dev/null
	echo -e "Bruteforce directory or file? [dir/file]  \c"
	read responses

	case "$responses" in
	"file")
		output="Web_Files_Bruteforce_Report"
		echo -e "File Type?: e.g. [php,html,asp,others..] \c"
		read file_type
		xterm -e "dirb $protocols://$hosts/ -X .$file_type $use_word_list  -o $report_path$hosts/$output.txt && $report_path$hosts/$output.txt 2> /dev/null ; x-www-browser $report_path$hosts/$output.txt 2> /dev/null" &
		active_recon_interface
		;;
	*)
		output="Web_Directory_Bruteforce_Report"
		xterm -e "dirb $protocols://$hosts/ $use_word_list  -o $report_path$hosts/$output.txt && $report_path$hosts/$output.txt 2> /dev/null ; x-www-browser $report_path$hosts/$output.txt 2> /dev/null" &
		active_recon_interface
		;;
	esac
	}
	
########################################################################################################################################################
#    _____       _             __               
#   |_   _|     | |           / _|              
#     | |  _ __ | |_ ___ _ __| |_ __ _  ___ ___ 
#     | | | '_ \| __/ _ \ '__|  _/ _` |/ __/ _ \
#    _| |_| | | | ||  __/ |  | || (_| | (_|  __/
#   |_____|_| |_|\__\___|_|  |_| \__,_|\___\___|
#                                               
#                                               

# Main Logo--------------------------------------------------------------------------------------------------------
function main_logo {
	clear && echo -en "\e[3J"
	echo ""
	echo -e "$OKRED███████╗ ██╗███╗   ███╗██████╗ ██╗     ██████╗   $RESET"
	echo -e "$OKRED██╔════╝███║████╗ ████║██╔══██╗██║     ╚════██╗  $RESET"
	echo -e "$OKRED███████╗╚██║██╔████╔██║██████╔╝██║      █████╔╝  $RESET"
	echo -e "$OKRED╚════██║ ██║██║╚██╔╝██║██╔═══╝ ██║      ╚═══██╗  $RESET"
	echo -e "$OKRED███████║ ██║██║ ╚═╝ ██║██║     ███████╗██████╔╝  $RESET"
	echo -e "$OKRED╚══════╝ ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═════╝ $app_version$RESET"
	}

# Main Function --------------------------------------------------------------------------------------------------------
function init {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the menu:
	
	1 : Passive Reconnaisance
	2 : Active Reconnaisance
	3 : Vulnerability Scanning
	4 : Search for Common Exploit
	9 : Update $SELF script
	
	99: Exit
	$RESET"
	
	echo -e "Adios! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		passive_recon_interface
		;;
	"2")
		active_recon_interface
		;;
	"3")
		va_scan
		;;
	"4")
		search_common_exploit
		;;
	"9")
		runSelfUpdate
		;;
	*)
		echo "Arigatou! Sayonara~"
		exit
		;;
	esac
	
	if [ -z $DISABLE_POSTGRESQL ]; then service postgresql start; fi
	}


# Passive Reconnaisance Interface--------------------------------------------------------------------------------------------------------
function passive_recon_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Passive Reconnaisance' menu:
	
	1  : Whois - $OKORANGE Whois Information $RESET $OKGREEN
	2  : Google Dork - $OKORANGE Information from Google $RESET $OKGREEN
	3  : AIO Site Information - $OKORANGE Informative site $RESET $OKGREEN
	4  : DNSDumpster - $OKORANGE Dns Recon & Research, Find & Lookup DNS Records $RESET $OKGREEN
	5  : Online Tools - $OKORANGE Free Online Recon and VA Tools $RESET $OKGREEN
	6  : theHarvester - $OKORANGE Email,Domain and Virtual Server enumerator  $RESET $OKGREEN
	7  : Banzai! - $OKORANGE Common Basic Passive Enumeration!  $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		pa_whois
		;;
	"2")
		pa_google_dork
		;;
	"3")
		pa_aio_site
		;;
	"4")
		pa_online_tools $pa_dnsdumpster_url
		passive_recon_interface
		;;
	"5")
		passive_recon_online_tools_interface
		;;
	"6")
		pa_harvester
		;;
	"7")
		pa_basic
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
	}


# Passive Recon Online Tools Interface--------------------------------------------------------------------------------------------------------
function passive_recon_online_tools_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Online Tools' menu:
	
	1  : Nmap - $OKORANGE Open Ports & Running Services Scanner $RESET $OKGREEN
	2  : Hostmap - $OKORANGE Hostnames & Virtual Hosts Discovery Tool $RESET $OKGREEN
	3  : Nikto - $OKORANGE Webserver VA Scanner $RESET $OKGREEN
	4  : WhatWeb - $OKORANGE CMS Identifier $RESET $OKGREEN
	5  : WPScan - $OKORANGE Wordpress VA Scanner $RESET $OKGREEN
	6  : Droopescan - $OKORANGE Drupal & Silverstripe VA Scanner $RESET $OKGREEN	
	7  : SQLMap - $OKORANGE Detecting SQL Injection Flaws $RESET $OKGREEN
	8  : All-in-one Tools - $OKORANGE Requires Account $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		pa_online_tools $pa_nmap_url
		passive_recon_online_tools_interface
		;;
	"2")
		pa_online_tools $pa_hosmap_url
		passive_recon_online_tools_interface
		;;
	"3")
		pa_online_tools $pa_nikto_url
		passive_recon_online_tools_interface
		;;
	"4")
		pa_online_tools $pa_whatsweb_url
		passive_recon_online_tools_interface
		;;
	"5")
		pa_online_tools $pa_wpscan_url
		passive_recon_online_tools_interface
		;;
	"6")
		pa_online_tools $pa_droopescan_url
		passive_recon_online_tools_interface
		;;
	"7")
		pa_online_tools $pa_sqlmap_url
		passive_recon_online_tools_interface
		;;
	"8")
		pa_online_tools $pa_aio_url
		passive_recon_online_tools_interface
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
	}
	
	
# Active Reconnaisance Interface--------------------------------------------------------------------------------------------------------
function active_recon_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Reconnaisance' menu:
	
	1  : Nmap - $OKORANGE Port Scanner $RESET $OKGREEN
	2  : DNS Reconnaisance - $OKORANGE Enumerate DNS Information $RESET $OKGREEN
	3  : Nikto - $OKORANGE Simple Basic Web Server Scanner $RESET $OKGREEN
	4  : WhatWeb - $OKORANGE Website Fingerprinter $RESET $OKGREEN
	5  : LBD - $OKORANGE Load Balancer Detector $RESET $OKGREEN
	6  : Wafw00f - $OKORANGE WAF Detector $RESET $OKGREEN
	7  : Skipfish - $OKORANGE Web Crawler $RESET $OKGREEN
	8  : HTTP Method Analyzer - $OKORANGE Http Method Analyzer $RESET $OKGREEN
	9  : Dirb - $OKORANGE Hidden Web Directory Bruteforcer $RESET $OKGREEN
	10 : Enumerate Common Port - $OKORANGE Active/Passive Website Crawler $RESET $OKGREEN
	11 : Armitage - $OKORANGE GUI Based Metasploit $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		active_recon_nmap_interface
		;;
	"2")
		active_recon_dns
		;;
	"3")
		active_recon_nikto_module
		;;
	"4")
		active_cms_identifier_module
		;;	
	"5")
		active_recon_load_balancer_module
		;;
	"6")
		active_recon_wafw00f_module
		;;
	"7")
		active_web_crawler_module
		;;
	"8")
		active_http_method_module
		;;
	"9")
		active_brute_dir_module
		;;
	"10")
		active_recon_common_port_interface
		;;
	"11")
		xterm -e "service postgresql start;armitage" &
		active_recon_interface
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
	}

	
# Active Recon Nmap Interface --------------------------------------------------------------------------------------------------------	
function active_recon_nmap_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Nmap command' menu:
	
	1 : Normal OS and Service Scan
	2 : Stealth OS and Service Scan [Very Slow!]
	3 : Normal UDP Scan
	4 : All-in-one Web Enumeration Scan
	5 : All-in-one SSL Vulnerability Scan
	6 : All-in-one Common Web Vulnerability Scan
	7 : NMAP Email Enumerator 
	
	99: Return	
	$RESET"
	
	echo -e "Hey! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		nmap_module
		;;
	"2")
		nmap_stealth_module
		;;	
	"3")
		nmap_udp_module
		;;
	"4")
		nmap_aio_enum_module
		;;
	"5")
		nmap_aio_ssl_module
		;;
	"6")
		nmap_aio_cve_module
		;;
	"7")
		nmap_email_enumerator_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		active_recon_interface
		;;
	esac
}


# Active Recon Common Service Interface --------------------------------------------------------------------------------------------------------	
function active_recon_common_port_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Nmap command' menu:
	
	1  : FTP - $OKORANGE (Normally Port 21) $RESET $OKGREEN 
	2  : IMAP - $OKORANGE (Normally Port 143) $RESET $OKGREEN 
	3  : MSSQL - $OKORANGE (Normally Port 1433) $RESET $OKGREEN 
	4  : MYSQL - $OKORANGE (Normally Port 3306) $RESET $OKGREEN 
	5  : NetBios - $OKORANGE (Internal) $RESET $OKGREEN 
	6  : POP3 - $OKORANGE (Normally Port 110) $RESET $OKGREEN 
	7  : SMB - $OKORANGE (Normally Port 445) $RESET $OKGREEN 
	8  : SMTP - $OKORANGE (Normally Port 25,465,587) $RESET $OKGREEN
	9  : SNMP - $OKORANGE (Normally Port 161) $RESET $OKGREEN 
	10 : SSH - $OKORANGE (Normally Port 22) $RESET $OKGREEN 
	11 : Telnet - $OKORANGE (Normally Port 23) $RESET $OKGREEN 
	12 : TFTP - $OKORANGE (Normally Port 69) $RESET $OKGREEN 
	13 : VMWARE
	14 : VNC - $OKORANGE (Normally Port 5900) $RESET $OKGREEN 
	
	99: Return	
	$RESET"
	
	echo -e "Hey! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		common_port_ftp_module
		;;
	"2")
		common_port_imap_module
		;;
	"3")
		common_port_mssql_module
		;;
	"4")
		common_port_mysql_module
		;;
	"5")
		common_port_netbios_module
		;;
	"6")
		common_port_pop3_module
		;;
	"7")
		common_port_smb_module
		;;
	"8")
		common_port_smtp_module
		;;
	"9")
		common_port_snmp_module
		;;
	"10")
		common_port_ssh_module
		;;
	"11")
		common_port_telnet_module
		;;
	"12")
		common_port_pop3_module
		;;
	"13")
		common_port_pop3_module
		;;
	"14")
		common_port_pop3_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		active_recon_interface
		;;
	esac
}

init
