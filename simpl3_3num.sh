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
declare -r app_version='BETA 2.9'


#Auto Update Script
set -o errexit
UPDATE_BASE=https://raw.githubusercontent.com/exrienz/s1mpl3/master/simpl3_3num.sh
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

declare -r domain_analyzer_git='https://github.com/eldraco/domain_analyzer.git'
declare -r domain_analyzer_folder='domain_analyzer'

declare -r ssh_audit_git='https://github.com/arthepsy/ssh-audit.git'
declare -r ssh_audit_folder='ssh-audit'

declare -r shocker_git='https://github.com/nccgroup/shocker.git'
declare -r shocker_folder='shocker'

declare -r massbleed_git='https://github.com/1N3/MassBleed.git'
declare -r massbleed_folder='MassBleed'

declare -r spaghetti_git='https://github.com/m4ll0k/Spaghetti.git'
declare -r spaghetti_folder='Spaghetti'


#AUTOINSTALL APPLICATION
declare -a required_apps=(
						"./$application_path$theHarvester_folder/theHarvester.py"
						"./$application_path$domain_analyzer_folder/domain_analyzer.py"
						"./$application_path$ssh_audit_folder/ssh-audit.py"
						"./$application_path$shocker_folder/shocker.py"
						"./$application_path$massbleed_folder/massbleed"
						"./$application_path$spaghetti_folder/spaghetti.py"
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
	echo -e "[-]::[Installing]: Downloading $1..Please Wait...."
	}

function install_success {
	#Download and install nmap
	echo -e "[✔-Installation Success!]::[Apps]: $1 $RESET"
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
	xsltproc $report_path$1/$2.xml -o $report_path$1/$2.html | 2> /dev/null
	rm $report_path$1/$2.xml | 2> /dev/null
	x-www-browser $report_path$1/$2.html | &> /dev/null &
	}

function xml2htmlII () {
	xsltproc $report_path$1/$2.xml -o $report_path$1/$2.html | 2> /dev/null
	x-www-browser $report_path$1/$2.html | &> /dev/null &
	}
	
#Check if Vulscan Script available
if [ -e /usr/share/nmap/scripts/vulscan/vulscan.nse ]
then
	echo -e "$OKGREEN"
    echo -e "[✔-OK!]::[Apps]: Vulscan Script Available $RESET"
else
	echo -e "$OKRED"
    echo -e "[x-Missing!]::[Apps]: Vulscan Script Not-Available $RESET"
	mkdir -p /usr/share/nmap/scripts/vulscan 2> /dev/null
	git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan	
	echo -e "$OKGREEN"
	echo -e "[✔-OK!]::[Apps]: Vulscan Script Available $RESET"
fi

	
#Install missing application
function install_apps {
	case "$1" in
	"./$application_path$theHarvester_folder/theHarvester.py")
		#Download and install theHarvester
		install_message theHarvester
		install_git $theHarvester_git $theHarvester_folder
		#Install apps
		chmod +x $application_path$theHarvester_folder/theHarvester.py &> /dev/null
		install_success theHarvester
		;;
	"./$application_path$domain_analyzer_folder/domain_analyzer.py")
		#Download and install domain_analyzer
		install_message domain_analyzer
		install_git $domain_analyzer_git $domain_analyzer_folder
		#Install apps
		install_success domain_analyzer
		;;
	"./$application_path$ssh_audit_folder/ssh-audit.py")
		#Download and install ssh-audit
		install_message ssh-audit
		install_git $ssh_audit_git $ssh_audit_folder
		chmod +x $application_path$ssh_audit_folder/ssh-audit.py &> /dev/null
		#Install apps
		install_success ssh-audit
		;;
	"./$application_path$shocker_folder/shocker.py")
		#Download and install shocker
		install_message Shocker
		install_git $shocker_git $shocker_folder
		chmod +x $application_path$shocker_folder/shocker.py &> /dev/null
		#Install apps
		install_success Shocker
		;;
	"./$application_path$massbleed_folder/massbleed")
		#Download and install MassBleed
		install_message MassBleed
		install_git $massbleed_git $massbleed_folder
		chmod +x $application_path$massbleed_folder/massbleed $application_path$massbleed_folder/heartbleed.py $application_path$massbleed_folder/winshock.sh $application_path$massbleed_folder/openssl_ccs.pl &> /dev/null
		#Install apps
		install_success MassBleed
		;;
	"./$application_path$spaghetti_folder/spaghetti.py")
		#Download and install Spaghetti
		install_message Spaghetti
		install_git $spaghetti_git $spaghetti_folder
		chmod +x $application_path$spaghetti_folder/spaghetti.py &> /dev/null
		pip install -r $application_path$spaghetti_folder/requirements.txt
		#Install apps
		install_success Spaghetti
		;;
	*)
		# echo ""
		# echo -e "$OKGREEN"
		# echo -e "Enjoy! $RESET"
		# echo ""
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
	x-www-browser --new-tab $pa_whois_url$hosts  | &> /dev/null &
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
					
		x-www-browser --new-tab ${dorks[@]} | &> /dev/null &
		
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

	declare -a dorks=(
					" -url http://toolbar.netcraft.com/site_report?url=$hosts"
					" -url https://www.tcpiputils.com/browse/domain/$hosts"
					" -url https://www.threatcrowd.org/domain.php?domain=$hosts"
					" -url https://httpsecurityreport.com/?report=$hosts"
					" -url https://www.robtex.com/dns-lookup/$hosts"
					" -url https://mxtoolbox.com/domain/$hosts/"
					" -url http://www.dnsstuff.com/tools#dnsReport|type=domain&&value=$hosts"
					" -url https://www.shodan.io/search?query=$hosts"
					" -url https://www.censys.io/ipv4?q=$hosts"
					" -url https://www.builtwith.com/$hosts"
					" -url https://web.archive.org/web/*/$hosts"
					" -url https://www.openbugbounty.org/search/?search=$hosts&type=hosts"
					" -url https://crt.sh/?q=$hosts"
					" -url https://www.ssllabs.com/ssltest/analyze.html?d=$hosts&latest")
					
		x-www-browser --new-tab ${dorks[@]} | &> /dev/null &
		
		passive_recon_interface
		;;
	*)
		passive_recon_interface
		;;
	esac
	}
	
	
#Passive Online Tools
function pa_online_tools {		
	x-www-browser --new-tab -url "$1" | &> /dev/null &
}


#Passive Online Credential Harvester
function pa_harvester {
	echo -e "What is your root host? e.g. example.com (NO SUBDOMAIN!)  \c"
	read hosts
	output="Email_Domain_Harvest_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	xterm -e "python $application_path$theHarvester_folder/theHarvester.py -d $hosts -l 500 -b all -f $output.html; mv $output.html $report_path$hosts; rm -f $output.xml; x-www-browser --new-tab -url '$report_path/$hosts/$output.html'  | &> /dev/null &" &
	passive_recon_interface
	}


#Passive Gatling Gun	
function pa_gatling_gun {
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
	
	x-www-browser --new-tab -url $report_path$hosts/$output.txt  | &> /dev/null &
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

	
#NMAP Service and OS Scan + Vulnscan + AutoEnum 	
function nmap_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "Use Vulscan (Might consist False Positive!) ? [y/n]  \c"
	read vul_resp	
		case "$vul_resp" in
		"y")
			vulscan_value="--script=vulscan/vulscan.nse  --script-args vulscandb=exploitdb.csv"
			;;
			*)
				vulscan_value=""
				;;
		esac
	echo	
	
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_OS_and_Service_Scan_Report"
	#nmap -sS -Pn -sV $vulscan_value --script=whois-ip,banner,iscsi-brute,isns-info,ntp-info,fingerprint-strings $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	nmap -sS -Pn -sV $vulscan_value --script "default or safe",firewalk  $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2htmlII $hosts $output
	# echo
	# echo -e "Use auto-pawn (Might destructive!)? [y/n]  \c"
	# read actions
	# echo	
	# case "$actions" in
	# "y")
		
		# service postgresql start				
		
		# export TARGET="$hosts"
		# export PATHS="$report_path$hosts/$output.xml"
		# export CURRENT_PATH="$default_directory/"
		# export APPLICATION_PATH="$application_path"
		# export REPORT_PATH="$report_path"
		
		# outputII="Detailed_Port_Analysis_Report"
		
		# . ./snipe.sh |& tee -a $report_path$hosts/$outputII.txt &&
		# wait			
		# active_recon_nmap_interface
		# ;;
	# *)
		# active_recon_nmap_interface
		# ;;
	# esac
	active_recon_nmap_interface
	}


#NMap Stealth Scan	
function nmap_stealth_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Stealth_Scan_Report"
	nmap --mtu 24 -A -sV  $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}		
	
	
#NMap UDP Module
function nmap_udp_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_UDP_Scan_Report"
	nmap -sU $hosts --script=banner -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	active_recon_nmap_interface
	}

	
#NMap email enumerator	
function nmap_email_enumerator_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your web port? (e.g. 80) \c"
	read port
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_email_enumerator_Report"
	nmap -p $port $hosts --script http-grep --script-args='match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",breakonmatch' -oX $report_path$hosts/$output.xml
	xml2html $hosts $output
	active_recon_nmap_interface
	}


#Domain Analyzer
function domain_analyzer_module {
	echo -e "What is your host? (No sub-domain!) e.g. example.com  \c"
	read hosts
	output="Domain_Analysis"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	./$application_path$domain_analyzer_folder/domain_analyzer.py -d $hosts -a -B | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null  | &> /dev/null &
	active_recon_interface
}
	
#Web/port capture
function active_recon_capture_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is the target host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is the target port (one port at one time)? e.g. 80  \c"
	read ports
	mkdir -p $report_path$hosts 2> /dev/null
	output="_screenshoot_port_"
	cutycapt --url=$protocols://$hosts:$ports --out=$report_path$hosts/$hosts$output$ports.jpg
	active_recon_interface
	}

#Nikto Module	
function active_recon_nikto_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Basic_Vulnerability_Report"
	rm -f $report_path$hosts/$output.html
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	#Nikto_Scan
	echo " __ _  __  __ _  ____  __     ____   ___   __   __ _ " |& tee -a  $report_path$hosts/$output.txt;
	echo "(  ( \(  )(  / )(_  _)/  \   / ___) / __) / _\ (  ( \ " |& tee -a  $report_path$hosts/$output.txt;
	echo "/    / )(  )  (   )( (  O )  \___ \( (__ /    \/    / " |& tee -a  $report_path$hosts/$output.txt;
	echo "\_)__)(__)(__\_) (__) \__/   (____/ \___)\_/\_/\_)__)" |& tee -a  $report_path$hosts/$output.txt;
	echo "" |& tee -a  $report_path$hosts/$output.txt;
	nikto -h $protocols://$hosts |& tee -a |& tee -a  $report_path$hosts/$output.txt;
	echo "" |& tee -a  $report_path$hosts/$output.txt;
	#UniScan
	# echo "" |& tee -a  $report_path$hosts/$output.txt;
	# uniscan -u $hosts/ -qweds |& tee -a  $report_path$hosts/$output.txt;
	# echo "" |& tee -a  $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt 2> /dev/null  | &> /dev/null &
	#Spaghetti Scan
	echo ""
	python $application_path$spaghetti_folder/spaghetti.py --url $hosts --scan 0 --random-agent --verbose
	echo ""
	#Show Report
	while true;
	do
		read -r -p "Spaghetti scan cant be saved (for now), exit ? [y/n]  " response   
		if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
		then
			active_recon_interface
		fi
	done
	}

#Load Balancer Detector Module	
function active_recon_load_balancer_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Load_balancer_report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	lbd $hosts |& tee -a $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt | &> /dev/null &
	active_recon_interface
	}

#Waf Identifier Module
function active_recon_wafw00f_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="WAF_report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	wafw00f $hosts |& tee -a $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt | &> /dev/null &
	active_recon_interface
	}


#CMS Identifier Module
function active_cms_identifier_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Site_Engine_Identifier_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	whatweb -a 3 -v $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt  | &> /dev/null &
	active_recon_interface
	}	


#SSL Analyzer module
function active_recon_ssl_analyzer {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="SSL_report"
	mkdir -p $report_path$hosts 2> /dev/null
	echo ""
	sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	echo ""
	echo "==================================================================================================">> $report_path$hosts/$output.txt;
	echo ""
	sslscan --no-failed $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	echo ""
	echo "==================================================================================================">> $report_path$hosts/$output.txt;
	echo ""
	testssl $hosts | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g" |& tee -a  $report_path$hosts/$output.txt;
	
	x-www-browser $report_path$hosts/$output.txt  | &> /dev/null &
	active_recon_interface
}


#Skipfish web crawler
function active_web_crawler_module {
	# echo -e "Http or Https? \c"
	# read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	# echo -e "Got Cookies? [y/n] \c"
	# read auth_cookies
	
	# case "$auth_cookies" in
	# "y")
		# echo -e "Insert The Cookie Values \c"
		# read cookies_value
		# the_cookies="-C name=$cookies_value"
		# ;;
	# *)
		# the_cookies=""
		# ;;
	# esac
	
	# echo -e "How deep you want to crawl? e.g. (Max:16)  \c"
	# read depth
	
	
	output="Web_Crawler"
	mkdir -p $report_path$hosts  2> /dev/null
	# echo ""
	# skipfish -d $depth $the_cookies -o $report_path$hosts/$output $protocols://$hosts;
	echo -e "$OKRED	[✔-OK!]::[Progress]: Crawling in progress..Please Wait! $RESET"
	./$application_path$domain_analyzer_folder/crawler.py -u $hosts -s -m 100 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | sed "s/\x0f//g"  >  $report_path$hosts/$output.txt;
	x-www-browser $report_path$hosts/$output.txt | &> /dev/null &
	# x-www-browser $report_path$hosts/$output/index.html | &> /dev/null &
	active_recon_interface
	}
	
	
#Dirb Module
function active_brute_dir_module {
	# xterm -e "dirbuster" &
	# active_recon_interface
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
		echo -e "File Type (can be more than one)?: e.g. [.php,.html,.asp,.others..] \c"
		read file_type
		xterm -e "dirb $protocols://$hosts/ -X $file_type $use_word_list  -o $report_path$hosts/$output.txt && $report_path$hosts/$output.txt 2> /dev/null ; x-www-browser $report_path$hosts/$output.txt  | 2> /dev/null " &
		active_recon_interface
		;;
	*)
		output="Web_Directory_Bruteforce_Report"
		xterm -e "dirb $protocols://$hosts/ $use_word_list  -o $report_path$hosts/$output.txt && $report_path$hosts/$output.txt 2> /dev/null ; x-www-browser $report_path$hosts/$output.txt  | 2> /dev/null " &
		active_recon_interface
		;;
	esac
	}


#Http Method Module
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
	xdg-open $report_path$hosts/$output.txt  | &> /dev/null &
	active_recon_interface
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
	7  : Gatling Gun! - $OKORANGE Quick AIO Passive Reconnaisance $RESET $OKGREEN
	
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
		pa_gatling_gun
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

Select from the 'Passive Online Tools' menu:
	
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

Select from the 'Active Reconnaisance' menu:
	
	1  : Nmap - $OKORANGE Port Scanner $RESET $OKGREEN
	2  : Domain Analyzer - $OKORANGE Top-Level Domain Analyzer $RESET $OKGREEN
	3  : CutyCapt - $OKORANGE Capture Web Port Interface $RESET $OKGREEN
	4  : Basic Vulnerability Scanner - $OKORANGE Basic VA Tool $RESET $OKGREEN
	5  : WhatWeb - $OKORANGE CMS Identifier Module $RESET $OKGREEN
	6  : LBD - $OKORANGE Load Balancer Detector $RESET $OKGREEN
	7  : WAF Identifier - $OKORANGE Web Application Firewall Scanner $RESET $OKGREEN
	8  : SSL Analyzer - $OKORANGE Analyze SSL Security $RESET $OKGREEN
	9  : Web Spider - $OKORANGE Simple Web Crawler $RESET $OKGREEN
	10 : Dirbuster - $OKORANGE Hidden Web Directory Bruteforcer $RESET $OKGREEN
	11 : HTTP Method Analyzer - $OKORANGE Http Method Analyzer $RESET $OKGREEN
	12 : Armitage - $OKORANGE GUI Based Metasploit $RESET $OKGREEN
	13 : Burpsuite - $OKORANGE Proxy-based WAPT Framework $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		active_recon_nmap_interface
		;;
	"2")
		domain_analyzer_module
		;;
	"3")
		active_recon_capture_module
		;;
	"4")
		active_recon_nikto_module
		;;
	"5")
		active_cms_identifier_module
		;;
	"6")
		active_recon_load_balancer_module
		;;
	"7")
		active_recon_wafw00f_module
		;;
	"8")
		active_recon_ssl_analyzer
		;;
	"9")
		active_web_crawler_module
		;;
	"10")
		active_brute_dir_module
		;;
	"11")
		active_http_method_module
		;;
	"12")
		xterm -e "service postgresql start && armitage" &
		active_recon_interface
		;;
	"13")
		xterm -e "burpsuite" &
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
	
	1 : OS and Service Scan
	2 : Stealth Scan
	3 : UDP Scan
	4 : NMAP Email Enumerator 
	
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
		nmap_email_enumerator_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		active_recon_interface
		;;
	esac
}


#Dependency Check
function setup {
	main_logo
	echo ""
	echo -e "$OKRED"
	echo -e "[!]::[Checking Dependencies]: $RESET"

		for i in "${required_apps[@]}"
		do
			if apps_exist $i ; then
				echo -e "$OKGREEN"
				echo -e "[✔-OK!]::[Apps]: $i $RESET"
			else
				echo -e "$OKRED"
				echo -e "[x-Missing!]::[Apps]: $i $RESET $OKGREEN"
				install_apps $i
			fi
		done
		}

		
#    __  __       _       
#   |  \/  |     (_)      
#   | \  / | __ _ _ _ __  
#   | |\/| |/ _` | | '_ \ 
#   | |  | | (_| | | | | |
#   |_|  |_|\__,_|_|_| |_|
#                         
#                         
setup
init



####TODO
#	1. Harvester cant create dir
#	2. Add Default Credential Pages 
#
#
#
#
