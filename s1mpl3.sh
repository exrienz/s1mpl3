#!/bin/bash

#   __      __        _       _     _      
#   \ \    / /       (_)     | |   | |     
#    \ \  / /_ _ _ __ _  __ _| |__ | | ___ 
#     \ \/ / _` | '__| |/ _` | '_ \| |/ _ \
#      \  / (_| | |  | | (_| | |_) | |  __/
#       \/ \__,_|_|  |_|\__,_|_.__/|_|\___|
#                                          
#     

#Auto Update Script
set -o errexit
UPDATE_BASE=https://raw.githubusercontent.com/exrienz/s1mpl3/master/s1mpl3.sh
SELF=$(basename $0)

reldir=`dirname $0`
cd $reldir
default_directory=`pwd`

declare -r ip_local=$(ip -4 route get 8.8.8.8 | awk {'print $7'} | tr -d '\n')

declare -r app_version='V 6.2'

declare -r application_path='Application/'
declare -r report_path='Report/'
declare -r bin_path='/usr/local/bin'

declare -r nmap_git='https://github.com/nmap/nmap.git'
declare -r nmap_folder='nmap'

declare -r nikto_git='https://github.com/sullo/nikto.git'
declare -r nikto_folder='nikto'

declare -r sniper_git='https://github.com/1N3/Sn1per.git'
declare -r sniper_folder='Sn1per'

declare -r fatrat_git='https://github.com/Screetsec/TheFatRat.git'
declare -r fatrat_folder='TheFatRat'

declare -r metagoofil_git='https://github.com/laramies/metagoofil.git'
declare -r metagoofil_folder='metagoofil'

declare -r wig_git='https://github.com/jekyc/wig.git'
declare -r wig_folder='wig'

declare -r arachni_git='https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz'
declare -r arachni_folder='arachni/bin'

declare -r joomlavs_git='https://github.com/rastating/joomlavs.git'
declare -r joomlavs_folder='joomlavs'

declare -r droopescan_git='https://github.com/droope/droopescan.git'
declare -r droopescan_folder='droopescan'

declare -r liferayscan_git='https://github.com/bcoles/LiferayScan.git'
declare -r liferayscan_folder='LiferayScan/bin'
declare -r liferayscan_folder_main='LiferayScan'


declare -r nessus_git='http://www.coco.oligococo.tk/file/Nessus-6.10.5-debian6_amd64.deb'

declare -a required_apps=("nmap" 
						"nikto" 
						"sniper" 
						"./$application_path$metagoofil_folder/metagoofil.py" 
						"./$application_path$wig_folder/wig.py"
						"./$application_path$arachni_folder/arachni_web"
						"/etc/init.d/nessusd"
						"./$application_path$joomlavs_folder/joomlavs.rb"
						"./$application_path$liferayscan_folder/LiferayScan"
						"./$application_path$droopescan_folder/droopescan"
						)
						

declare -a wordlist_path=("/usr/share/wordlists/wfuzz/general/common.txt"
						"/usr/share/wordlists/wfuzz/general/medium.txt"
						"/usr/share/wordlists/wfuzz/general/big.txt"
						"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
						"/usr/share/wordlists/fasttrack.txt")

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'


#    ______                _   _             
#   |  ____|              | | (_)            
#   | |__ _   _ _ __   ___| |_ _  ___  _ __  
#   |  __| | | | '_ \ / __| __| |/ _ \| '_ \ 
#   | |  | |_| | | | | (__| |_| | (_) | | | |
#   |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|
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

	
#Convert XML to HTML
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
		xterm -e "apt-get install nikto & yes" &
		wait
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"sniper")
		#Download and install sn1per
		install_message $1
		install_git $sniper_git $sniper_folder
		chmod 777 $application_path$sniper_folder/install.sh &> /dev/null
		chmod 777 $application_path$sniper_folder/sniper.sh &> /dev/null
		xterm -e "./$application_path$sniper_folder/install.sh & yes & y" &
		wait
		rm -r $application_path$sniper_folder
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"		
		;;
	"./$application_path$metagoofil_folder/metagoofil.py")
		#Download and install Metagoofil
		install_message metagoofil
		install_git $metagoofil_git $metagoofil_folder
		chmod +x $application_path$metagoofil_folder/metagoofil.py &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		#Install apps
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
	"fatrat")
		echo -e "Fatrat module is not available, install now? (It might take a looong time!) y/n \c"
		read actions
		case "$actions" in
		"y")
			#Download and install fatrat
			install_message Fatrat
			if [ -d "$application_path$fatrat" ]; then
			  # if true this block of code will execute
				xterm -e "./$application_path$fatrat_folder/setup.sh" &
				wait
			else
				install_git $fatrat_git $fatrat_folder
				chmod +x $application_path$fatrat_folder/powerfull.sh
				chmod +x $application_path$fatrat_folder/setup.sh
				gnome-terminal -x "./$application_path$fatrat_folder/setup.sh" &
				wait
			fi
			#rm -r $application_path$fatrat_folder
			echo -e "$OKGREEN	[✔-OK!]::[Apps]: Fatrat $RESET"	
			exploit_interface
			;;
		*)
			exploit_interface
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

	
#    _____                        __  __           _       _      
#   |  __ \                      |  \/  |         | |     | |     
#   | |__) |___  ___ ___  _ __   | \  / | ___   __| |_   _| | ___ 
#   |  _  // _ \/ __/ _ \| '_ \  | |\/| |/ _ \ / _` | | | | |/ _ \
#   | | \ \  __/ (_| (_) | | | | | |  | | (_) | (_| | |_| | |  __/
#   |_|  \_\___|\___\___/|_| |_| |_|  |_|\___/ \__,_|\__,_|_|\___|
#                                                                 
#                                                                 

function nmap_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Intense_Scan_Report"
	nmap -p- -A -sV --version-intensity 5 --script=whois-ip,banner $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
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
	nmap_interface
	}

	
function nmap_aio_enum_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "What is your http port? \c"
	read portz
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Http_Enum_Scan_Report"
	nmap -p $portz -sV -sC --script=http-title,http-traceroute,http-waf-detect,http-waf-fingerprint,http-internal-ip-disclosure,http-server-header,whois-ip,http-exif-spider,http-headers,http-referer-checker,http-enum,http-open-redirect,http-phpself-xss,http-xssed,http-userdir-enum,http-sitemap-generator,http-svn-info,http-unsafe-output-escaping,http-default-accounts,http-aspnet-debug,http-php-version,http-cross-domain-policy,http-comments-displayer,http-backup-finder,http-auth-finder,http-apache-server-status,http-ls,http-mcmp,http-mobileversion-checker,http-robtex-shared-ns,firewalk --traceroute $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}
	

function nmap_aio_cve_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Http_CVE_Scan_Report"
	nmap --script=http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-5638 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
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
	nmap_interface
	}

	
function nmap_smb_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_SMB_Scan_Report"
	nmap -p 445 --script=smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-regsvc-dos,smb-vuln-conficker,smb-vuln-ms06-025,smb-vuln-cve2009-3103 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}
	
	
function metagofil_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	echo -e "Enter filetype separated by comma (e.g:- pdf, doc, xls,ppt,etc): \c"
	read files
	mkdir -p $report_path$hosts/files 2> /dev/null
	output="File_and_metadata_Report"
	python $application_path$metagoofil_folder/metagoofil.py -d $hosts -t $files -l 500 -n 1000 -o $report_path$hosts/files -f $report_path$hosts/$output.html
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	recon
	}

	
function sniper_module {
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	
	echo -e "Do a passive (Stealth) scan? (y/n) \c"
	read  choice
	
	
	if [ $choice != "y" ]
	then
	  #If not yes, use web scan
	  scan_mode="web"
	else
	  #Use stealth scan
	  scan_mode="stealth"
	fi
	
	xterm -e "sniper $hosts $scan_mode report <<< $hosts" &
	wait
	xterm -e "sniper loot <<< $hosts" &
	wait
	echo "Done!"
	recon
	}
	
	
function brute_dir_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	wordlist
	echo -e "Use wordlist path:  \c"
	read use_word_list
	output="Web_Directory_Bruteforce_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	#wfuzz -c -z file,/usr/share/wordlists/fasttrack.txt --hc 404,301 -o html http://example.com/FUZZ > output.html
	echo -e $OKRED
	echo -e "Bruteforcing....Please wait...... "$RESET
	xterm -e "wfuzz -c -z file,$use_word_list --hc 404,301,302 -o html $protocols://$hosts/FUZZ | tee -a $report_path$hosts/$output.html"
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	recon
	}
	

function nikto_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="Nikto_Report"
	rm -f $output.html
	nikto -h $protocols://$hosts -F htm -output $output.html
	mv $output.html $report_path$hosts/$output.html
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	recon
	}
	
	
function wig_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	output="CMS_Identifier_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	#./Application/wig/wig.py http://localhost:9292  &>> Report/localhost/CMS_Identifier_Report.txt
	echo  -e $OKRED & echo -e "Scanning...This process might take same time, please wait..$RESET" & echo
	./Application/wig/wig.py $protocols://$hosts  | tee -a $report_path$hosts/$output.txt
	xdg-open $report_path$hosts/$output.txt 2> /dev/null &
	recon
	}	
	
	
function maltego_module {
	xterm -hold -e 'maltegoce' &
	recon
	}

	
function reconng_module {
	echo -e '#!/bin/sh\n recon-ng' > $application_path/reconng.sh
	chmod +x $application_path/reconng.sh
	gnome-terminal -x $application_path/reconng.sh &
	recon
	}
	
	
function maltego_module {
	xterm -e 'maltegoce' &
	wait
	recon
	}
	
	
function http_method_module {
	response='y'  
	while [ ${response:0:1} != n ]  
	do  
		output="HTTP_Method_Report"
		# Command(s) 
		echo
		#echo -e "Enter Link to test (e.g: www.example.com)  \c"
		#read links
		echo -e "Please give name for output file:  \c"
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
	recon
	}	


#     _____                       _               __  __           _       _      
#    / ____|                     (_)             |  \/  |         | |     | |     
#   | (___   ___ __ _ _ __  _ __  _ _ __   __ _  | \  / | ___   __| |_   _| | ___ 
#    \___ \ / __/ _` | '_ \| '_ \| | '_ \ / _` | | |\/| |/ _ \ / _` | | | | |/ _ \
#    ____) | (_| (_| | | | | | | | | | | | (_| | | |  | | (_) | (_| | |_| | |  __/
#   |_____/ \___\__,_|_| |_|_| |_|_|_| |_|\__, | |_|  |_|\___/ \__,_|\__,_|_|\___|
#                                          __/ |                                  
#                                         |___/                                   

function arachni_module {
	xterm -hold -e 'echo -e "Admin Account	:--- user: admin@admin.admin	pass: administrator" &
	echo -e "User Account	:--- user: user@user.user	pass: regular_user" &
	./Application/arachni/bin/arachni_web' &
	sleep 25
	x-www-browser http://localhost:9292 &
	va_scanning
	}

	
function open_vas_module {
	xterm -hold -e 'echo -e "User Account	user: admin	pass: admin" && 
	echo -e "echo -e "In case of any error, please run '"openvas-setup"' commmand""
	openvas-start &&
	openvasmd --create-user admin;
	openvasmd --user=admin --new-password=admin' &
	#openvas-start
	#openvas-stop
	sleep 25
	x-www-browser https://127.0.0.1:9392 &
	va_scanning
	}

	
function burpsuite_module {
	xterm -hold -e 'echo "
	DONT CLOSE THIS WINDOW!
	Please set proxy to 127.0.0.1:8080 and enable intercept mode" & 
	echo &
	burpsuite'&
	sleep 25
	x-www-browser &
	va_scanning
	}

	
function nessus_module {
	xterm -hold -e 'echo "For 1st time login:
    1. Register account
    2. Enter licence, register from here : https://www.tenable.com/register" && 
	/etc/init.d/nessusd start' &
	sleep 25
	x-www-browser https://kali:8834/ &
	va_scanning
	}


function wpscan_module {
	
	echo -e "What is your host? e.g. www.example.com  \c"
	read hosts
	
	echo -e "$OKGREEN

	Scan Wordpress using:
	
	1 : Non Intrusive Scane
	2 : Enumerate User
	3 : Enumerate Plugins
	4 : Enumerate Themes
	
	99: Exit
	$RESET"
	
	echo -e "Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		xterm -hold -e "wpscan --url $hosts" &
		CMS_Interface
		;;
	"2")
		xterm -hold -e "wpscan --url $hosts --enumerate u" &
		CMS_Interface
		;;
	"3")
		xterm -hold -e "wpscan --url $hosts --enumerate p" &
		CMS_Interface
		;;
	"4")
		xterm -hold -e "wpscan --url $hosts --enumerate t" &
		CMS_Interface
		;;
	"1")
		xterm -hold -e "wpscan --url $hosts" &
		CMS_Interface
		;;
	*)
		echo "Bye Bye~"
		exit
		;;
	esac
	
	}
	
	
function joomlavs_module {
	echo -e "What is your host? e.g www.example.com  \c"
	read hosts	
	xterm -hold -e "./$application_path$joomlavs_folder/joomlavs.rb -u $hosts --scan-all" &
	CMS_Interface
	}
	
	
function droopescan_module {
	echo -e "What is your host? e.g www.example.com  \c"
	read hosts
	xterm -hold -e "./$application_path$droopescan_folder/droopescan scan drupal -u $hosts -t 8" &
	CMS_Interface
	}
	
	
function liferayscan_module {
	echo -e "What is your host? e.g www.example.com  \c"
	read hosts
	xterm -hold -e "./$application_path$liferayscan_folder/LiferayScan -u $hosts" &
	CMS_Interface
	}

	
#    ______            _       _ _     __  __           _       _      
#   |  ____|          | |     (_) |   |  \/  |         | |     | |     
#   | |__  __  ___ __ | | ___  _| |_  | \  / | ___   __| |_   _| | ___ 
#   |  __| \ \/ / '_ \| |/ _ \| | __| | |\/| |/ _ \ / _` | | | | |/ _ \
#   | |____ >  <| |_) | | (_) | | |_  | |  | | (_) | (_| | |_| | |  __/
#   |______/_/\_\ .__/|_|\___/|_|\__| |_|  |_|\___/ \__,_|\__,_|_|\___|
#               | |                                                    
#               |_|                                                    


function fatrat_module {
	gnome-terminal -e "fatrat" &
	exploit_interface
	}

	
#    _____       _             __               
#   |_   _|     | |           / _|              
#     | |  _ __ | |_ ___ _ __| |_ __ _  ___ ___ 
#     | | | '_ \| __/ _ \ '__|  _/ _` |/ __/ _ \
#    _| |_| | | | ||  __/ |  | || (_| | (_|  __/
#   |_____|_| |_|\__\___|_|  |_| \__,_|\___\___|
#                                               
#                                               

# Main Logo
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


# Landing Page Interface
function init {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the menu:
	
	1 : Reconnaisance
	2 : Vulnerability Scanning
	3 : Exploit
	9 : Update $SELF script
	
	99: Exit
	$RESET"
	
	echo -e "Adios! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		recon
		;;
	"2")
		va_scanning
		;;
	"3")
		exploit_interface
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


# Reconnaisance Interface
function recon {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Reconnaisance' menu:
	
	1  : Nmap - $OKORANGE Port Scanner $RESET $OKGREEN
	2  : Sn1per - $OKORANGE All-in-one Enumerator $RESET $OKGREEN
	3  : Nikto - $OKORANGE Server Configuration Scanner $RESET $OKGREEN
	4  : Wig - $OKORANGE CMS Identifier $RESET $OKGREEN
	5  : Burpsuite_module - $OKORANGE Active/Passive Website Crawler $RESET $OKGREEN
	6  : WFuzz - $OKORANGE Hidden Web Directory Bruteforcer $RESET $OKGREEN
	7  : Metagoofil - $OKORANGE Information gathering tool $RESET $OKGREEN
	8  : HTTP Method Analyzer - $OKORANGE Http Method Analyzer $RESET $OKGREEN
	9  : Maltego - $OKORANGE Reconnaissance framework $RESET $OKGREEN
	10 : Recon-Ng - $OKORANGE Web Reconnaissance framework $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		nmap_interface
		;;
	"2")
		sniper_module
		;;
	"3")
		nikto_module
		;;
	"4")
		wig_module
		;;
	"5")
		burpsuite_module
		;;
	"6")
		brute_dir_module
		;;
	"7")
		metagofil_module
		;;
	"8")
		http_method_module
		;;
	"9")
		maltego_module
		;;
	"10")
		reconng_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
	}


#Nmap Interface	
function nmap_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Nmap command' menu:
	
	1 : Normal Intense Scan
	2 : UDP Scan
	3 : All-in-one Web Enumeration
	4 : All-in-one SSL Vulnerability Scan
	5 : All-in-one Common Web Vulnerability Scan
	6 : Basic SMB Scanner (TODO: Doublepulsar)
	7 : Update NSE Script
	
	99: Return	
	$RESET"
	
	echo -e "Hey! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		nmap_module
		;;
	"2")
		nmap_udp_module
		;;
	"3")
		nmap_aio_enum_module
		;;
	"4")
		nmap_aio_ssl_module
		;;
	"5")
		nmap_aio_cve_module
		;;
	"6")
		nmap_smb_module
		;;
	"7")
		nmap --script-updatedb
		nmap_interface
		;;
	*)
		#echo "Huhhh! Wrong input!"
		recon
		;;
	esac
}


#Vulnerability Scanning Interface
function va_scanning {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Vulnerability Scanning' menu:
	
	1 : Arachni - $OKORANGE  Web Application Security Scanner $RESET $OKGREEN
	2 : Openvas - $OKORANGE (Halted!) Vulnerability Scanning $RESET $OKGREEN
	3 : Nessus - $OKORANGE Vulnerability Scanning Tool $RESET $OKGREEN
	4 : Burpsuit - $OKORANGE  Toolkit for Web Application Security Testing $RESET $OKGREEN
	5 : CMS Vulnerability Scanner - $OKORANGE Wordpress,Joomla,Drupal,Liferay  $RESET $OKGREEN
	5 : OWASP Top 10 Vulnerability Scanner - $OKORANGE SQLi,XXS,LFI,RFI etc  $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		arachni_module
		;;
	"2")	
		#Check Openvas if installed	
		if apps_exist "openvas-start" ; then
			#Execute OpenVas
			open_vas_module
		else
			install_apps openvas-start
		fi
		;;
	"3")
		nessus_module
		;;
	"4")
		burpsuite_module
		;;
	"5")
		CMS_Interface
		;;
	"6")
		OWASP_Interface
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
}


#CMS Scanner Interface
function CMS_Interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Vulnerability Scanning' menu:
	
	1 : WPScan  - $OKORANGE  WordPress vulnerability scanner $RESET $OKGREEN
	2 : Joomlavs - $OKORANGE Joomla vulnerability scanner $RESET $OKGREEN
	3 : Droopescan - $OKORANGE Drupal & Silver Stripe vulnerability scanner $RESET $OKGREEN
	4 : LiferayScan - $OKORANGE  Liferay vulnerability scanner $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		wpscan_module
		;;
	"2")
		joomlavs_module
		;;
	"3")
		droopescan_module
		;;
	"4")
		liferayscan_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
}


#Owasp Interface	
function OWASP_Interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Nmap command' menu:
	
	1 : Shuriken - $OKORANGE  Automated XSS Scanner $RESET $OKGREEN
	2 : SQLMap - $OKORANGE Automated SQLi Scanner $RESET $OKGREEN
	3 : Kadimus - $OKORANGE  LFI Scanner $RESET $OKGREEN
	4 : All-in-one SSL Vulnerability Scan
	5 : All-in-one Common Web Vulnerability Scan
	6 : Basic SMB Scanner (TODO: Doublepulsar)
	7 : Update NSE Script
	
	99: Return	
	$RESET"
	
	echo -e "Hey! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		nmap_module
		;;
	"2")
		nmap_udp_module
		;;
	"3")
		nmap_aio_enum_module
		;;
	"4")
		nmap_aio_ssl_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		recon
		;;
	esac
}


#Exploit Interface
function exploit_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-]
[-]       	    Local IP:         	  [-]$RESET $OKORANGE
[-]             $ip_local      	  [-]$RESET $OKGREEN  

Select from the 'Vulnerability Scanning' menu:
	
	1 : Fatrat - $OKORANGE  FUD Backdoor Generator $RESET $OKGREEN
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")		
		#Check Fatrat if installed	
		if apps_exist "fatrat" ; then
			#Execute OpenVas
			fatrat_module
		else
			install_apps fatrat
		fi
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
}


#Dependency Check
function setup {
	main_logo
	echo ""
	echo -e "$OKRED [!]::[Check Dependencies]: $RESET"
	echo ""

		for i in "${required_apps[@]}"
		do
			if apps_exist $i ; then
				echo -e "$OKGREEN	[✔-OK!]::[Apps]: $i $RESET"
			else
				echo -e "$OKRED	[x-Missing!]::[Apps]: $i $RESET"
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

#Update
#nikto -update

# TODO
# python3 altinstall
# autodownload nmap NSE script
# Use another frame to install openvas
# 
