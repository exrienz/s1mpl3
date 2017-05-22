#!/bin/bash

#   __      __        _       _     _      
#   \ \    / /       (_)     | |   | |     
#    \ \  / /_ _ _ __ _  __ _| |__ | | ___ 
#     \ \/ / _` | '__| |/ _` | '_ \| |/ _ \
#      \  / (_| | |  | | (_| | |_) | |  __/
#       \/ \__,_|_|  |_|\__,_|_.__/|_|\___|
#                                          
#     

declare -r application_path='Application/'
declare -r report_path='Report/'
declare -r bin_path='/usr/local/bin'

declare -r nmap_git='https://github.com/nmap/nmap.git'
declare -r nmap_folder='nmap'

declare -r nikto_git='https://github.com/sullo/nikto.git'
declare -r nikto_folder='nikto'

declare -r sniper_git='https://github.com/1N3/Sn1per'
declare -r sniper_folder='Sn1per'

declare -r fatrat_git='https://github.com/Screetsec/TheFatRat.git'
declare -r fatrat_folder='TheFatRat'

declare -r metagoofil_git='https://github.com/laramies/metagoofil.git'
declare -r metagoofil_folder='metagoofil'

declare -r wig_git='https://github.com/jekyc/wig.git'
declare -r wig_folder='wig'

declare -r arachni_git='https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz'



declare -a required_apps=("nmap" 
						"nikto" 
						"sniper" 
						"fatrat" 
						"./$application_path$metagoofil_folder/metagoofil.py" 
						"./$application_path$wig_folder/wig.py"
						"./Application/arachni/bin/arachni_web"
						"openvas-start"
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
	git clone $1 $application_path$2  &> /dev/null
	}

function install_message {
	#Download and install nmap
	echo -e "$OKGREEN	[-]::[Installing]: Downloading $1..Please Wait.... $RESET"
	}

function install_apps {
	case "$1" in
	"nmap")
		install_message $1
		apt-get install nmap
		y
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"nikto")
		#Download and install nikto	
		install_message $1
		install_git $nikto_git $nikto_folder
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"sniper")
		#Download and install sn1per
		install_message $1
		install_git $sniper_git $sniper_folder
		chmod 777 $application_path$sniper_folder/install.sh &> /dev/null
		chmod 777 $application_path$sniper_folder/sniper.sh &> /dev/null
		./$application_path$sniper_folder/install.sh 
		y
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"		
		;;
	"fatrat")
		#Download and install fatrat
		install_message $1
		install_git $fatrat_git $fatrat_folder
		chmod +x $application_path$fatrat_folder/setup.sh
		./$application_path/$fatrat_folder/setup.sh
		;;
	"./$application_path$metagoofil_folder/metagoofil.py")
		install_message metagoofil
		install_git $metagoofil_git $metagoofil_folder
		chmod +x $application_path$metagoofil_folder/metagoofil.py &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		#Install apps
		;;
	"./$application_path$wig_folder/wig.py")
		install_message wig
		install_git $wig_git $wig_folder
		#Install apps
		cd $application_path$wig_folder
		chmod 777 setup.py wig.py &> /dev/null
		python setup.py install &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"./Application/arachni/bin/arachni_web")
		install_message arachni
		echo & echo
		wget $arachni_git -P $application_path 
		tar -xvzf $application_path/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -C $application_path 
		mv $application_path/arachni-1.5.1-0.5.12 $application_path/arachni &> /dev/null
		rm $application_path/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	"openvas-start")
		install_message openvas &> /dev/null
		apt-get install openvas &> /dev/null
		y  &> /dev/null
		openvas-setup &> /dev/null
		echo -e "$OKGREEN	[✔-OK!]::[Apps]: $1 $RESET"
		;;
	*)
		echo ""
		echo -e "$OKGREEN Enjoy! $RESET"
		echo ""
		;;
	esac	
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


# arg1 = host	arg2 = output
function xml2html () {
	xsltproc $report_path$1/$2.xml -o $report_path$1/$2.html 2> /dev/null
	rm $report_path$1/$2.xml 2> /dev/null
	x-www-browser $report_path$1/$2.html 2> /dev/null &
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
	echo -e "What is your host? \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Intense_Scan_Report"
	nmap -p- -A -sV --version-intensity 5 --script=whois-ip,banner $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}

function nmap_udp_module {
	echo -e "What is your host? \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_UDP_Scan_Report"
	nmap -sU $hosts --script=banner -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}

function nmap_aio_enum_module {
	echo -e "What is your host? \c"
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
	echo -e "What is your host? \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_Http_CVE_Scan_Report"
	nmap --script=http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-5638 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}

	
function nmap_aio_ssl_module {
	echo -e "What is your host? \c"
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
	echo -e "What is your host? \c"
	read hosts
	mkdir -p $report_path$hosts 2> /dev/null
	output="Nmap_SMB_Scan_Report"
	nmap -p 445 --script=smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-regsvc-dos,smb-vuln-conficker,smb-vuln-ms06-025,smb-vuln-cve2009-3103 $hosts -oX $report_path$hosts/$output.xml 2> /dev/null
	xml2html $hosts $output
	nmap_interface
	}
	
	
function metagofil_module {
	echo -e "What is your host? \c"
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
	echo -e "What is your host? \c"
	read hosts
	sniper $hosts
	recon
	}
	
	
function brute_dir_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host?  \c"
	read hosts
	wordlist
	echo -e "Use wordlist path:  \c"
	read use_word_list
	output="Web_Directory_Bruteforce_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	#wfuzz -c -z file,/usr/share/wordlists/fasttrack.txt --hc 404,301 -o html http://example.com/FUZZ > output.html
	echo -e $OKRED
	echo -e "Bruteforcing....Please wait...... "$RESET
	wfuzz -c -z file,$use_word_list --hc 404,301,302 -o html $protocols://$hosts/FUZZ &>> $report_path$hosts/$output.html
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	recon
	}
	

function nikto_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host?  \c"
	read hosts
	output="Nikto_Report"
	nikto -h $protocols://$hosts -F htm -output $output.html
	mv $output.html $report_path$hosts/$output.html
	x-www-browser $report_path$hosts/$output.html 2> /dev/null &
	recon
	}
	
function wig_module {
	echo -e "Http or Https? \c"
	read protocols
	echo -e "What is your host?  \c"
	read hosts
	output="CMS_Identifier_Report"
	mkdir -p $report_path$hosts 2> /dev/null
	#./Application/wig/wig.py http://localhost:9292  &>> Report/localhost/CMS_Identifier_Report.txt
	echo  -e $OKRED & echo -e "Scanning...This process might take same time, please wait..$RESET" & echo
	./Application/wig/wig.py $protocols://$hosts  &>> $report_path$hosts/$output.txt
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
	xterm -hold -e 'maltegoce' &
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
			curl -i -X OPTIONS $line >>$report_path$hosts/$output.txt
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
		

function cewl_module {
	echo -e "What is your host?  \c"
	read hosts
	output="Possible_Password"
	mkdir -p $report_path$hosts 2> /dev/null
	echo "" > $report_path$hosts/$output.txt
	cewl -w $report_path$hosts/$output.txt -d 5 -m 7 $hosts
	echo
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
	xterm -hold -e 'echo -e "User Account	:--- user: admin	pass: admin" & 
	openvas-start &
	openvasmd --user=admin --new-password=admin'&
	sleep 25
	x-www-browser https://127.0.0.1:9392 &
	va_scanning
	}
	


#    ______            _       _ _     __  __           _       _      
#   |  ____|          | |     (_) |   |  \/  |         | |     | |     
#   | |__  __  ___ __ | | ___  _| |_  | \  / | ___   __| |_   _| | ___ 
#   |  __| \ \/ / '_ \| |/ _ \| | __| | |\/| |/ _ \ / _` | | | | |/ _ \
#   | |____ >  <| |_) | | (_) | | |_  | |  | | (_) | (_| | |_| | |  __/
#   |______/_/\_\ .__/|_|\___/|_|\__| |_|  |_|\___/ \__,_|\__,_|_|\___|
#               | |                                                    
#               |_|                                                    


		
#    _____       _             __               
#   |_   _|     | |           / _|              
#     | |  _ __ | |_ ___ _ __| |_ __ _  ___ ___ 
#     | | | '_ \| __/ _ \ '__|  _/ _` |/ __/ _ \
#    _| |_| | | | ||  __/ |  | || (_| | (_|  __/
#   |_____|_| |_|\__\___|_|  |_| \__,_|\___\___|
#                                               
#                                               

function main_logo {
clear && echo -en "\e[3J"
echo ""
echo -e "$OKRED███████╗ ██╗███╗   ███╗██████╗ ██╗     ██████╗   $RESET"
echo -e "$OKRED██╔════╝███║████╗ ████║██╔══██╗██║     ╚════██╗  $RESET"
echo -e "$OKRED███████╗╚██║██╔████╔██║██████╔╝██║      █████╔╝  $RESET"
echo -e "$OKRED╚════██║ ██║██║╚██╔╝██║██╔═══╝ ██║      ╚═══██╗  $RESET"
echo -e "$OKRED███████║ ██║██║ ╚═╝ ██║██║     ███████╗██████╔╝  $RESET"
echo -e "$OKRED╚══════╝ ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═════╝	$RESET"

}


function init {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-] 

Select from the menu:
	
	1 : Reconnaisance
	2 : Vulnerability Scanning
	3 : Exploit
	4 : Post Exploit
	9 : Update Module
	
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
		echo "Lets Exploit!"
		;;
	"4")
		echo "Post Exploit!"
		;;
	"9")
		echo "Lets Update!"
		;;
	*)
		echo "Arigatou! Sayonara~"
		exit
		;;
	esac
}

function recon {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-] 

Select from the 'Reconnaisance' menu:
	
	1  : Nmap - $OKORANGE Port Scanner $RESET $OKGREEN
	2  : Sn1per - $OKORANGE All-in-one Enumerator $RESET $OKGREEN
	3  : Nikto - $OKORANGE Server Configuration Scanner $RESET $OKGREEN
	4  : Wig - $OKORANGE CMS Identifier $RESET $OKGREEN
	5  : Web Crawler - $OKORANGE Website Crawler $RESET $OKGREEN
	6  : WFuzz - $OKORANGE Hidden Web Directory Bruteforcer $RESET $OKGREEN
	7  : Metagoofil - $OKORANGE Information gathering tool $RESET $OKGREEN
	8  : HTTP Method Analyzer - $OKORANGE Http Method Analyzer $RESET $OKGREEN
	9  : Maltego - $OKORANGE Reconnaissance framework $RESET $OKGREEN
	10 : Recon-Ng - $OKORANGE Web Reconnaissance framework $RESET $OKGREEN
	11 : Cewl - $OKORANGE Possible Password List Generator $RESET $OKGREEN
	
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
		echo "Crawler"
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
	"11")
		cewl_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
}

function nmap_interface {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-] 

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


function va_scanning {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-] 

Select from the 'Vulnerability Scanning' menu:
	
	1 : Arachni
	2 : Openvas
	3 : 
	4 : 
	5 : 
	6 : 
	7 : 
	
	99 : Return		
	$RESET"
	
	echo -e "Holla! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		arachni_module
		;;
	"2")
		open_vas_module
		;;
	*)
		#echo "Huhhh! Wrong input!"
		init
		;;
	esac
}



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
