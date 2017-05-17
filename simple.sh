#!/bin/bash
 
#echo -e "Hi, please type the word: \c "
#read  word
#echo "The word you entered is: $word"

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

declare -r nmap_git='https://github.com/nmap/nmap.git'
declare -r nmap_folder='nmap'

declare -r nikto_git='https://github.com/sullo/nikto.git'
declare -r nikto_folder='nikto'

declare -r sniper_git='https://github.com/1N3/Sn1per'
declare -r sniper_folder='Sn1per'

declare -r fatrat_git='https://github.com/Screetsec/TheFatRat.git'
declare -r fatrat_folder='TheFatRat'

declare -a required_apps=("nmap" "nikto" "sniper" "fatrat")

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


function install_apps {
	case "$1" in
	"nmap")
		#Download and install nmap
		install_git $nmap_git $nmap_folder
		;;
	"nikto")
		#Download and install nikto	
		install_git $nikto_git $nikto_folder
		;;
	"sniper")
		#Download and install sn1per
		install_git $sniper_git $sniper_folder
		;;
	"fatrat")
		#Download and install fatrat
		install_git $fatrat_git $fatrat_folder
		;;
	*)
		echo "Do Nothing"
		;;
	esac	
}

function initialization {
	for i in "${required_apps[@]}"
	do
		if apps_exist $i ; then
			echo "$i exist"
		
		else
			echo "$i is not exist!"
			install_apps $i
		fi
	done
}


function create_dir (){
mkdir -p $report_path$1
}


# arg1 = host	arg2 = output
function xml2html () {
xsltproc $report_path$1/$2.xml -o $report_path$1/$2.html
rm $report_path$1/$2.xml
open -a "$(/usr/local/bin/DefaultApplication -url 'http:')" "$report_path$1/$2.html"
}



#    __  __           _       _      
#   |  \/  |         | |     | |     
#   | \  / | ___   __| |_   _| | ___ 
#   | |\/| |/ _ \ / _` | | | | |/ _ \
#   | |  | | (_) | (_| | |_| | |  __/
#   |_|  |_|\___/ \__,_|\__,_|_|\___|
#                                    
#                                    

function nmap {

echo -e "What is your host? \c"
read hosts
mkdir -p $report_path$hosts 2> /dev/null
output="Nmap_Default_Scan_Report"
nmap -p- -A -sV --version-intensity 5 --script=whois-ip $hosts -oX $report_path$output.xml 2> /dev/null
#xml2html $hosts $output
recon
}


#    _____       _             __               
#   |_   _|     | |           / _|              
#     | |  _ __ | |_ ___ _ __| |_ __ _  ___ ___ 
#     | | | '_ \| __/ _ \ '__|  _/ _` |/ __/ _ \
#    _| |_| | | | ||  __/ |  | || (_| | (_|  __/
#   |_____|_| |_|\__\___|_|  |_| \__,_|\___\___|
#                                               
#                                               

function main_logo {
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
	2 : Scanning
	3 : Exploit
	4 : Post Exploit
	9 : Update Module
	99: Exit
	$RESET"
	
	echo -e "Adios! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		clear
		recon
		;;
	"2")
		echo "Lets Scann!"
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
		echo "Uhh...Error?!"
		;;
	esac
}

function recon {
	main_logo
	echo -e "$OKGREEN
[+]       Coded BY Muzaffar Mohamed       [+] 
[-]           coco.oligococo.tk           [-] 

Select from the 'Reconnaisance' menu:
	
	1 : nmap (default)
	2 : nmap (stealth)
	3 : SSL Analyzer
	4 : Enumerate HTTP
	5 : Common CVE
	6 : Metagofill
	7 : Sn1per	
	$RESET"
	
	echo -e "Hey! Your choice is? \c"
	read  choice
	
	case "$choice" in
	"1")
		nmap
		;;
	"2")
		echo "Lets Scann!"
		;;
	"3")
		echo "Lets Exploit!"
		;;
	"4")
		echo "Post Exploit!"
		;;
	"5")
		echo "Lets Update!"
		;;
	"6")
		echo "Lets Update!"
		;;
	"7")
		echo "Lets Update!"
		;;
	*)
		echo "Uhh...Error?!"
		;;
	esac
}

#    __  __       _       
#   |  \/  |     (_)      
#   | \  / | __ _ _ _ __  
#   | |\/| |/ _` | | '_ \ 
#   | |  | | (_| | | | | |
#   |_|  |_|\__,_|_|_| |_|
#                         
#                         

init
