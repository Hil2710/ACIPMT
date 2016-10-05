import subprocess
import sys
import ipaddress
import re
import acipdt
import requests
import json


def quit(userinput):
    if userinput.lower() == 'quit':
        sys.exit()


def apic_info():
    while True:
        while True:
            apic = input("Please input the APIC IP address: ")
            quit(apic)
            try:
                ipaddress.ip_address(apic)
                break
            except:
                print("Please enter a valid IP address in x.x.x.x format,"
                      " or type 'quit'.")
        user = input("Please enter the APIC userid [admin]: ")
        user = user or 'admin'
        quit(user)
        pword = input("Please enter the APIC password [password]: ")
        pword = pword or 'password'
        quit(pword)
        print(user, pword, apic)
        try:
            aci_login = acipdt.FabLogin(apic, user, pword)
            cookies = aci_login.login()
            break
        except:
            print("Something went wrong logging into ACI. Check your "
                  "username and password.")
    return(apic, user, pword, cookies)


def gre_tunnel():
    while True:
        gre = input("Do you already have a GRE tunnel setup on this "
                    "machine to receive SPAN data? ('y' or 'n') [y]: ")
        gre = gre or 'y'
        quit(gre)
        if gre.lower() == 'y' or gre.lower() == 'n':
            break
        else:
            print("Please enter 'y' or 'n' only.")

    print("Verifying ip_gre module is loaded.")
    # Validate ip_gre module loaded before continuing
    try:
        p = subprocess.check_output(['lsmod | grep ip_gre'], shell=True)
    # If ip_gre not loaded, attempt ot remediate
    except:
        print("ip_gre module not loaded, attempting to remediate...")
        # Attempt to load ip_gre module
        try:
            p = subprocess.call('modprobe ip_gre', shell=True)
            if p == 0:
                pass
            elif p == 1:
                sys.exit()
        # If loading ip_gre fails, exit
        except:
            print("Failed attempting to load ip_gre, exiting.")
            sys.exit()

    # If user already has a tunnel
    if gre == 'y':

        # Prompt user for tunnel name
        while True:
            tun_name = input("Enter the GRE tunnel interface name "
                             "(i.e. mon0, gre0) [mon0]: ")
            tun_name = tun_name or 'mon0'
            quit(tun_name)
            # Check to see if tunnel exists
            try:
                p = subprocess.check_output(['ifconfig', tun_name])
                break
            # If tunnel doesn't exist, re-prompt user
            except:
                print("Please enter a valid interface.")

        # Get source IP address of the tunnel
        while True:
            # Try to get source IP of tunnel
            try:
                p = subprocess.check_output(['ip addr show %s | grep link/gre'
                                            % tun_name], shell=True)
                # decode p from bytes to string
                p = p.decode('utf-8')
                # find all IPs in string, remove all 0.0.0.0 entries
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                ip.remove('0.0.0.0')
                src_ip = ip[0]
                break
            # If source IP cannot be sourced, prompt user for IP
            except:
                print("Failed to get %s source IP address." % tun_name)
                src_ip = input("Manually enter tunnel source IP "
                               "(i.e. 1.1.1.1), or type 'quit' to exit: ")
                quit(src_ip)
                # Validate user provided IP is legal
                try:
                    ipaddress.ip_address(src_ip)
                    break
                # Re-prompt user if IP is not legal
                except:
                    print("Please enter a valid IP address in x.x.x.x "
                          "format, or type 'quit'.")

        # Validate tunnel is "up", remediate if necessary
        while True:
            # Check ifconfig output for "UP"
            try:
                p = subprocess.check_output(['ifconfig %s | grep UP'
                                            % tun_name], shell=True)
                break
            # If tunnel is not "UP"
            except:
                try:
                    print("Tunnel does not seem to be up, attempting "
                          "to bring up.")
                    tun_bringup = ('ip link set %s up' % tun_name)
                    p = subprocess.Popen(tun_bringup, shell=True)
                # If tunnel cannot be brought up, exit
                except:
                    print("Failed to bring up tunnel, exiting.")
                    sys.exit()

        # Get IP address of tunnel itself
        while True:
            # Check for tunnel IP Address
            try:
                p = subprocess.check_output(['ifconfig %s | grep inet'
                                             % tun_name], shell=True)
                # decode p from bytes to string
                p = p.decode('utf-8')
                # find all IPs in string, remove all 0.0.0.0 entries
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                tun_ip = ip[0]
                break
            # If tunnel IP cannot be fou,d prompt user
            except:
                print("Failed to get %s IP address." % tun_name)
                tun_ip = input("\nManually enter interface %s IP address, or "
                               "type 'quit' to exit: " % tun_ip)
                quit(tun_ip)
                # Check to see if user supplied IP is legal
                try:
                    ipaddress.ip_address(tun_ip)
                    break
                # If IP not legal, re-prompt user
                except:
                    print("Please enter a valid IP address in "
                          "x.x.x.x format, or type 'quit'.")

    # If user does NOT have a tunnel
    if gre == 'n':
        # Load available interfaces for tunnel source
        p = subprocess.check_output(['ls /sys/class/net'], shell=True)
        p = p.decode('utf-8')
        p = p.split()
        # Remove some known interfaces that we dont want to see
        p.remove('lo')
        p.remove('gre0')
        p.remove('gretap0')
        # Ask user what source interface to use
        while True:
            print("Available Interfaces:")
            print(*p, sep='\n')
            src_int = input("Enter the interface to use as the GRE tunnel "
                            "source interface [eth0]: ")
            src_int = src_int or 'eth0'
            quit(src_int)
            # Check output to validate interface
            try:
                p = subprocess.check_output(['ifconfig', src_int])
                break
            # Re-prompt user if interface is not valid
            except:
                print("Please enter a valid interface.")

        # Get IP address of the tunnel source
        while True:
            # Check output to glean IP address
            try:
                p = subprocess.check_output(['ip addr show %s | grep inet'
                                            % src_int], shell=True)
                # decode p from bytes to string
                p = p.decode('utf-8')
                # find all IPs in string, remove all 0.0.0.0 entries
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                src_ip = ip[0]
                break
            # Prompt user to manually enter IP if fail to retreive IP
            except:
                print("Failed to get %s IP address." % gre_src)
                src_ip = input("\nManually enter interface %s IP address, "
                               "or type 'quit' to exit: " % gre_src)
                quit(src_ip)
                # Validate IP address provided is legal
                try:
                    ipaddress.ip_address(src_ip)
                    break
                # If IP not legal, re-prompt user
                except:
                    print("Please enter a valid IP address in x.x.x.x "
                          "format, or type 'quit'.")

        print("Validating that mon0 is not taken.")
        # Verify mon0 is not taken then load that as tunnel name
        p = subprocess.check_output(['ls /sys/class/net'], shell=True)
        p = p.decode('utf-8')
        p = p.split()
        # If mon0 is taken, exit
        # In the future add code to change tunnel number
        if 'mon0' in p:
            print("Interface mon0 already exists, exiting.")
            sys.exit()
        else:
            tun_name = 'mon0'

        print("Building tunnel interface.")
        # Build new tunnel interface
        try:
            p = subprocess.Popen(['ip tunnel add %s mode gre local %s'
                                 % (tun_name, src_ip)], shell=True)
        # If building tunnel interface fails, exit
        except:
            print("Failed to create tunnel interface. Exiting")
            sys.exit()

        print("Assigning IP address to tunnel.")
        # Assign IP address to Tunnel
        tun_ip = '1.1.1.1'
        # Assign IP to tunnel
        try:
            p = subprocess.Popen(['sudo ip addr add %s/30 dev %s'
                                 % (tun_ip, tun_name)], shell=True)
        # If tunnel IP assignment fails, exit
        except:
            print("Failed to add IP address to tunnel. Exiting")
            sys.exit()

        print("Bringing up tunnel interface.")
        # Bring up tunnel
        try:
            tun_bringup = ('ip link set %s up' % tun_name)
            p = subprocess.Popen(tun_bringup, shell=True)
        # If tunnel bringup fails, exit
        except:
            print("Failed to bring up tunnel, exiting")
            sys.exit()

    return(src_ip, tun_name, tun_ip)


def aci_span(apic, cookies, src_ip, tun_ip):
    # Convert src_ip and tun_ip (which was created in the gre func)
    # to dest_ip, tun_src_ip (as we are now working on opposite end
    # of the tunnel)
    dst_ip = src_ip
    tun_src_ip = ipaddress.IPv4Address(tun_ip)
    tun_src_ip = tun_src_ip + 256

    while True:
        cfg_aci = input("Do you already have an ACI SPAN session setup to "
                        "point to this server? ('y' or 'n') [y]: ")
        cfg_aci = cfg_aci or 'y'
        quit(cfg_aci)
        if cfg_aci.lower() == 'y' or cfg_aci.lower() == 'n':
            break
        else:
            print("Please enter 'y' or 'n' only.")

    # If user does not have ACI SPAN, prompt and configure
    if cfg_aci == 'n':
        # Prompt user for SPAN Source Information
        while True:
            aci_srctn = input("Which ACI Tenant in ACI is your SPAN "
                              "destination group?: ")
            aci_srcap = input("In Tenant %s, which Application Profile will "
                              "the SPAN be sourced from?: " % aci_srctn)
            aci_srcepg = input("In Tenant %s Application Profile %s, which "
                               "EPG will the SPAN be sourced from?: " %
                               (aci_srctn, aci_srcap))

            # Validate the input supplied by the user
            print("Validating ACI Tenant, Application Profile, and "
                  "EPG exists.")
            s = requests.Session()
            try:
                r = s.get('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                          % (apic, aci_srctn, aci_srcap, aci_srcepg),
                          cookies=cookies, verify=False)
                status = r.status_code
            except:
                print("Failed to query APIC, exiting.")
                sys.exit()
            payload = json.loads(r.text)
            payload_len = len(payload['imdata'])
            if payload_len == 1:
                break
            else:
                print("Seems you entered an invalid Tenant, AP, or EPG. "
                      "Try again or type 'quit'.")

        # Prompt user for SPAN Destination Information
        while True:
            aci_dsttn = input("Which ACI Tenant in ACI is your SPAN "
                              "destination group?: ")
            aci_dstap = input("In Tenant %s, which Application Profile "
                              "will the SPAN be destined for?: " % aci_dsttn)
            aci_dstepg = input("In Tenant %s Application Profile %s, which "
                               "EPG will the SPAN be destined for?: "
                               % (aci_dsttn, aci_dstap))

            # Validate the input supplied by the user
            print("Validating ACI Tenant, Application Profile, and "
                  "EPG exists.")
            s = requests.Session()
            try:
                r = s.get('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                          % (apic, aci_dsttn, aci_dstap, aci_dstepg),
                          cookies=cookies, verify=False)
                status = r.status_code
            except:
                print("Failed to query APIC, exiting.")
                sys.exit()
            payload = json.loads(r.text)
            payload_len = len(payload['imdata'])
            if payload_len == 1:
                break
            else:
                print("Seems you entered an invalid Tenant, AP, or EPG. "
                      "Try again or type 'quit'.")

        # Initialize the Tshoot Class, then build the SPAN session
        print("Creating SPAN Source.")
        aci_span = acipdt.TshootPol(apic, cookies)
        try:
            aci_span.span_src(aci_srctn, 'ACI-PMT-Src', 'enabled', 'both',
                              aci_srcap, aci_srcepg, 'ACI-PMT-Dst',
                              'created,modified')
        except:
            print("Failed to create ACI SPAN Source. Exiting.")
            sys.exit()

        print("Creating SPAN Destination.")
        try:
            aci_span.span_dst(aci_srctn, 'ACI-PMT-Dst', aci_dsttn,
                              aci_dstap, aci_dstepg, dst_ip, tun_src_ip,
                              'created,modified')
        except:
            print("Failed to create ACI SPAN Destination. Exiting.")
            sys.exit()


def tshark_setup():
    print("In seconds (s), minutes (m), hours (h), or days (d), how "
          "long would you like the SPAN to run?")
    while True:
        tshark_duration = input("Enter your selection "
                                "(i.e. 1s, 5m, 10h or 1d): ")
        quit(tshark_duration)
        if (tshark_duration[-1] == 's' or
            tshark_duration[-1] == 'm' or
            tshark_duration[-1] == 'h' or
            tshark_duration[-1] == 'd'):
                try:
                    duration = tshark_duration[:-1]
                    duration = int(duration)
                    break
                except:
                        print("Please enter a valid integer "
                              "before time suffix.")
        else:
            print("Please enter a valid time suffix (i.e. 'm', 'h', or 'd'.")

    if tshark_duration[-1] == 's':
        tshark_duration = duration
    elif tshark_duration[-1] == 'm':
        tshark_duration = duration * 60
    elif tshark_duration[-1] == 'h':
        tshark_duration = duration * 60 * 60
    elif tshark_duration[-1] == 'd':
        tshark_duration = duration * 60 * 60 * 12

    tshark_duration = int(tshark_duration)
    return(tshark_duration)


def top_menu():
    # want people to be able to start this w/ command line args, but
    # if they havent passed any, run this
    print("Welcome to the ACI Probable Mapping Tool!")
    print("From any prompt type 'quit' to exit program.")

    # get apic info from user and validate login
    (apic, user, pword, cookies) = apic_info()

    # process gre tunnel bring up
    (src_ip, tun_name, tun_ip) = gre_tunnel()

    # process aci span bring up
    aci_span(apic, cookies, src_ip, tun_ip)

    # process tshark duration information
    tshark_duration = tshark_setup()

    # return tshark_duration and the tunnel interface name
    return(tun_name, tshark_duration)
