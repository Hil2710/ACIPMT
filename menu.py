import subprocess
import sys
import ipaddress
import re
import acipdt
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import getpass
import configparser
import os


# Function to parse setup.ini
def process_setup(logger):
    logger.debug('Processing setup file.')
    if os.path.isfile('setup.ini'):
        logger.debug('Setup file exists.')
        setup_config = configparser.ConfigParser()
        setup_config.read('setup.ini')
    else:
        return False
    gre_config = setup_config['GRE']['Prompt']
    if (gre_config.lower() == 'yes' or gre_config.lower() == 'no'):
        pass
    else:
        gre_config = 'yes'
    apic_config = setup_config['APIC']['Prompt']
    if (apic_config.lower() == 'yes' or apic_config.lower() == 'no'):
        pass
    else:
        apic_config = 'yes'
    span_config = setup_config['SPAN']['Prompt']
    if (span_config.lower() == 'yes' or span_config.lower() == 'no'):
        pass
    else:
        span_config = 'yes'
    tshark_config = setup_config['TSHARK']['Prompt']
    if (tshark_config.lower() == 'yes' or tshark_config.lower() == 'no'):
        pass
    else:
        tshark_config = 'yes'
    return(gre_config, apic_config, span_config, tshark_config)


# Function to return setup values for specified section
def parse_setup(section):
    setup_config = configparser.ConfigParser()
    setup_config.read('setup.ini')
    setup_dict = {}
    for i in setup_config[section]:
        setup_dict[i] = setup_config[section][i]
    return setup_dict


# Function to exit program if user enters 'quit'
def quit(userinput, logger):
    if userinput.lower() == 'quit':
        logger.critical('Exiting program - user entered "quit" in a prompt.')
        sys.exit()


# Function to gather info about GRE setup (and build if required)
def gre_tunnel(logger, gre_config):
    logger.debug('Entered "gre_tunnel" function.')

    logger.debug('Verifying ip_gre module is loaded.')
    # Validate ip_gre module loaded before continuing
    try:
        p = subprocess.check_output(['lsmod | grep ip_gre'], shell=True)
        logger.info('ip_gre module is loaded.')
    # If ip_gre not loaded, attempt ot remediate
    except:
        logger.error('ip_gre module not loaded, attempting to remediate...')
        # Attempt to load ip_gre module
        try:
            p = subprocess.call('modprobe ip_gre', shell=True)
            if p == 0:
                logger.info('ip_gre module is loaded.')
                pass
            elif p == 1:
                logger.critical('FAILED attempting to load ip_gre, exiting.')
                sys.exit()
        # If loading ip_gre fails, exit
        except:
            logger.critical('FAILED attempting to load ip_gre, exiting.')
            sys.exit()

    section = 'GRE'
    setup_dict = parse_setup(section)
    if setup_dict['prompt'].lower() == 'no':
        try:
            tun_name = setup_dict['tunnel_name']
            src_ip = setup_dict['source_ip']
            tun_ip = setup_dict['tunnel_ip']
            # validate stuff
            # validate tun interface
            p = subprocess.check_output(['ifconfig', tun_name])
            logger.debug('GRE tunnel %s exists.' % tun_name)
            # validate tun is up
            tun_bringup = ('ip link set %s up' % tun_name)
            p = subprocess.Popen(tun_bringup, shell=True)
            logger.debug('GRE tunnel %s is up.' % tun_name)
            # validate tun source ip
            p = subprocess.check_output(['ip addr show %s | grep link/gre'
                                        % tun_name], shell=True)
            # decode p from bytes to string
            p = p.decode('utf-8')
            # find all IPs in string, remove all 0.0.0.0 entries
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
            ip.remove('0.0.0.0')
            if src_ip == ip[0]:
                pass
            else:
                raise
            # validate tun ip
            p = subprocess.check_output(['ifconfig %s | grep inet'
                                        % tun_name], shell=True)
            # decode p from bytes to string
            p = p.decode('utf-8')
            # find all IPs in string, remove all 0.0.0.0 entries
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
            if tun_ip == ip[0]:
                pass
            else:
                raise
            return(src_ip, tun_name, tun_ip)
        except:
            # fail out to while loops
            gre = 'n'
            logger.error('FAILED to validate setup GRE configs.')
    else:
        while True:
            gre = input("Do you already have a GRE tunnel setup on this "
                        "machine to receive SPAN data? ('y' or 'n') [y]: ")
            gre = gre or 'y'
            logger.debug('User entered "%s" for '
                         '"Do you already have a GRE tunnel."' % gre)
            quit(gre, logger)
            if gre.lower() == 'y' or gre.lower() == 'n':
                break
            else:
                logger.error('Invalid input of "%s" entered for "Do you '
                             'already have a GRE tunnel". Enter a valid '
                             'input or "quit".'
                             % (gre))

    # If user already has a tunnel
    if gre == 'y':
        logger.debug('User has indicated gre tunnel already exists.')
        # Prompt user for tunnel name
        while True:
            tun_name = input("Enter the GRE tunnel interface name "
                             "(i.e. mon0, gre0) [mon0]: ")
            tun_name = tun_name or 'mon0'
            logger.debug('User entered "%s" for gre interface name.'
                         % tun_name)
            quit(tun_name, logger)
            # Check to see if tunnel exists
            try:
                p = subprocess.check_output(['ifconfig', tun_name])
                logger.debug('GRE tunnel %s exists.' % tun_name)
                break
            # If tunnel doesn't exist, re-prompt user
            except:
                logger.error('Invalid input of "%s" entered for "Enter the GRE'
                             ' tunnel interface name. Enter valid tunnel name,'
                             ' or type "quit".' % (tun_name))

        # Get source IP address of the tunnel
        while True:
            logger.debug('Attempting to ascertain GRE source IP address.')
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
                logger.debug('Ascertained GRE source IP of "%s".' % src_ip)
                break
            # If source IP cannot be sourced, prompt user for IP
            except:
                logger.error('Failed to get "%s" source IP address'
                             % (tun_name))
                src_ip = input("Manually enter tunnel source IP "
                               "(i.e. 1.1.1.1), or type 'quit' to exit: ")
                logger.debug('User entered "%s" for gre source IP address.'
                             % src_ip)
                quit(src_ip, logger)
                # Validate user provided IP is legal
                try:
                    ipaddress.ip_address(src_ip)
                    logger.debug('User entered a valid IP address of "%s" for '
                                 'GRE tunnel source IP.' % src_ip)
                    break
                # Re-prompt user if IP is not legal
                except:
                    logger.error('Invalid input of "%s" entered for '
                                 '"GRE source IP Address". Enter a valid IP '
                                 'address in x.x.x.x format, or type "quit".'
                                 % (src_ip))

        # Validate tunnel is "up", remediate if necessary
        while True:
            logger.debug('Attempting to ascertain if GRE tunnel is UP.')
            # Check ifconfig output for "UP"
            try:
                p = subprocess.check_output(['ifconfig %s | grep UP'
                                            % tun_name], shell=True)
                logger.debug('GRE tunnel appears to be up.')
                break
            # If tunnel is not "UP"
            except:
                logger.info('Tunnel does not seem to be up, attempting '
                            'to bring up.')
                try:
                    tun_bringup = ('ip link set %s up' % tun_name)
                    p = subprocess.Popen(tun_bringup, shell=True)
                    logger.debug('Tunnel successfully brought up.')
                # If tunnel cannot be brought up, exit
                except:
                    logger.critical('FAILED to bring up tunnel "%s", exiting.'
                                    % tun_name)
                    sys.exit()

        # Get IP address of tunnel itself
        while True:
            logger.debug('Attemptig to ascertain IP of GRE tunnel itself.')
            # Check for tunnel IP Address
            try:
                p = subprocess.check_output(['ifconfig %s | grep inet'
                                             % tun_name], shell=True)
                # decode p from bytes to string
                p = p.decode('utf-8')
                # find all IPs in string, remove all 0.0.0.0 entries
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                tun_ip = ip[0]
                logger.debug('Ascertained GRE tunnel IP of "%s".' % tun_ip)
                break
            # If tunnel IP cannot be fou,d prompt user
            except:
                logger.error('Failed to get "%s" source IP address'
                             % (tun_name))
                tun_ip = input("\nManually enter interface %s IP address, or "
                               "type 'quit' to exit: " % tun_ip)
                logger.debug('User entered "%s" for gre tunnel IP address.'
                             % src_ip)
                quit(tun_ip, logger)
                # Check to see if user supplied IP is legal
                try:
                    ipaddress.ip_address(tun_ip)
                    logger.debug('User entered a valid IP address of "%s" for '
                                 'GRE tunnel IP.' % src_ip)
                    break
                # If IP not legal, re-prompt user
                except:
                    logger.error('Invalid input of "%s" entered for '
                                 '"GRE IP Address". Enter a valid IP '
                                 'address in x.x.x.x format, or type "quit".'
                                 % (src_ip))

    # If user does NOT have a tunnel
    if gre == 'n':
        logger.debug('User has indicated no gre tunnel exists.')
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
            logger.debug('Prompting user to select GRE source interface.')
            logger.info('Available Interfaces:')
            for i in p:
                logger.info(i)
            src_int = input("Enter the interface to use as the GRE tunnel "
                            "source interface [eth0]: ")
            src_int = src_int or 'eth0'
            logger.debug('User entered "%s" for gre source interface.'
                         % src_int)
            quit(src_int, logger)
            # Check output to validate interface
            try:
                p = subprocess.check_output(['ifconfig', src_int])
                logger.debug('User entered a valid interface of "%s" '
                             'for GRE source interface' % src_int)
                break
            # Re-prompt user if interface is not valid
            except:
                logger.error('Invalid input of "%s" entered for '
                             '"GRE source interface". Enter a valid '
                             'inteface, or type "quit".'
                             % (src_int))

        # Get IP address of the tunnel source
        while True:
            logger.debug('Attempting to ascertain GRE source IP address.')
            # Check output to glean IP address
            try:
                p = subprocess.check_output(['ip addr show %s | grep inet'
                                            % src_int], shell=True)
                # decode p from bytes to string
                p = p.decode('utf-8')
                # find all IPs in string, remove all 0.0.0.0 entries
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                src_ip = ip[0]
                logger.debug('Ascertained GRE tunnel source IP of "%s".'
                             % src_ip)
                break
            # Prompt user to manually enter IP if fail to retreive IP
            except:
                logger.error('Failed to get "%s" IP address'
                             % (src_int))
                src_ip = input("\nManually enter interface %s IP address, "
                               "or type 'quit' to exit: " % src_int)
                quit(src_ip, logger)
                logger.debug('User entered "%s" for gre source IP address.'
                             % src_ip)
                # Validate IP address provided is legal
                try:
                    ipaddress.ip_address(src_ip)
                    logger.debug('User entered a valid IP address of "%s" for '
                                 'GRE source IP.' % src_ip)
                    break
                # If IP not legal, re-prompt user
                except:
                    logger.error('Invalid input of "%s" entered for '
                                 '"GRE source IP". Enter a valid '
                                 'inteface, or type "quit".'
                                 % (src_ip))

        logger.info('Validating that mon0 is not taken.')
        # Verify mon0 is not taken then load that as tunnel name
        p = subprocess.check_output(['ls /sys/class/net'], shell=True)
        p = p.decode('utf-8')
        p = p.split()
        # If mon0 is taken, exit
        # In the future add code to change tunnel number
        if 'mon0' in p:
            logger.critical('Interface "mon0" is already taken, exiting.')
            sys.exit()
        else:
            logger.debug('Interface "mon0" is available.')
            tun_name = 'mon0'

        logger.info('Building tunnel interface.')
        # Build new tunnel interface
        try:
            p = subprocess.Popen(['ip tunnel add %s mode gre local %s'
                                 % (tun_name, src_ip)], shell=True)
            logger.debug('Interface "mon0" successfully created.')
        # If building tunnel interface fails, exit
        except:
            logger.critical('FAILED to create tunnel interface, exiting.')
            sys.exit()

        logger.info('Assigning IP address to tunnel.')
        # Assign IP address to Tunnel
        tun_ip = '1.1.1.1'
        # Assign IP to tunnel
        try:
            p = subprocess.Popen(['sudo ip addr add %s/30 dev %s'
                                 % (tun_ip, tun_name)], shell=True)
            logger.debug('IP successfully assinged to interface "mon0".')
        # If tunnel IP assignment fails, exit
        except:
            logger.critical('FAILED to add IP to interface "mon0".')
            sys.exit()

        logger.info('Bringing up tunnel "mon0".')
        # Bring up tunnel
        try:
            tun_bringup = ('ip link set %s up' % tun_name)
            p = subprocess.Popen(tun_bringup, shell=True)
            logger.debug('Tunnel "mon0" successfully brought up.')
        # If tunnel bringup fails, exit
        except:
            logger.critical('FAILED bring up "mon0", exiting.')
            sys.exit()

    # return src_ip, tun_name and tun_ip to top_menu
    logger.debug('GRE Tunnel functionality complete, returning tunnel name of'
                 '"%s", tunnel IP of "%s", and tunnel source IP of "%s" to '
                 'top_menu.' % (tun_name, tun_ip, src_ip))
    return(src_ip, tun_name, tun_ip)


# Function to gather APIC information and validate it
def apic_info(logger, apic_config):
    logger.debug('Entered "apic_info" function.')
    section = 'APIC'
    setup_dict = parse_setup(section)
    if setup_dict['prompt'].lower() == 'no':
        try:
            apic = setup_dict['ip']
            user = setup_dict['username']
            pword = setup_dict['password']
            aci_login = acipdt.FabLogin(apic, user, pword)
            cookies = aci_login.login()
            logger.info('Successfully verified APIC login information.')
            # return apic, user, password, and cookies to top_menu
            logger.debug('APIC Info functionality complete, returning APIC IP '
                         'of "%s", user of "%s", and password of [redacted] to'
                         ' top_menu.' % (apic, user))
            return(apic, user, pword, cookies)
        except:
            logger.error('FAILED to log into APIC w/ provided information.'
                         ' APIC = "%s", User = "%s"' % (apic, user))
    while True:
        while True:
            apic = input("Please input the APIC IP address: ")
            logger.debug('User entered "%s" for APIC ip' % apic)
            quit(apic, logger)
            try:
                ipaddress.ip_address(apic)
                break
            except:
                logger.error('User entered an invalid IP address of "%s", '
                             'Please enter a valid IP address in x.x.x.x '
                             'format, or type "quit"' % apic)
        user = input("Please enter the APIC userid [admin]: ")
        user = user or 'admin'
        logger.debug('User entered "%s" for APIC user' % user)
        quit(user, logger)
        pword = getpass.getpass("Please enter APIC password [password]: ")
        pword = pword or 'password'
        logger.debug('User entered [redacted] for APIC password')
        quit(pword, logger)
        try:
            aci_login = acipdt.FabLogin(apic, user, pword)
            cookies = aci_login.login()
            logger.info('Successfully verified APIC login information.')
            break
        except:
            logger.error('FAILED to log into APIC w/ provided information.'
                         ' APIC = "%s", User = "%s"' % (apic, user))

    # return apic, user, password, and cookies to top_menu
    logger.debug('APIC Info functionality complete, returning APIC IP of'
                 '"%s", user of "%s", and password of [redacted] to '
                 'top_menu.' % (apic, user))
    return(apic, user, pword, cookies)


def validate_aci_span(logger, apic, cookies, tn, ap, epg):
    s = requests.Session()
    try:
        r = s.get('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                  % (apic, tn, ap, epg), cookies=cookies, verify=False)
        status = r.status_code
        logger.debug('Received status code "%s" from APIC while '
                     'attempting to validate user input.' % status)
    except:
        logger.critical('FAILED to query APIC, exiting.')
        sys.exit()
    payload = json.loads(r.text)
    payload_len = len(payload['imdata'])
    if payload_len == 1:
        logger.debug('Users input for ACI source SPAN validated.')
        return True
    else:
        logger.error('It seems you entered an invalid Tenant, AP, '
                     'or EPG. Try again, or type "quit".')
        return False


# Function to build ACI SPAN configurations if required
def aci_span(apic, cookies, src_ip, tun_ip, logger, span_config):
    logger.debug('Entered "aci_span" function.')
    # Convert src_ip and tun_ip (which was created in the gre func)
    # to dest_ip, tun_src_ip (as we are now working on opposite end
    # of the tunnel)
    dst_ip = src_ip
    tun_src_ip = ipaddress.IPv4Address(tun_ip)
    tun_src_ip = tun_src_ip + 256

    section = 'SPAN'
    setup_dict = parse_setup(section)
    if setup_dict['prompt'].lower() == 'no':
        aci_srctn = setup_dict['source_tn']
        aci_srcap = setup_dict['source_ap']
        aci_srcepg = setup_dict['source_epg']
        aci_dsttn = setup_dict['destination_tn']
        aci_dstap = setup_dict['destination_ap']
        aci_dstepg = setup_dict['destination_epg']
        try:
            validate_aci_span(logger, apic, cookies,
                              aci_srctn, aci_srcap, aci_srcepg)
            validate_aci_span(logger, apic, cookies,
                              aci_dsttn, aci_dstap, aci_dstepg)
            return True
        except:
            print("Failed to Validate ACI SPAN configs.")

    while True:
        cfg_aci = input("Do you already have an ACI SPAN session setup to "
                        "point to this server? ('y' or 'n') [y]: ")
        cfg_aci = cfg_aci or 'y'
        logger.debug('User entered "%s" for '
                     '"Do you already have an ACI SPAN session."' % cfg_aci)
        quit(cfg_aci, logger)
        if cfg_aci.lower() == 'y' or cfg_aci.lower() == 'n':
            break
        else:
            logger.error('Invalid input of "%s" entered for "Do you already '
                         'have an ACI SPAN session". Enter a valid input or '
                         '"quit".' % (cfg_aci))

    # If user does not have ACI SPAN, prompt and configure
    if cfg_aci == 'n':
        # Prompt user for SPAN Source Information
        while True:
            aci_srctn = input("Which ACI Tenant in ACI is your SPAN "
                              "source group?: ")
            quit(aci_srctn, logger)
            logger.debug('User entered "%s" for "ACI Tenant for SPAN '
                         'source"' % aci_srctn)
            aci_srcap = input("In Tenant %s, which Application Profile will "
                              "the SPAN be sourced from?: " % aci_srctn)
            quit(aci_srcap, logger)
            logger.debug('User entered "%s" for "ACI App Profile for SPAN '
                         'source"' % aci_srcap)
            aci_srcepg = input("In Tenant %s Application Profile %s, which "
                               "EPG will the SPAN be sourced from?: " %
                               (aci_srctn, aci_srcap))
            quit(aci_srcepg, logger)
            logger.debug('User entered "%s" for "ACI EPG for SPAN '
                         'source"' % aci_srcepg)

            # Validate the input supplied by the user
            logger.info('Validating ACI Tenant, Application Profile, and '
                        'EPG exists.')
            validate_aci_span(logger, apic, cookies,
                              aci_srctn, aci_srcap, aci_srcepg)

        # Prompt user for SPAN Destination Information
        while True:
            aci_dsttn = input("Which ACI Tenant in ACI is your SPAN "
                              "destination group?: ")
            logger.debug('User entered "%s" for "ACI Tenant for SPAN '
                         'destination"' % aci_dsttn)
            aci_dstap = input("In Tenant %s, which Application Profile "
                              "will the SPAN be destined for?: " % aci_dsttn)
            logger.debug('User entered "%s" for "ACI App Profile for SPAN '
                         'source"' % aci_dstap)
            aci_dstepg = input("In Tenant %s Application Profile %s, which "
                               "EPG will the SPAN be destined for?: "
                               % (aci_dsttn, aci_dstap))
            logger.debug('User entered "%s" for "ACI EPG for SPAN '
                         'source"' % aci_dstepg)

            # Validate the input supplied by the user
            logger.info('Validating ACI Tenant, Application Profile, and '
                        'EPG exists.')
            validate_aci_span(logger, apic, cookies,
                              aci_dsttn, aci_dstap, aci_dstepg)

        # Initialize the Tshoot Class, then build the SPAN session
        logger.info('Creating SPAN Source.')
        aci_span = acipdt.TshootPol(apic, cookies)
        try:
            aci_span.span_src(aci_srctn, 'ACI-PMT-Src', 'enabled', 'both',
                              aci_srcap, aci_srcepg, 'ACI-PMT-Dst',
                              'created,modified')
            logger.debug('Created ACI SPAN source.')
        except:
            logger.critical('FAILED to create ACI SPAN source, exiting.')
            sys.exit()

        logger.info('Creating SPAN Destination.')
        try:
            aci_span.span_dst(aci_srctn, 'ACI-PMT-Dst', aci_dsttn,
                              aci_dstap, aci_dstepg, dst_ip, tun_src_ip,
                              'created,modified')
            logger.debug('Created ACI SPAN Destination.')
        except:
            logger.critical('FAILED to create ACI SPAN destination, exiting.')
            sys.exit()

        logger.debug('ACI SPAN functionality complete, returning to top_menu.')


# Function to gather information required to run Tshark
def tshark_setup(logger, tshark_config):
    logger.debug('Entered "tshark_setup" function.')
    section = 'TSHARK'
    setup_dict = parse_setup(section)
    if setup_dict['prompt'].lower() == 'no':
        tshark_duration = setup_dict['duration']
        duration = tshark_duration[:-1]
        duration = int(duration)
        try:
            if tshark_duration[-1] == 's':
                tshark_duration = duration
            elif tshark_duration[-1] == 'm':
                tshark_duration = duration * 60
            elif tshark_duration[-1] == 'h':
                tshark_duration = duration * 60 * 60
            elif tshark_duration[-1] == 'd':
                tshark_duration = duration * 60 * 60 * 12

            tshark_duration = int(tshark_duration)

            logger.debug('Tshark duration = %s seconds' % tshark_duration)
            return(tshark_duration)
        except Exception as e:
            print(e)
            logger.error('FAILED to load Tshark duration from setup file, '
                         'please input valid values.')

    while True:
        logger.info('In seconds (s), minutes (m), hours (h), or days (d), how '
                    'long would you like the SPAN to run?')
        tshark_duration = input("Enter your selection "
                                "(i.e. 1s, 5m, 10h or 1d): ")
        logger.debug('User entered "%s" for tshark duration.' %
                     (tshark_duration))
        quit(tshark_duration, logger)
        try:
            if (tshark_duration[-1] == 's' or
                tshark_duration[-1] == 'm' or
                tshark_duration[-1] == 'h' or
                tshark_duration[-1] == 'd'):
                    try:
                        duration = tshark_duration[:-1]
                        duration = int(duration)
                        break
                    except:
                        logger.error('User entered "%s" please enter a valid '
                                     'integer before time suffix, or type '
                                     '"quit".' % (tshark_duration))
            else:
                logger.error('User entered "%s" please enter a vlid time '
                             'suffix,  (i.e. "s", "m", "h", or "d", or type '
                             '"quit".' % (tshark_duration))
        except:
            logger.error('Please enter a valid argument for duration.')

    if tshark_duration[-1] == 's':
        tshark_duration = duration
    elif tshark_duration[-1] == 'm':
        tshark_duration = duration * 60
    elif tshark_duration[-1] == 'h':
        tshark_duration = duration * 60 * 60
    elif tshark_duration[-1] == 'd':
        tshark_duration = duration * 60 * 60 * 12

    tshark_duration = int(tshark_duration)

    logger.debug('Tshark duration = %s seconds' % tshark_duration)
    return(tshark_duration)


# Main menu function
def top_menu(logger):
    logger.debug('Entering menu.')
    # Disable requests insecure warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    logger.debug('Attempting to read setup.ini')
    gre_config, apic_config, span_config, tshark_config = process_setup(logger)

    if all(x == 'no' for x in (gre_config, apic_config,
                               span_config, tshark_config)):
        logger.info('Bypassing prompts due to setup.ini configuration')
    else:
        print("Welcome to the ACI Probable Mapping Tool!")
        print("From any prompt type 'quit' to exit program.")

    # process gre tunnel bring up
    logger.debug('Loading gre tunnel.')
    (src_ip, tun_name, tun_ip) = gre_tunnel(logger, gre_config)

    # get apic info from user and validate login
    logger.debug('Loading apic info.')
    (apic, user, pword, cookies) = apic_info(logger, apic_config)

    # process aci span bring up
    logger.debug('Loading aci span.')
    aci_span(apic, cookies, src_ip, tun_ip, logger, span_config)

    # process tshark duration information
    logger.debug('Loading tshark setup.')
    tshark_duration = tshark_setup(logger, tshark_config)

    # return tshark_duration and the tunnel interface name
    logger.debug('Menu functionality complete, returning tunnel name of "%s",'
                 'and duration for tshark of "%s" to main.' %
                 (tun_name, tshark_duration))
    return(tun_name, tshark_duration)
