import quit
import subprocess
import re
import ipaddress
import sys


class GREsetup(object):
    def __init__(self, logger):
        self.logger = logger
        logger.debug('GREsetup class initialized.')

    def gre_values_from_setup(self, setup_obj):
        section = 'GRE'
        section_options = ['prompt', 'tunnel_name', 'source_ip', 'tunnel_ip',
                           'source_int']
        (section_true, setup_dict) = setup_obj.values(section, section_options)
        if section_true is True:
            self.logger.debug('\'gre_values_from_setup\' method loaded.')
            self.gre_prompt = setup_dict['prompt']
            self.tun_name = setup_dict['tunnel_name']
            self.src_ip = setup_dict['source_ip']
            self.tun_ip = setup_dict['tunnel_ip']
            self.src_int = setup_dict['source_int']
            self.logger.debug('Setup file has the following values for GRE sec'
                              'tion:\n\tTunnel Name = %s\n\tSource IP = %s\n\t'
                              'Tunnel IP = %s' %
                              (self.tun_name, self.src_ip, self.tun_ip))
            if self.gre_prompt == 'yes':
                self.logger.debug('Setup file values for GRE, but prompt is se'
                                  't to "yes".')
                return False
        else:
            self.tun_name = 'mon0'
            self.src_ip = '10.1.1.1'
            self.tun_ip = '1.1.1.1'
            self.src_int = 'eth0'
            self.logger.error('Setup file has errors for GRE section.')
            return False

    def gre_values_from_user(self):
        while True:
            cfg_gre = input("Do you already have a GRE tunnel setup to receive"
                            " SPAN data on this server? ('y' or 'n') [y]: ")
            cfg_gre = cfg_gre or 'y'
            self.logger.debug('User entered "%s" for "Do you already have a GR'
                              'E tunnel."' % (cfg_gre))
            quit.quit(self.logger, cfg_gre)
            if cfg_gre.lower() == 'y' or cfg_gre.lower() == 'n':
                break
            else:
                self.logger.error('Invalid input of "%s" entered for "Do you a'
                                  'lready have a GRE tunnel". Enter a valid in'
                                  'put or "quit".' % (cfg_gre))
        if cfg_gre.lower() == 'y':
            return True
        elif cfg_gre.lower() == 'n':
            self.src_interfaces()
            self.mon0_exist()
            self.build_tunnel()

    def tun_validate(self):
        try:
            subprocess.check_output(['ifconfig', self.tun_name])
            self.logger.debug('GRE tunnel %s exists.' % self.tun_name)
            return True
        except:
            self.logger.error('GRE tunnel %s does NOT exist.' %
                              (self.tun_name))
            return False

    def srcip_validate(self):
        try:
            ipaddress.ip_address(self.src_ip)
            self.logger.debug('Tunnel source IP of %s is a valid IP' %
                              (self.src_ip))
            p = subprocess.check_output(['ip addr show %s | grep link/'
                                        'gre' % self.tun_name],
                                        shell=True)
            p = p.decode('utf-8')
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
            ip.remove('0.0.0.0')
            if self.src_ip == ip[0]:
                return True
            else:
                self.src_ip = ip[0]
                self.logger.debug('Updating GRE source IP to reflect actual co'
                                  'nfiguration. IP address = "%s"' %
                                  (self.src_ip))
                return True
        except:
            return False

    def tunup_validate(self):
        try:
            subprocess.check_output(['ifconfig %s | grep UP' %
                                    (self.tun_name)], shell=True)
            self.logger.debug('GRE tunnel seems to be up.')
            return True
        except:
            self.logger.error('GRE tunnel is not up, attempting to remediate.')
            try:
                tun_bringup = ('ip link set %s up' % (self.tun_name))
                subprocess.Popen(tun_bringup, shell=True)
                self.logger.debug('Tunnel successfully brought up.')
                return True
            except:
                self.logger.critical('FAILED to bring up tunnel "%s", exiting.'
                                     % (self.tun_name))
                sys.exit()

    def tunip_validate(self):
        try:
            ipaddress.ip_address(self.tun_ip)
            self.logger.debug('Tunnel IP of %s is a valid IP' %
                              (self.tun_ip))
            p = subprocess.check_output(['ifconfig %s | grep inet' %
                                        (self.tun_name)], shell=True)
            p = p.decode('utf-8')
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
            if self.tun_ip == ip[0]:
                return True
            else:
                return False
        except:
            return False

    def modprobe_validate(self):
        self.logger.debug('Verifying ip_gre module is loaded.')
        try:
            p = subprocess.check_output(['lsmod | grep ip_gre'], shell=True)
            self.logger.debug('ip_gre module is loaded.')
            return True
        except:
            self.logger.error('ip_gre module not loaded, attempting to load.')
            try:
                p = subprocess.call('modprobe ip_gre', shell=True)
                if p == 0:
                    self.logger.debug('ip_gre module loaded successfully.')
                    return True
                elif p == 1:
                    self.logger.critical('FAILED attempting to load ip_gre,'
                                         'exiting.')
                    sys.exit()
            except:
                self.logger.critical('FAILED attempting to load ip_gre, exitin'
                                     'g.')
                sys.exit()

    # NEEDS CLEANUP
    def build_tunnel(self):
        try:
            subprocess.Popen(['ip tunnel add %s mode gre local %s'
                              % (self.tun_name, self.src_ip)], shell=True)
            self.logger.debug('Interface "mon0" successfully created.')
        except:
            self.logger.critical('FAILED to create tunnel interface, exiting.')
            sys.exit()
        try:
            subprocess.Popen(['sudo ip addr add %s/30 dev %s'
                              % (self.tun_ip, self.tun_name)], shell=True)
            self.logger.debug('IP successfully assinged to interface "mon0".')
        except:
            self.logger.critical('FAILED to add IP to interface "mon0".')
            sys.exit()

        self.logger.info('Bringing up tunnel "mon0".')
        self.tunup_validate

    # NEEDS CLEANUP
    def src_interfaces(self):
        p = subprocess.check_output(['ls /sys/class/net'], shell=True)
        p = p.decode('utf-8')
        p = p.split()
        p.remove('lo')
        p.remove('gre0')
        p.remove('gretap0')
        while True:
            print('Available Interfaces:')
            for i in p:
                print(i)
            src_int = input("Enter the interface to use as the GRE tunnel sour"
                            "ce interface [%s]: " % (self.src_int))
            src_int = src_int or 'eth0'
            self.src_int = src_int or self.src_int
            quit.quit(self.logger, self.src_ip)
            try:
                p = subprocess.check_output(['ifconfig', self.src_int])
                self.logger.debug('User entered a valid interface of "%s" for '
                                  'GRE source interface' % (src_int))
                break
            except:
                self.logger.error('Invalid input of "%s" entered for "GRE sour'
                                  'ce interface". Enter a valid inteface, or t'
                                  'ype "quit".' % (src_int))
        while True:
            try:
                p = subprocess.check_output(['ip addr show %s | grep inet'
                                            % self.src_int], shell=True)
                p = p.decode('utf-8')
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', p)
                self.src_ip = ip[0]
                break
            except:
                self.logger.error('Failed to get "%s" IP address' %
                                  (self.src_int))
                src_ip = input('Enter interface %s IP address, or type "quit" '
                               'to exit: ' % (self.src_ip))
                self.src_ip = src_ip or self.src_ip
                quit.quit(self.logger, self.src_ip)
                try:
                    ipaddress.ip_address(self.src_ip)
                    self.logger.debug('User entered a valid IP address of "%s"'
                                      ' for GRE source IP.' % (self.src_ip))
                    break
                except:
                    self.logger.error('Invalid input of "%s" entered for "GRE '
                                      'source IP". Enter a valid inteface, or '
                                      'type "quit".' % (self.src_ip))

    # NEEDS CLEANUP
    def mon0_exist(self):
        self.logger.debug('Validating that mon0 is not taken.')
        # Verify mon0 is not taken then load that as tunnel name
        p = subprocess.check_output(['ls /sys/class/net'], shell=True)
        p = p.decode('utf-8')
        p = p.split()
        # If mon0 is taken, exit
        # In the future add code to change tunnel number
        if 'mon0' in p:
            self.logger.critical('Interface "mon0" is already taken, exiting.')
            sys.exit()
        else:
            self.logger.debug('Interface "mon0" is available.')
            self.tun_name = 'mon0'

    def return_values(self):
        return(self.src_ip, self.tun_ip, self.tun_name)
