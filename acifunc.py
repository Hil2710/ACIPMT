import acipdt
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import quit
import ipaddress
import getpass
import sys


class ACIsetup(object):
    def __init__(self, logger):
        self.logger = logger
        logger.debug('ACIsetup class initialized.')

    def login_values_from_setup(self, setup_obj):
        section = 'APIC'
        section_options = ['prompt', 'ip', 'username', 'password']
        (section_true, setup_dict) = setup_obj.values(section, section_options)
        if section_true is True:
            self.logger.debug('\'login_values_from_setup\' method loaded.')
            self.apic_prompt = setup_dict['prompt']
            self.apic = setup_dict['ip']
            self.user = setup_dict['username']
            self.pword = setup_dict['password']
            self.logger.debug('Setup file has the following values for APIC se'
                              'ction:\n\tAPIC IP = %s\n\tUsername = %s' %
                              (self.apic, self.user))
            if self.apic_prompt == 'yes':
                self.logger.debug('Setup file values for APIC, but prompt is s'
                                  'et to "yes".')
                return False
        else:
            self.apic = '10.1.1.1'
            self.user = 'admin'
            self.logger.error('Setup file has errors for APIC section.')
            return False

    def login_values_from_user(self):
        # Capture APIC IP address
        while True:
            apic = input("Please enter the APIC IP address [%s]: " %
                         (self.apic))
            self.apic = apic or self.apic
            self.logger.debug('User entered "%s" as APIC IP address.' %
                              (self.apic))
            quit.quit(self.logger, self.apic)
            try:
                ipaddress.ip_address(self.apic)
                break
            except:
                self.logger.error('User entered an invalide IP address of "%s"'
                                  ', please enter a valid IP address in "x.x.x'
                                  '.x" format, or type "quit".' % (self.apic))

        # Caputure APIC username
        user = input("Please enter the APIC username [%s]: " % (self.user))
        self.user = user or self.user
        self.logger.debug('User entered "%s" as APIC username.' % (self.user))
        quit.quit(self.logger, self.user)

        # Caputure APIC password
        self.pword = getpass.getpass("Please enter APIC password [password] :")
        self.pword = self.pword or 'password'
        self.logger.debug('User entered [redacted] as APIC password.')
        quit.quit(self.logger, self.pword)

    def span_values_from_setup(self, setup_obj):
        section = 'SPAN'
        section_options = ['prompt', 'source_tn', 'source_ap', 'source_epg',
                           'destination_tn', 'destination_ap',
                           'destination_epg']
        (section_true, setup_dict) = setup_obj.values(section, section_options)
        if section_true is True:
            self.logger.debug('\'span_values_from_setup\' method loaded.')
            self.span_prompt = setup_dict['prompt']
            self.src_tn = setup_dict['source_tn']
            self.src_ap = setup_dict['source_ap']
            self.src_epg = setup_dict['source_epg']
            self.dst_tn = setup_dict['destination_tn']
            self.dst_ap = setup_dict['destination_ap']
            self.dst_epg = setup_dict['destination_epg']
            self.logger.debug('Setup file has the following values for APIC sp'
                              'an section:\n\tSource TN = %s\n\tSource AP = %s'
                              '\n\tSource EPG = %s\n\tDestination TN = %s\n\tD'
                              'estination AP = %s\n\tDestination EPG = %s' %
                              (self.src_tn, self.src_ap, self.src_epg,
                               self.dst_tn, self.dst_ap, self.dst_epg))
            if self.span_prompt == 'yes':
                self.logger.debug('Setup file values for SPAN, but prompt is s'
                                  'et to "yes".')
                return False
            else:
                src_dn = ('uni/tn-%s/ap-%s/epg-%s' % (self.src_tn, self.src_ap,
                                                      self.src_epg))
                dst_dn = ('uni/tn-%s/ap-%s/epg-%s' % (self.dst_tn, self.dst_ap,
                                                      self.dst_epg))
                src_validation = self.span_validate(src_dn)
                dst_validation = self.span_validate(dst_dn)
                if src_validation is False:
                    self.logger.error('SPAN source information failed to valid'
                                      'ate, will now prompt for all SPAN infor'
                                      'mation to be re-entered.')
                    return False
                if dst_validation is False:
                    self.logger.error('SPAN destination information failed to '
                                      'validate, will now prompt for all SPAN '
                                      'information to be re-entered.')
                    return False
        else:
            self.src_tn = ''
            self.src_ap = ''
            self.src_epg = ''
            self.dst_tn = ''
            self.dst_ap = ''
            self.dst_epg = ''
            self.logger.error('Setup file has errors for SPAN section.')
            return False

    def span_values_from_user(self):
        while True:
            cfg_aci = input("Do you already have an ACI SPAN session setup to "
                            "point to this server? ('y' or 'n') [y]: ")
            cfg_aci = cfg_aci or 'y'
            self.logger.debug('User entered "%s" for "Do you already have an A'
                              'CI SPAN session."' % (cfg_aci))
            quit.quit(self.logger, cfg_aci)
            if cfg_aci.lower() == 'y' or cfg_aci.lower() == 'n':
                break
            else:
                self.logger.error('Invalid input of "%s" entered for "Do you a'
                                  'lready have an ACI SPAN session". Enter a v'
                                  'alid input or "quit".' % (cfg_aci))
        if cfg_aci.lower() == 'y':
            return True
        elif cfg_aci.lower() == 'n':
            while True:
                src_tn = input("Which ACI Tenant in ACI is your SPAN source gr"
                               "oup? [%s]: " % (self.src_tn))
                self.src_tn = src_tn or self.src_tn
                quit.quit(self.logger, self.src_tn)
                self.logger.debug('User entered "%s" for "ACI Tenant for SPAN '
                                  'source"' % (self.src_tn))
                src_ap = input("In Tenant %s, which Application Profile will t"
                               "he SPAN be sourced from? [%s]: " %
                               (self.src_tn, self.src_ap))
                self.src_ap = src_ap or self.src_ap
                quit.quit(self.logger, self.src_ap)
                self.logger.debug('User entered "%s" for "ACI App Profile for '
                                  'SPAN source"' % (self.src_ap))
                src_epg = input("In Tenant %s Application Profile %s, which EP"
                                "G will the SPAN be sourced from? [%s]: " %
                                (self.src_tn, self.src_ap, self.src_epg))
                self.src_epg = src_epg or self.src_epg
                quit.quit(self.logger, self.src_epg)
                self.logger.debug('User entered "%s" for "ACI EPG for SPAN sou'
                                  'rce"' % self.src_epg)

                # Validate the input supplied by the user
                self.logger.info('Validating ACI Tenant, Application Profile, '
                                 'and EPG exists.')
                dn = ('uni/tn-%s/ap-%s/epg-%s' % (self.src_tn, self.src_ap,
                                                  self.src_epg))
                validate = self.span_validate(dn)
                if validate is True:
                    break
            while True:
                dst_tn = input("Which ACI Tenant in ACI is your SPAN destinati"
                               "on group? [%s]: " % (self.dst_tn))
                self.dst_tn = dst_tn or self.dst_tn
                quit.quit(self.logger, self.dst_tn)
                self.logger.debug('User entered "%s" for "ACI Tenant for SPAN '
                                  'source"' % (self.dst_tn))
                dst_ap = input("In Tenant %s, which Application Profile will t"
                               "he SPAN be sourced from? [%s]: " %
                               (self.dst_tn, self.dst_ap))
                self.dst_ap = dst_ap or self.dst_ap
                quit.quit(self.logger, self.dst_ap)
                self.logger.debug('User entered "%s" for "ACI App Profile for '
                                  'SPAN source"' % (self.dst_ap))
                dst_epg = input("In Tenant %s Application Profile %s, which EP"
                                "G will the SPAN be sourced from? [%s]: " %
                                (self.dst_tn, self.dst_ap, self.dst_epg))
                self.dst_epg = dst_epg or self.dst_epg
                quit.quit(self.logger, self.dst_epg)
                self.logger.debug('User entered "%s" for "ACI EPG for SPAN sou'
                                  'rce"' % self.dst_epg)

                # Validate the input supplied by the user
                self.logger.info('Validating ACI Tenant, Application Profile, '
                                 'and EPG exists.')
                dn = ('uni/tn-%s/ap-%s/epg-%s' % (self.dst_tn, self.dst_ap,
                                                  self.dst_epg))
                validate = self.span_validate(dn)
                if validate is True:
                    break
            return False

    def apic_login(self):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        try:
            aci_login = acipdt.FabLogin(self.apic, self.user, self.pword)
            self.cookies = aci_login.login()
            self.logger.debug('Successfully verified APIC login information.')
            return True
        except:
            self.logger.error('FAILED to log into APIC w/ provided information'
                              ': APIC IP = "%s", Username = "%s"' %
                              (self.apic, self.user))
            return False

    def span_validate(self, dn):
        try:
            aci_query = acipdt.Query(self.apic, self.cookies)
            (status, payload) = aci_query.query_dn(dn)
        except:
            self.logger.error('Failed to query APIC for SPAN objects.')
            return False

        payload_len = len(payload['imdata'])
        if payload_len == 1:
            if 'error' in payload['imdata'][0]:
                self.logger.error('Error querying SPAN objects.')
                return False
            elif 'fvAEPg' in payload['imdata'][0]:
                self.logger.debug('ACI SPAN object validated.')
                return True
        else:
            self.logger.error('Too many objects in query payload, check SPAN o'
                              'bjects (TN/AP/EPG).')
            return False

    def span_deploy(self, dst_ip, src_ip):
        aci_span = acipdt.TshootPol(self.apic, self.cookies)
        tmp = ipaddress.IPv4Address(src_ip)
        src_ip = tmp + 256
        try:
            src_status = aci_span.span_src(self.src_tn, 'ACI-PMT-Src',
                                           'enabled', 'both', self.src_ap,
                                           self.src_epg, 'ACI-PMT-Dst',
                                           'created,modified')
        except:
            self.logger.critical('FAILED to create ACI SPAN source.')
            return False
        try:
            dst_status = aci_span.span_dst(self.src_tn, 'ACI-PMT-Dst',
                                           self.dst_tn, self.dst_ap,
                                           self.dst_epg, dst_ip, src_ip,
                                           'created,modified')
        except:
            self.logger.critical('FAILED to create ACI SPAN destination.')
            return False
        if src_status == dst_status == 200:
            self.logger.debug('Created ACI SPAN destination. Status Code = %s'
                              % (src_status))
            self.logger.debug('Created ACI SPAN destination. Status Code = %s'
                              % (dst_status))
            return True
        elif src_status == dst_status == 400:
            self.logger.critical('Failed to create ACI SPAN source and destina'
                                 'tion. Status Code = %s' % (src_status))
            return False
        elif src_status != dst_status:
            if src_status == 400:
                self.logger.critical('Failed to create ACI SPAN source. Status'
                                     ' Code = %s' % (src_status))
                return False
            elif dst_status == 400:
                self.logger.critical('Failed to create ACI SPAN destination. S'
                                     'tatus Code = %s' % (src_status))
                return False

    def query_endpoints(self):
        while True:
            login = self.apic_login()
            if login is True:
                pass
            elif login is False:
                self.logger.critical('Failed to log into APIC, exiting.')
                sys.exit()
            query_class = 'fvCEp'
            try:
                aci_query = acipdt.Query(self.apic, self.cookies)
                (status, payload) = aci_query.query_class(query_class)
                return payload
            except:
                self.logger.error('Failed to query APIC for endpoints.')
                sys.exit()
