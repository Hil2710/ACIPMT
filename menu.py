import os
import quit


class MAINmenu(object):
    def __init__(self, logger, setup_obj, grefunc_obj, acifunc_obj,
                 shkfunc_obj, dbsfunc_obj):
        self.logger = logger
        self.setup_obj = setup_obj
        self.grefunc_obj = grefunc_obj
        self.acifunc_obj = acifunc_obj
        self.shkfunc_obj = shkfunc_obj
        self.dbsfunc_obj = dbsfunc_obj
        '''
        Run setup method - returning True/False (setup file exists)
        '''
        self.setup_exist = self.setup_obj.setup()
        logger.debug('MainMenu class initialized.')

    def main_menu(self):
        os.system('clear')
        print("Welcome to ACI Probable Mapping Tool (ACIpmt)!")
        valid_options = [1, 2, 3, 4, 8, 9]
        while True:
            print("Please select an option from the menu below to begin. Or ty"
                  "pe \"quit\" to exit from any prompt.")
            print("Run ACIpmt                              [1]")
            print("View Database                           [2]")
            print("Clear Database                          [3]")
            print("Output Diagram (future)                 [4]")
            print("Modify Setup File (future)              [8]")
            print("Clear Log (future)                      [9]")
            user_input = input("Enter your selection [1]: ")
            selection = user_input or '1'
            quit.quit(self.logger, selection)
            self.logger.debug('User entered "%s" in the menu.' % (selection))
            try:
                selection = int(selection)
                try:
                    if selection in valid_options:
                        return selection
                except:
                    self.logger.error('Enter a valid integer corresponding to '
                                      'the menu item you would like to run.')
            except:
                self.logger.error('Enter a valid integer corresponding to the '
                                  'menu item you would like to run.')

    def gre_menu(self):
        '''
        Process and validate GRE/Interface Information
        '''
        if self.setup_exist is True:
            gre_prompt = self.grefunc_obj.gre_values_from_setup(self.setup_obj)
        elif self.setup_exist is False:
            self.grefunc_obj.gre_values_from_user()
        if gre_prompt is False:
            self.grefunc_obj.gre_values_from_user()
        gre_validated = False
        while gre_validated is False:
            validate1 = self.grefunc_obj.srcip_validate()
            validate2 = self.grefunc_obj.tunup_validate()
            validate3 = self.grefunc_obj.tunip_validate()
            validate4 = self.grefunc_obj.modprobe_validate()
            if validate1 is validate2 is validate3 is validate4 is True:
                self.logger.debug('Validated GRE configurations.')
                gre_validated = True
            else:
                self.grefunc_obj.gre_values_from_user()
        (self.dst_ip, self.src_ip, self.tun_name) = self.grefunc_obj.return_values()
        return self.tun_name

    def apic_logon_menu(self):
        '''
        Process and validate APIC Information
        '''
        if self.setup_exist is True:
            apic_prompt = self.acifunc_obj.login_values_from_setup(self.setup_obj)
        elif self.setup_exist is False:
            self.acifunc_obj.login_values_from_user()
        if apic_prompt is False:
            self.acifunc_obj.login_values_from_user()
        apic_validated = False
        while apic_validated is False:
            apic_validated = self.acifunc_obj.apic_login()
            if apic_validated is False:
                self.acifunc_obj.login_values_from_user()

    def apic_span_menu(self):
        '''
        Process and validate APIC SPAN Information
        If/elif setup_exist True/False, process and validate input accordingly
        Finally validate APIC SPAN creation success, or re-prompt until success
        '''
        if self.setup_exist is True:
            span_prompt = self.acifunc_obj.span_values_from_setup(self.setup_obj)
        elif self.setup_exist is False:
            span_created = self.acifunc_obj.span_values_from_user()
        if span_prompt is False:
            span_created = self.acifunc_obj.span_values_from_user()
        else:
            span_created = False
        while span_created is False:
            span_created = self.acifunc_obj.span_deploy(self.dst_ip, self.src_ip)
            if span_created is False:
                span_created = self.acifunc_obj.span_values_from_user()

    def shark_menu(self):
        '''
        Process and validate TSHARK Information
        If/elif setup_exist True/False, process and validate input accordingly
        '''
        if self.setup_exist is True:
            shark_prompt = self.shkfunc_obj.shark_values_from_setup(self.setup_obj)
        elif self.setup_exist is False:
            self.shkfunc_obj.shark_values_from_user()
        if shark_prompt is False:
            self.shkfunc_obj.shark_values_from_user()

    def db_menu(self):
        self.dbsfunc_obj.db_values_from_setup(self.setup_obj)

    def db_clear(self):
        os.system('clear')
        valid_options = [1, 2, 3, 9]
        while True:
            print("Please select an option from the menu below to begin. Or ty"
                  "pe \"quit\" to exit from any prompt.")
            print("Clear Endpoint Table                    [1]")
            print("Clear Flows Table                       [2]")
            print("Clear Contracts Table                   [3]")
            print("Return to Main Menu                     [9]")
            user_input = input("Enter your selection [9]: ")
            selection = user_input or '9'
            quit.quit(self.logger, selection)
            self.logger.debug('User entered "%s" in the clear DB menu.' %
                              (selection))
            try:
                selection = int(selection)
                try:
                    if selection in valid_options:
                        if selection == 9:
                            return(False)
                        elif selection == 1:
                            table = 'Endpoints'
                            return(table)
                        elif selection == 2:
                            table = 'Flows'
                            return(table)
                        elif selection == 3:
                            table = 'Contracts'
                            return(table)
                except:
                    self.logger.error('Enter a valid integer corresponding to '
                                      'the menu item you would like to run.')
            except:
                self.logger.error('Enter a valid integer corresponding to the '
                                  'menu item you would like to run.')

    def db_show(self):
        os.system('clear')
        valid_options = [1, 2, 3, 9]
        while True:
            print("Please select an option from the menu below to begin. Or ty"
                  "pe \"quit\" to exit from any prompt.")
            print("Show Endpoint Table                     [1]")
            print("Show Flows Table                        [2]")
            print("Show Contracts Table                    [3]")
            print("Return to Main Menu                     [9]")
            user_input = input("Enter your selection [9]: ")
            selection = user_input or '9'
            quit.quit(self.logger, selection)
            self.logger.debug('User entered "%s" in the clear DB menu.' %
                              (selection))
            try:
                selection = int(selection)
                try:
                    if selection in valid_options:
                        if selection == 9:
                            return(False)
                        elif selection == 1:
                            table = 'Endpoints'
                            return(table)
                        elif selection == 2:
                            table = 'Flows'
                            return(table)
                        elif selection == 3:
                            table = 'Contracts'
                            return(table)
                except:
                    self.logger.error('Enter a valid integer corresponding to '
                                      'the menu item you would like to run.')
            except:
                self.logger.error('Enter a valid integer corresponding to the '
                                  'menu item you would like to run.')

    def export_db(self, table):
        valid_options = [1, 2, 9]
        while True:
            print("Please select an option from the menu below to begin. Or ty"
                  "pe \"quit\" to exit from any prompt.")
            print("Export DB as CSV                        [1]")
            print("Return to Show DB Menu                  [9]")
            user_input = input("Enter your selection [9]: ")
            selection = user_input or '9'
            quit.quit(self.logger, selection)
            self.logger.debug('User entered "%s" in the "export_db" menu.' %
                              (selection))
            try:
                selection = int(selection)
                try:
                    if selection in valid_options:
                        if selection == 9:
                            return(False)
                        elif selection == 1:
                            return(True)
                except:
                    self.logger.error('Enter a valid integer corresponding to '
                                      'the menu item you would like to run.')
            except:
                self.logger.error('Enter a valid integer corresponding to the '
                                  'menu item you would like to run.')
