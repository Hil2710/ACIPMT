import configparser
import os


class Setup(object):
    def __init__(self, logger):
        self.setup_file = 'setup.ini'
        self.logger = logger
        logger.debug('Setup class initialized.')

    def setup(self):
        if os.path.isfile(self.setup_file):
            self.setup = configparser.ConfigParser()
            self.setup.read(self.setup_file)
            self.logger.debug('Setup file exists and is loaded.')
            return True
        else:
            self.logger.error('Setup file does NOT exist or failed to load.')
            return False

    def values(self, section, section_options):
        self.logger.debug('Parsing %s values in setup file.' % (section))
        if self.setup.has_section(section) is True:
            for v in section_options:
                if self.setup.has_option(section, v):
                    section_true = True
                else:
                    section_true = False
                    break
        else:
            section_true = False
        setup_dict = {}
        if section_true is True:
            for v in self.setup[section]:
                setup_dict[v] = self.setup[section][v]
        return(section_true, setup_dict)
