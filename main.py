import config_loader
import acifunc
import grefunc
import shkfunc
import dbsfunc
import menu
import configparser
import os
import logging
import logging.handlers
import sys
import threading


# Setup logging
def log():
    '''
    Load logging level from setup.ini
    Doing this manually since setup.py requires logger
    '''
    setup_file = 'setup.ini'
    section = 'LOGGING'
    try:
        if os.path.isfile(setup_file):
            setup = configparser.ConfigParser()
            setup.read(setup_file)
            if setup.has_option(section, 'Level'):
                logging_level = setup[section]['Level']
            else:
                raise Exception
        else:
            raise Exception
    except:
        logging_level = 'DEBUG'
    # Create a logger named 'logger'
    setup_log = logging.getLogger('logger')
    # Set logging level, initially debugging, but would like to make this
    # user settable via argsparse
    eval("setup_log.setLevel(logging.%s)" % logging_level)
    # Initialize a logger named 'logger'
    logger = logging.getLogger('logger')
    # Create a handler called 'logstream' for stdout
    logstream = logging.StreamHandler()
    # Setup log stream formatting
    logstreamformat = logging.Formatter("%(message)s")
    logstream.setFormatter(logstreamformat)
    # Create a handler called 'logfile' for logging to a .log
    logfile = logging.FileHandler('/home/acipmt/acipmt.log')
    # Setup log file formatting
    logfileformat = logging.Formatter("%(levelname)s, %(asctime)s,"
                                      "\n\tFunction: %(funcName)s, "
                                      "Line: %(lineno)d, \n\tMessage: "
                                      "%(message)s")
    logfile.setFormatter(logfileformat)
    # Add hanlders to the 'logger' object
    setup_log.addHandler(logstream)
    setup_log.addHandler(logfile)
    # return 'logger' to the main
    return(logger)


def query_thread(acifunc_obj, dbsfunc_obj, interval, stop_event):
    while(not stop_event.is_set()):
        payload = acifunc_obj.query_endpoints()
        dbsfunc_obj.write_endpoints(payload)
        dbsfunc_obj.clean_endpoints()
        stop_event.wait(interval)


# Main, call menu and proceed from there
def main():
    # Load log setup
    logger = log()
    logger.debug('Logging loaded.')

    # initialize modules
    setup_obj = config_loader.Setup(logger)
    grefunc_obj = grefunc.GREsetup(logger)
    acifunc_obj = acifunc.ACIsetup(logger)
    shkfunc_obj = shkfunc.SHKsetup(logger)
    dbsfunc_obj = dbsfunc.DBSsetup(logger)
    menu_obj = menu.MAINmenu(logger, setup_obj, grefunc_obj, acifunc_obj,
                             shkfunc_obj, dbsfunc_obj)

    # load menus
    while True:
        selection = menu_obj.main_menu()
        if selection == 1:
            tun_name = menu_obj.gre_menu()
            menu_obj.apic_logon_menu()
            menu_obj.apic_span_menu()
            menu_obj.shark_menu()
            menu_obj.db_menu()

            interval = 60
            thread_stop = threading.Event()
            thread_query_endpoints = threading.Thread(target=query_thread,
                                                      args=(acifunc_obj,
                                                            dbsfunc_obj,
                                                            interval,
                                                            thread_stop))
            thread_query_endpoints.start()
            # returning total cycles to pass to the csv->db func
            total_cycles = shkfunc_obj.run_shark(tun_name)
            shkfunc_obj.shark_convert()
            shkfunc_obj.shark_dedupe_csv()
            dbsfunc_obj.write_flows(total_cycles)
            shkfunc_obj.shark_clean()
            dbsfunc_obj.write_contracts()
            dbsfunc_obj.clean_tcp_contracts()
            dbsfunc_obj.clean_udp_contracts()
            thread_stop.set()
        elif selection == 2:
            table = menu_obj.db_show()
            if table is False:
                pass
            else:
                dbsfunc_obj.show_table(table)
                export = menu_obj.export_db(table)
                if export is False:
                    pass
                else:
                    dbsfunc_obj.export_table(table)
        elif selection == 3:
            table = menu_obj.db_clear()
            if table is False:
                pass
            else:
                dbsfunc_obj.erase_table(table)
        else:
            print("currently no viable option other than 1 and 3. exiting")
            sys.exit()


if __name__ == '__main__':
    main()
