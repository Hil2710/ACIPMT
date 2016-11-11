from dbstruct import Base, engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import acilogin
import dbfunc
import shark
import menu
import logging
import logging.handlers


# Setup logging
def log():
    # Create a logger named 'logger'
    setup_log = logging.getLogger('logger')
    # Set logging level, initially debugging, but would like to make this
    # user settable via argsparse
    setup_log.setLevel(logging.DEBUG)
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


# Main, call menu and proceed from there
def main():
    # Load log setup
    logger = log()
    logger.debug('Logging loaded.')

    # Load Main Text Driven Menu
    logger.debug('Loading main menu.')
    tun_name, tshark_duration = menu.top_menu(logger)

    # Load Base from dbstruct, create DB Session as 'session'
    logger.debug('Create DB session.')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = scoped_session(DBSession)
    # Disable urllib3 InsecureRequestWarnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # This block should run freaquently for small fabrics, and less for larger
    # Grab cookie and ACI IP from login func
    logger.debug('Logging into APIC.')
    (aci_ip, aci_cookies) = acilogin.aci_login()
    # Log into ACI, grab current endpoints, and write to DB
    logger.debug('Capturing current endpoints from APIC.')
    dbfunc.current_endpoints(aci_ip, aci_cookies, session, logger)
    # Remove stale endpoints
    logger.debug('Removing stale endpoints from DB.')
    dbfunc.clean_endpoints(session, logger)

    if tshark_duration < 120:
        duration = tshark_duration
        cycle = 1
        logger.debug('TShark duration less than 120 seconds, beginning single'
                     ' TShark capture.')
        shark.tshark_process(tun_name, duration, cycle, logger)
        logger.debug('Beginning TShark conversion from pcapng -> CSV.')
        shark.tshark_convert(session, cycle, logger)
    else:
        logger.debug('TShark duration is over 120 seconds. Beginning A/B '
                     'TShark captures.')
        cycle = 1
        while tshark_duration > 0:
            if tshark_duration - 60 >= 0:
                duration = 60
                tshark_duration = tshark_duration - 60
            else:
                duration = tshark_duration
                tshark_duration = tshark_duration - tshark_duration
            logger.debug('Begin TShark process for cycle "%s".' % (str(cycle)))
            shark.tshark_process(tun_name, duration, cycle, logger)
            cycle += 1

    total_cycles = int(cycle)

    while cycle > 0:
        logger.debug('Begin TShark convert for cycle "%s".' % (str(cycle)))
        shark.tshark_convert(session, cycle, logger)
        cycle -= 1

    # Closing the session... need to fix all the session shit here,
    # this is a crappy "fix"
    session.close()
    # This should probably only run at the "end" of a batch -- i.e. if we run
    # tshark for one week, this should run maybe once every 6 hours or
    # something to keep the DB clean(ish)
    # Test creating contract table
    logger.debug('Loading build contracts.')
    dbfunc.build_contracts(session, logger)
    # Test "cleaning" tcp contracts
    logger.debug('Loading clean tcp contracts.')
    dbfunc.clean_tcp_contracts(session, logger)
    # Test "cleaning" udp contracts
    logger.debug('Loading clean udp contracts.')
    dbfunc.clean_udp_contracts(session, logger)
    # Clean up files when done
    logger.debug('Loading TShark clean.')
    shark.tshark_clean(total_cycles, logger)

    logger.debug('Program complete, exiting.')


if __name__ == '__main__':
    main()
