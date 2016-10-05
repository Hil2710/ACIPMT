from dbstruct import Base, engine
from sqlalchemy.orm import sessionmaker
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import acilogin
import dbfunc
import shark
import menu
import itertools
import threading
import time


def main():
    # Load Main Text Driven Menu
    tun_name, tshark_duration = menu.top_menu()

    # Possibly sleep here to wait for faults to clear in ACI and stuff?

    # Load Base from dbstruct, create DB Session as 'session'
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    # Disable urllib3 InsecureRequestWarnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # This block should run freaquently for small fabrics, and less for larger
    # Grab cookie and ACI IP from login func
    (aci_ip, aci_cookies) = acilogin.aci_login()
    # Log into ACI, grab current endpoints, and write to DB 
    dbfunc.current_endpoints(aci_ip, aci_cookies, session)
    # Remove stale endpoints
    dbfunc.clean_endpoints(session)

    tshark_cycles = ['a', 'b']
    cycles = itertools.cycle(tshark_cycles)
    if tshark_duration < 120:
        duration = tshark_duration
        cycle = 'a'
        shark.tshark_process(tun_name, duration, cycle)
        shark.tshark_convert(session, cycle)
    else:
        while tshark_duration > 0:
            if tshark_duration - 60 >= 0:
                duration = 60
                tshark_duration = tshark_duration - 60
            else:
                duration = tshark_duration
                tshark_duration = tshark_duration - tshark_duration
            cycle = next(cycles)
            shark.tshark_process(tun_name, duration, cycle)
            t = threading.Thread(target=shark.tshark_convert,
                                 args=(session, cycle))
            t.start()

    # This should probably only run at the "end" of a batch -- i.e. if we run tshark for one week, this should run maybe once every 6 hours or something to keep the DB clean(ish)
    # Test creating contract table
    dbfunc.build_contracts(session)
    # Test "cleaning" tcp contracts
    dbfunc.clean_tcp_contracts(session)
    # Test "cleaning" udp contracts
    dbfunc.clean_udp_contracts(session)

    # Sleep whilst waiting for the processing to complete
    # Should look into checking if the thread is complete - but will need to figure out
        # how to make that not fail out for the times where we dont thread it (i.e. under 120)
    time.sleep(10)
    # Clean up files when done
    shark.tshark_clean()


if __name__ == '__main__':
    main()