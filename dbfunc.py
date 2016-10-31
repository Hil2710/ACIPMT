from dbstruct import Endpoints, Flows, Contracts
from sqlalchemy import func
import requests
import json
import datetime
import os
import ipaddress


def current_endpoints(apic, cookies, session):
    s = requests.Session()
    r = s.get('https://%s/api/class/fvCEp.json'
              % (apic), cookies=cookies, verify=False)
    payload = json.loads(r.text)
    payload_len = len(payload['imdata'])
    for x in range(0, payload_len):
        try:
            ip = payload['imdata'][x]['fvCEp']['attributes']['ip']
            dn = payload['imdata'][x]['fvCEp']['attributes']['dn']
        except:
            print("Failed to parse the IP and DN of an endpoint for"
                  " some reason.")
            pass
        else:
            try:
                current_time = datetime.datetime.now()
                eps = Endpoints(dn=dn, ip=ip, last_seen=current_time)
                # Note that 'merge' is like 'insert if does not exist'
                session.merge(eps)
                # Commit to the DB
                session.commit()
            except:
                print("Failed to write an endpoint to the DB for some reason.")
                pass


def clean_endpoints(session):
    # Set 'maxage' time -- currently its 1.4 minutes for testing
    maxage = datetime.datetime.now() - datetime.timedelta(0.001)
    # Query all endpoints in the table older than maxage
    aged_eps = session.query(Endpoints).filter(Endpoints.last_seen <
                                               maxage).all()
    # Grab the length of the returned list it iterate over it
    ep_len = len(aged_eps)
    # For every returned endpoint
    for x in range(0, ep_len):
        # Load the endpoint into an object to delete
        del_eps = session.query(Endpoints).filter(Endpoints.dn ==
                                                  aged_eps[x].dn).one()
        # Delete the endpoint and commit to the DB
        session.delete(del_eps)
        session.commit()
        x += 1


# function takes "flow data" which is an array of info from an individual flow
# think this could be optimized? seems wasteful to ship each individual
# flow as an array and pass that between functions...?
def query_hitcount(session, flow_data):
    # check to see if the flow already exists in the table
    # note that the primary keys are src/dst ip and port (tcp or udp, if tcp udp = 0 and visa versa)
    # if there is a flow already in the DB then we find the hits, if empty we make it 0 then increment
    # if its already exists we just load that up as an int then increment
    # if no flow exists we set the hits to 0 as we think this is the first time we saw the flow
    try:
        flow = session.query(Flows).filter((Flows.src_ip == flow_data[0]) &
                                           (Flows.dst_ip == flow_data[1]) &
                                           (Flows.tcp_dst == flow_data[3]) &
                                           (Flows.udp_dst == flow_data[5]) &
                                           (Flows.protocol ==
                                            flow_data[6])).one()
        if flow.hits is None:
            hits = 0
        else:
            hits = flow.hits
        hits += 1
        session.close()
    except:
        hits = 1
    # finally we return the hit counts
    return(hits)


# function to read off the csv and import into the mariadb
def csv_to_db(session, convert_cycle):
    capfile = 'capture-%s.csv' % convert_cycle
    if os.path.isfile(capfile):
        with open(capfile, 'r') as f:
            for line in f:
                # set the current time as we use this for 'last seen' in the db
                current_time = datetime.datetime.now()
                flow_data = line.split(',')
                # grab hit count from above function for each individual flow
                hits = query_hitcount(session, flow_data)
                # if/elif/else to ensure that we have non-empty src/dst ip
                # this just ensures that we ignore any L2 stuff
                if flow_data[0] == '':
                    continue
                if flow_data[1] == '':
                    continue
                # IF we get ICMP redirects, we get a weird condition where
                # TShark puts an IP in to the [2] and [3] positions in the
                # row, catch this, then continue
                try:
                    if ipaddress.ip_address(flow_data[2]):
                        continue
                    else:
                        pass
                except:
                    pass
                # Try to add flow to DB
                try:
                    flow = Flows(src_ip=flow_data[0],
                                 dst_ip=flow_data[1],
                                 tcp_src=flow_data[2],
                                 tcp_dst=flow_data[3],
                                 udp_src=flow_data[4],
                                 udp_dst=flow_data[5],
                                 protocol=flow_data[6],
                                 last_seen=current_time,
                                 hits=hits)
                    session.merge(flow)
                    session.commit()
                except Exception as e:
                    print("Failed adding a flow to the DB. Rolling back.")
                    print("Exception: %s" % (e))
                    session.rollback()
    return(True)


# want to run this one infrequently and also make sure that its checking the time of the last_seen in EPs -- basically should only generate a contract if its been seen within last week or something
# also need to put the src ports in because this will throw lots of whacky shit like a million contracts for tcp dst ports -- 
# basically will want to delete all rows that have matching src / dst epg and dst port -- that should eliminate all the high order ports
def build_contracts(session):
    flow = session.query(Flows).all()
    session.close()
    # snag the length of all flows (basically total count of flows)
    # use this later to loop over each entry
    flow_len = len(flow)
    for x in range(0, flow_len):
        # had some issues parsing new lines and empty strings, so strip those off
        # this leaves the protocol number
        protocol = flow[x].protocol.strip('\n').strip('')
        # we want to make sure protocol is indeed an integer (should be!)
        try:
            protocol = int(protocol)
        except:
            continue
        # for now we only care about 6 (tcp) and 17 (udp) for everything else skip
        if protocol == 6:
            protocol = 'tcp'
            tcp_src = flow[x].tcp_src
            tcp_dst = flow[x].tcp_dst
            udp_src = 'N/A'
            udp_dst = 'N/A'
        elif protocol == 17:
            protocol = 'udp'
            tcp_src = 'N/A'
            tcp_dst = 'N/A'
            udp_src = flow[x].udp_src
            udp_dst = flow[x].udp_dst
        else:
            continue
        # Try to find the source EPG for the particular flow we are working on
        # if it doesn't exist we enter "unknown" this means its not in the fabric (probably external)
        try:
            src_epg = session.query(Endpoints).filter(Endpoints.ip == flow[x].src_ip).one()
            session.close()
            src_epg = src_epg.dn
        except:
            src_epg = 'unkown'
        # Do the same thing for the destination
        try:
            dst_epg = session.query(Endpoints).filter(Endpoints.ip == flow[x].dst_ip).one()
            session.close()
            dst_epg = dst_epg.dn
        except:
            dst_epg = 'unkown'
        # Now we load an entry into the contracts table
        # need to add in src port becauase we want to make sure that we have that so we can filter on it
        # basically we may see flows inbound to an epg w/ high order destination ports (return http traffic for example)
        # we want to be able to correlate all this and elimnate all that stuff -- this is up next
        contract = Contracts(src_epg=src_epg,
                             dst_epg=dst_epg,
                             tcp_src=tcp_src,
                             tcp_dst=tcp_dst,
                             udp_src=udp_src,
                             udp_dst=udp_dst,
                             protocol=protocol,
                             last_seen=func.now())
        session.merge(contract)
        session.commit()
        x += 1


# This one should be ran infrequently as well -- it is designed to eliminate all the wonky src port contracts
# Basically if a tcp session is 1025->80 then we dont need a contract for 80->1025, so this is designed
# to eliminate those flows from the contract table (we will keep them in the flow table though just in case)
def clean_tcp_contracts(session):
    tcp_ctrx = session.query(Contracts).filter(Contracts.protocol ==
                                               'tcp').all()
    # Get quantity of all tcp contracts
    tcp_ctrx_len = len(tcp_ctrx)
    # for every tcp contract
    for x in range(0, tcp_ctrx_len):
        # for every tcp contract in the nested loop
        for y in range(0, tcp_ctrx_len):
            # see if the src epg matches is also a destination epg from the query
            if tcp_ctrx[x].src_epg == tcp_ctrx[y].dst_epg:
                # if it does, then see if the src and dst ports match (indicating return traffic)
                if tcp_ctrx[x].tcp_src == tcp_ctrx[y].tcp_dst:
                    # if both ports are ephemeral, leave them in
                    if (int(tcp_ctrx[x].tcp_src) > 1024 and
                        int(tcp_ctrx[y].tcp_src) > 1024):
                            print("High order port on source EPG, leaving in "
                                  "contract table. Issue is between following "
                                  "EPGs.")
                            print("Source EPG: " + tcp_ctrx[x].src_epg +
                                  ", Source TCP:" + tcp_ctrx[x].tcp_src +
                                  ", Destination TCP: " + tcp_ctrx[x].tcp_dst)
                            print("Destination EPG: " + tcp_ctrx[x].src_epg +
                                  ", Source TCP:" + tcp_ctrx[x].tcp_src +
                                  ", Destination TCP: " + tcp_ctrx[x].tcp_dst)
                            print("--------------")
                    else:
                        if (int(tcp_ctrx[x].tcp_src) < 1025 and
                            int(tcp_ctrx[y].tcp_src) > 1024):
                                print("Deleting Contract.")
                                print("Source EPG: " + tcp_ctrx[x].src_epg +
                                      ", Source TCP:" + tcp_ctrx[x].tcp_src +
                                      ", Destination TCP: " +
                                      tcp_ctrx[x].tcp_dst)
                                print("Destination EPG: " +
                                      tcp_ctrx[x].src_epg + ", Source TCP:" +
                                      tcp_ctrx[x].tcp_src +
                                      ", Destination TCP: " +
                                      tcp_ctrx[x].tcp_dst)
                                print("--------------")
                                session.delete(tcp_ctrx[x])
                                session.commit()


def clean_udp_contracts(session):
    udp_ctrx = session.query(Contracts).filter(Contracts.protocol ==
                                               'udp').all()
    # Get quantity of all tcp contracts
    udp_ctrx_len = len(udp_ctrx)
    # for every tcp contract
    for x in range(0, udp_ctrx_len):
        # for every tcp contract in the nested loop
        for y in range(0, udp_ctrx_len):
            # see if the src epg matches is also a destination epg from the query
            if udp_ctrx[x].src_epg == udp_ctrx[y].dst_epg:
                # if it does, then see if the src and dst ports match (indicating return traffic)
                if udp_ctrx[x].udp_src == udp_ctrx[y].udp_dst:
                    # if both ports are ephemeral, leave them in
                    if (int(udp_ctrx[x].udp_src) > 1024 and
                        int(udp_ctrx[y].udp_src) > 1024):
                            print("High order port on source EPG, leaving in "
                                  "contract table. Issue is between following "
                                  "EPGs.")
                            print("Source EPG: " + udp_ctrx[x].src_epg +
                                  ", Source TCP:" + udp_ctrx[x].udp_src +
                                  ", Destination UDP: " + udp_ctrx[x].udp_dst)
                            print("Destination EPG: " + udp_ctrx[x].src_epg +
                                  ", Source TCP:" + udp_ctrx[x].udp_src +
                                  ", Destination UDP: " + udp_ctrx[x].udp_dst)
                            print("--------------")
                    else:
                        if (int(udp_ctrx[x].udp_src) < 1025 and
                            int(udp_ctrx[y].udp_src) > 1024):
                                print("Deleting Contract.")
                                print("Source EPG: " + udp_ctrx[x].src_epg +
                                      ", Source TCP:" + udp_ctrx[x].udp_src +
                                      ", Destination UDP: " +
                                      udp_ctrx[x].udp_dst)
                                print("Destination EPG: " +
                                      udp_ctrx[x].src_epg + ", Source TCP:" +
                                      udp_ctrx[x].udp_src +
                                      ", Destination UDP: " +
                                      udp_ctrx[x].udp_dst)
                                print("--------------")
                                session.delete(udp_ctrx[x])
                                session.commit()
