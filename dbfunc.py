from dbstruct import Endpoints, Flows, Contracts
from collections import Counter
import requests
import json
import datetime
import os
import ipaddress


# Query current endpoints in ACI
def current_endpoints(apic, cookies, session, logger):
    s = requests.Session()
    r = s.get('https://%s/api/class/fvCEp.json'
              % (apic), cookies=cookies, verify=False)
    payload = json.loads(r.text)
    payload_len = len(payload['imdata'])
    for x in range(0, payload_len):
        try:
            ip = payload['imdata'][x]['fvCEp']['attributes']['ip']
            dn = payload['imdata'][x]['fvCEp']['attributes']['dn']
        except Exception as e:
            logger.error('Failed to parse the IP and DN of an endpoint, '
                         'exception: %s' % (e))
            pass
        else:
            try:
                current_time = datetime.datetime.now()
                eps = Endpoints(dn=dn, ip=ip, last_seen=current_time)
                # Note that 'merge' is like 'insert if does not exist'
                session.merge(eps)
                # Commit to the DB
                session.commit()
                logger.debug('Endpoint DN: %s, IP: %s merged into the DB' %
                             (dn, ip))
            except Exception as e:
                logger.error('Failed to write an endpoint to the DB, '
                             'exception: %s.' % (e))
                pass
    logger.debug('Finished capturing current endpoints and writing to DB.')


# Remove stale endpoints from the endpoints DB
def clean_endpoints(session, logger):
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
        logger.debug('Removed endpoint "%s" from the database - REASON: '
                     'exceeded max age.' % (del_eps.dn))
        x += 1
    logger.debug('Finished removing stale endpoints from DB.')


# takes "flow data" which is an array of info from an individual flow
# returns hit counts for this flow if it is already in DB
def query_hitcount(session, flow_data):
    try:
        flow = session.query(Flows).filter((Flows.src_ip == flow_data[2]) &
                                           (Flows.dst_ip == flow_data[3]) &
                                           (Flows.tcp_dst == flow_data[5]) &
                                           (Flows.udp_dst == flow_data[7]) &
                                           (Flows.protocol ==
                                            flow_data[8])).one()
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


# Deduplicates the CSV, but counts total "hits" for each flow
def clean_csv(convert_cycle, logger):
    entries = []
    capfile = ('capture-%s.csv' % (convert_cycle))
    logger.debug('capture-%s.csv being deduplicated.' % (convert_cycle))
    with open(capfile, 'r') as f:
        for row in f:
            entries.append(row.strip('\n'))
    caplen_start = len(entries)
    counted_entries = Counter()
    for x in entries:
        counted_entries[x] += 1
    with open(capfile, 'w') as f:
        for k, v in counted_entries.items():
            write_me = ','.join([k, str(v)])
            f.write('%s\n' % (write_me))
    with open(capfile, 'r') as f:
        caplen_finish = sum(1 for row in f)
    lines_removed = caplen_start - caplen_finish
    logger.debug('capture-%s.csv deduplicated, consolidated %s lines.' %
                 (convert_cycle, lines_removed))


# function to read off the csv and import into the mariadb
def csv_to_db(session, convert_cycle, logger):
    clean_csv(convert_cycle, logger)
    capfile = 'capture-%s.csv' % convert_cycle
    if os.path.isfile(capfile):
        with open(capfile, 'r') as f:
            for line in f:
                # set the current time as we use this for 'last seen' in the db
                current_time = datetime.datetime.now()
                flow_data = line.split(',')
                # grab hit count from above function for each individual flow
                hits = query_hitcount(session, flow_data)
                hits = hits + int(flow_data[9])
                # if/elif/else to ensure that we have non-empty src/dst ip
                # this just ensures that we ignore any L2 stuff
                if flow_data[2] == '':
                    continue
                if flow_data[3] == '':
                    continue
                # IF we get ICMP redirects, we get a weird condition where
                # TShark puts an IP in to the [4] and [5] positions in the
                # row, catch this, then continue
                try:
                    if ipaddress.ip_address(flow_data[4]):
                        continue
                    else:
                        pass
                except:
                    pass
                # Try to add flow to DB
                try:
                    flow = Flows(src_mac=flow_data[0],
                                 dst_mac=flow_data[1],
                                 src_ip=flow_data[2],
                                 dst_ip=flow_data[3],
                                 tcp_src=flow_data[4],
                                 tcp_dst=flow_data[5],
                                 udp_src=flow_data[6],
                                 udp_dst=flow_data[7],
                                 protocol=flow_data[8],
                                 last_seen=current_time,
                                 hits=hits)
                    session.merge(flow)
                    session.commit()
                except Exception as e:
                    logger.error('Failed adding a flow to the DB. Rolling '
                                 'back. Exception: %s' % (e))
                    session.rollback()
    logger.debug('Completed importing CSV data into DB.')
    return(True)


# Function to parse flow data and build relevant contracts
def build_contracts(session, logger):
    flow = session.query(Flows).all()
    session.close()
    # Loop over each entrie in "flow"
    flow_len = len(flow)
    for x in range(0, flow_len):
        # had some issues parsing new lines & empty strings, so strip those off
        # this leaves the protocol number
        protocol = flow[x].protocol.strip('\n').strip('')
        # we want to make sure protocol is indeed an integer (should be!)
        try:
            protocol = int(protocol)
        except:
            logger.error('Encountered flow with an invalid protocol'
                         'number. Protocol was "%s"' % (str(protocol)))
            continue
        # for now we only care about 6(tcp) & 17(udp) for everything else skip
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
            logger.debug('Skipping a flow for not being TCP or UDP, protocol '
                         'ID is: %s' % (protocol))
            continue

        # Try to find the source EPG for the particular flow we are working on
        # if it doesn't exist we enter "unknown"
        src_mac = flow[x].src_mac.strip('\n').strip('')
        try:
            src_ips = session.query(Endpoints).filter(Endpoints.ip ==
                                                      flow[x].src_ip).all()
            session.close()
        except:
            logger.error('Failed to query DB while corelating a flow to '
                         'endpoints.')
        # If we receive more than 0 results from our query:
        if len(src_ips) == 1:
            src_epg = src_ips[0].dn
        elif len(src_ips) > 1:
            for i in src_ips:
                logger.debug('Source IP address: %s matches multiple EPGs: %s'
                             % (flow[x].src_ip, i.dn))
            for i in src_ips:
                if i.dn[-17:].lower() == src_mac:
                    src_epg = i.dn
                    break
                else:
                    src_epg = 'Multiple EGPs matching MAC/IP.'
        # If we got 0 results from our query, then the EPG is unkown
        else:
            logger.debug('Failed to match source IP: %s to any EPG in the'
                         ' fabric' % (flow[x].dst_ip))
            src_epg = 'unkown'

        # Do the same as above but for destination MAC
        dst_mac = flow[x].dst_mac.strip('\n').strip('')
        try:
            dst_ips = session.query(Endpoints).filter(Endpoints.ip ==
                                                      flow[x].dst_ip).all()
            session.close()
        except:
            logger.error('Failed to query DB while corelating a flow to '
                         'endpoints.')
        # If we receive more than 0 results from our query:
        if len(dst_ips) == 1:
            dst_epg = dst_ips[0].dn
        elif len(dst_ips) > 1:
            for i in dst_ips:
                logger.debug('Destination IP address: %s matches multiple '
                             'EPGs: %s' % (flow[x].dst_ip, i.dn))
            for i in dst_ips:
                if i.dn[-17:].lower() == dst_mac:
                    dst_epg = i.dn
                    break
                else:
                    dst_epg = 'Multiple EGPs matching MAC/IP.'
        # If we got 0 results from our query, then the EPG is unkown
        else:
            logger.debug('Failed to match destination IP: %s to any EPG in the'
                         ' fabric' % (flow[x].dst_ip))
            dst_epg = 'unkown'

        # Add entry to contracts table in DB
        contract = Contracts(src_epg=src_epg,
                             dst_epg=dst_epg,
                             tcp_src=tcp_src,
                             tcp_dst=tcp_dst,
                             udp_src=udp_src,
                             udp_dst=udp_dst,
                             protocol=protocol,
                             last_seen=datetime.datetime.now())
        session.merge(contract)
        session.commit()
        logger.debug('Created contract entry for flow between the following '
                     'EPGs:\nSource: %s \nDestination: %s' %
                     (src_epg, dst_epg))
        x += 1


# Attempt to eliminate redundant/reverse flow info (i.e. 1025->443 / 443->1025)
def clean_tcp_contracts(session, logger):
    # Query all TCP contracts
    tcp_ctrx = session.query(Contracts).filter(Contracts.protocol ==
                                               'tcp').all()
    # Get quantity of all tcp contracts
    tcp_ctrx_len = len(tcp_ctrx)
    # for every tcp contract
    for x in range(0, tcp_ctrx_len):
        # for every tcp contract in the nested loop
        for y in range(0, tcp_ctrx_len):
            # if the src epg [x] matches is also a destination epg [y]
            if tcp_ctrx[x].src_epg == tcp_ctrx[y].dst_epg:
                # If the src and dst ports match (indicating return traffic)
                if tcp_ctrx[x].tcp_src == tcp_ctrx[y].tcp_dst:
                    # if both ports are ephemeral, leave them in and log
                    if (int(tcp_ctrx[x].tcp_src) > 1024 and
                        int(tcp_ctrx[y].tcp_src) > 1024):
                            logger.debug('Flow with ephemeral ports in both '
                                         'source and destination, leaving in '
                                         'Contracts DB.\nFlow #1:\n'
                                         'Source: %s:%s\nDestination: %s:%s\n'
                                         'Flow #2:\nSource: %s:%s\n'
                                         'Destination: %s:%s' %
                                         (tcp_ctrx[x].src_epg,
                                          tcp_ctrx[x].tcp_src,
                                          tcp_ctrx[x].dst_epg,
                                          tcp_ctrx[x].tcp_dst,
                                          tcp_ctrx[y].src_epg,
                                          tcp_ctrx[y].tcp_src,
                                          tcp_ctrx[y].dst_epg,
                                          tcp_ctrx[y].tcp_dst))
                    else:
                        # find and delete flow w/ low order source port
                        if (int(tcp_ctrx[x].tcp_src) < 1025 and
                            int(tcp_ctrx[y].tcp_src) > 1024):
                                logger.debug('Flow with low order source port.'
                                             ' Deleting unnecessary flow from '
                                             'Contracts DB.\nFlow #1:\nSource:'
                                             ' %s:%s\nDestination: %s:%s\n'
                                             'Flow #2:\nSource: %s:%s\n'
                                             'Destination: %s:%s' %
                                             (tcp_ctrx[x].src_epg,
                                              tcp_ctrx[x].tcp_src,
                                              tcp_ctrx[x].dst_epg,
                                              tcp_ctrx[x].tcp_dst,
                                              tcp_ctrx[y].src_epg,
                                              tcp_ctrx[y].tcp_src,
                                              tcp_ctrx[y].dst_epg,
                                              tcp_ctrx[y].tcp_dst))
                                session.delete(tcp_ctrx[x])
                                session.commit()


# Attempt to eliminate redundant/reverse flow info (i.e. 1025->443 / 443->1025)
def clean_udp_contracts(session, logger):
    # Query all UDP contracts
    udp_ctrx = session.query(Contracts).filter(Contracts.protocol ==
                                               'udp').all()
    # Get quantity of all udp contracts
    udp_ctrx_len = len(udp_ctrx)
    # for every udp contract
    for x in range(0, udp_ctrx_len):
        # for every udp contract in the nested loop
        for y in range(0, udp_ctrx_len):
            # if the src epg [x] matches is also a destination epg [y]
            if udp_ctrx[x].src_epg == udp_ctrx[y].dst_epg:
                # If the src and dst ports match (indicating return traffic)
                if udp_ctrx[x].udp_src == udp_ctrx[y].udp_dst:
                    # if both ports are ephemeral, leave them in and log
                    if (int(udp_ctrx[x].udp_src) > 1024 and
                        int(udp_ctrx[y].udp_src) > 1024):
                            logger.debug('Flow with ephemeral ports in both '
                                         'source and destination, leaving in '
                                         'Contracts DB.\nFlow #1:\n'
                                         'Source: %s:%s\nDestination: %s:%s\n'
                                         'Flow #2:\nSource: %s:%s\n'
                                         'Destination: %s:%s' %
                                         (udp_ctrx[x].src_epg,
                                          udp_ctrx[x].udp_src,
                                          udp_ctrx[x].dst_epg,
                                          udp_ctrx[x].udp_dst,
                                          udp_ctrx[y].src_epg,
                                          udp_ctrx[y].udp_src,
                                          udp_ctrx[y].dst_epg,
                                          udp_ctrx[y].udp_dst))
                    else:
                        # find and delete flow w/ low order source port
                        if (int(udp_ctrx[x].udp_src) < 1025 and
                            int(udp_ctrx[y].udp_src) > 1024):
                                logger.debug('Flow with low order source port.'
                                             ' Deleting unnecessary flow from '
                                             'Contracts DB.\nFlow #1:\nSource:'
                                             ' %s:%s\nDestination: %s:%s\n'
                                             'Flow #2:\nSource: %s:%s\n'
                                             'Destination: %s:%s' %
                                             (udp_ctrx[x].src_epg,
                                              udp_ctrx[x].udp_src,
                                              udp_ctrx[x].dst_epg,
                                              udp_ctrx[x].udp_dst,
                                              udp_ctrx[y].src_epg,
                                              udp_ctrx[y].udp_src,
                                              udp_ctrx[y].dst_epg,
                                              udp_ctrx[y].udp_dst))
                                session.delete(udp_ctrx[x])
                                session.commit()
