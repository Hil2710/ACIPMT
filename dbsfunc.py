from dbstruct import Base, engine, Endpoints, Flows, Contracts
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
import datetime
import ipaddress
import os
from prettytable import PrettyTable


class DBSsetup(object):
    def __init__(self, logger):
        self.logger = logger
        logger.debug('DBSsetup class initialized.')
        # initialize DB
        self.logger.debug('Create DB session.')
        Base.metadata.bind = engine
        DBSession = sessionmaker(bind=engine)
        self.session = scoped_session(DBSession)

    def db_values_from_setup(self, setup_obj):
        section = 'DATABASE'
        section_options = ['endpoint_timeout']
        (section_true, setup_dict) = setup_obj.values(section, section_options)
        if section_true is True:
            self.logger.debug('\'db_values_from_setup\' method loaded.')
            self.ep_timeout = setup_dict['endpoint_timeout']
            self.logger.debug('Setup file has the following values for DATABAS'
                              'E section:\n\tEndpoint Timeout = %s' %
                              (self.ep_timeout))
            try:
                self.ep_timeout = int(self.ep_timeout)
                return True
            except:
                self.ep_timeout = 86400
                self.logger.error('Invalid entry in setup file for endpoint_ti'
                                  'meout.')
                return True
        else:
            self.ep_timeout = 86400
            self.logger.error('Setup file has errors for DATABSE section.')
            return True

    def write_endpoints(self, payload):
        payload_len = len(payload['imdata'])
        for x in range(0, payload_len):
            try:
                ip = payload['imdata'][x]['fvCEp']['attributes']['ip']
                dn = payload['imdata'][x]['fvCEp']['attributes']['dn']
            except Exception as e:
                self.logger.error('Failed to parse the IP and DN of an endpoin'
                                  't, exception: %s' % (e))
                pass
            else:
                try:
                    current_time = datetime.datetime.now()
                    eps = Endpoints(dn=dn, ip=ip, last_seen=current_time)
                    # Note that 'merge' is like 'insert if does not exist'
                    self.session.merge(eps)
                    # Commit to the DB
                    self.session.commit()
                    self.logger.debug('Endpoint DN: %s, IP: %s merged into the'
                                      ' DB' % (dn, ip))
                except Exception as e:
                    self.logger.error('Failed to write an endpoint to the DB, '
                                      'exception: %s.' % (e))
                    pass

    def clean_endpoints(self):
        maxage = datetime.datetime.now() - datetime.timedelta(seconds = 
                                                              self.ep_timeout)
        aged_eps = self.session.query(Endpoints).filter(Endpoints.last_seen <
                                                        maxage).all()
        ep_len = len(aged_eps)
        for x in range(0, ep_len):
            del_eps = self.session.query(Endpoints).filter(Endpoints.dn ==
                                                           aged_eps[x].dn).one()
            self.session.delete(del_eps)
            self.session.commit()
            self.logger.debug('Removed endpoint "%s" from the database - REASO'
                              'N: exceeded max age.' % (del_eps.dn))
            x += 1
        self.logger.debug('Finished removing stale endpoints from DB.')

    def query_hitcount(self, flow_data):
        try:
            flow = self.session.query(Flows).filter((Flows.src_ip ==
                                                     flow_data[2]) &
                                                    (Flows.dst_ip ==
                                                     flow_data[3]) &
                                                    (Flows.tcp_dst ==
                                                     flow_data[5]) &
                                                    (Flows.udp_dst ==
                                                     flow_data[7]) &
                                                    (Flows.protocol ==
                                                     flow_data[8])).one()
            if flow.hits is None:
                hits = 0
            else:
                hits = flow.hits
            hits += 1
            self.session.close()
        except:
            hits = 1
        return(hits)

    def write_flows(self, total_cycles):
        cycle = total_cycles
        while cycle > 0:
            capfile = 'capture-%s.csv' % cycle
            if os.path.isfile(capfile):
                with open(capfile, 'r') as f:
                    for line in f:
                        current_time = datetime.datetime.now()
                        flow_data = line.split(',')
                        hits = self.query_hitcount(flow_data)
                        try:
                            int(flow_data[9])
                            hits = hits + int(flow_data[9])
                        except Exception as e:
                            print(e)
                            continue
                        if flow_data[2] == '':
                            continue
                        if flow_data[3] == '':
                            continue
                        try:
                            if ipaddress.ip_address(flow_data[4]):
                                continue
                            else:
                                pass
                        except:
                            pass
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
                            self.session.merge(flow)
                            self.session.commit()
                        except Exception as e:
                            self.logger.error('Failed adding a flow to the DB.'
                                              'Rolling back. Exception: %s' %
                                              (e))
                            self.session.rollback()
            self.logger.debug('Completed importing capture-%s data into DB.' %
                              (cycle))
            cycle -= 1
        return(True)

    def write_contracts(self):
        flow = self.session.query(Flows).all()
        self.session.close()
        flow_len = len(flow)
        for x in range(0, flow_len):
            protocol = flow[x].protocol.strip('\n').strip('')
            try:
                protocol = int(protocol)
            except:
                self.logger.error('Encountered flow with an invalid protocol n'
                                  'umber. Protocol was "%s"' % (str(protocol)))
                continue
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
                self.logger.debug('Skipping a flow for not being TCP or UDP, p'
                                  'rotocol ID is: %s' % (protocol))
                continue

            src_mac = flow[x].src_mac.strip('\n').strip('')
            try:
                src_ips = self.session.query(Endpoints).filter(Endpoints.ip ==
                                                               flow[x].src_ip).all()
                self.session.close()
            except:
                self.logger.error('Failed to query DB while corelating a flow '
                                  'to endpoints.')
            if len(src_ips) == 1:
                src_epg = src_ips[0].dn
            elif len(src_ips) > 1:
                for i in src_ips:
                    self.logger.debug('Source IP address: %s matches multiple '
                                      'EPGs: %s' % (flow[x].src_ip, i.dn))
                for i in src_ips:
                    if i.dn[-17:].lower() == src_mac:
                        src_epg = i.dn
                        break
                    else:
                        src_epg = 'Multiple EGPs matching MAC/IP.'
            else:
                self.logger.debug('Failed to match source IP: %s to any EPG in'
                                  ' the fabric' % (flow[x].dst_ip))
                src_epg = 'unkown'

            dst_mac = flow[x].dst_mac.strip('\n').strip('')
            try:
                dst_ips = self.session.query(Endpoints).filter(Endpoints.ip ==
                                                               flow[x].dst_ip).all()
                self.session.close()
            except:
                self.logger.error('Failed to query DB while corelating a flow '
                                  'to endpoints.')
            if len(dst_ips) == 1:
                dst_epg = dst_ips[0].dn
            elif len(dst_ips) > 1:
                for i in dst_ips:
                    self.logger.debug('Destination IP address: %s matches mult'
                                      'iple EPGs: %s' % (flow[x].dst_ip, i.dn))
                for i in dst_ips:
                    if i.dn[-17:].lower() == dst_mac:
                        dst_epg = i.dn
                        break
                    else:
                        dst_epg = 'Multiple EGPs matching MAC/IP.'
            # If we got 0 results from our query, then the EPG is unkown
            else:
                self.logger.debug('Failed to match destination IP: %s to any E'
                                  'PG in the fabric' % (flow[x].dst_ip))
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
            self.session.merge(contract)
            self.session.commit()
            self.logger.debug('Created contract entry for flow between the fol'
                              'lowing EPGs:\nSource: %s \nDestination: %s' %
                              (src_epg, dst_epg))
            x += 1

    def clean_tcp_contracts(self):
        tcp_ctrx = self.session.query(Contracts).filter(Contracts.protocol ==
                                                        'tcp').all()
        tcp_ctrx_len = len(tcp_ctrx)
        for x in range(0, tcp_ctrx_len):
            for y in range(0, tcp_ctrx_len):
                if tcp_ctrx[x].src_epg == tcp_ctrx[y].dst_epg:
                    if tcp_ctrx[x].tcp_src == tcp_ctrx[y].tcp_dst:
                        if (int(tcp_ctrx[x].tcp_src) > 1024 and
                                int(tcp_ctrx[y].tcp_src) > 1024):
                            self.logger.debug('Flow with ephemeral ports in bo'
                                              'th source and destination, leav'
                                              'ing in Contracts DB.\nFlow #1:'
                                              '\nSource: %s:%s\nDestination: '
                                              '%s:%s\n Flow #2:\nSource: %s:'
                                              '%s\n Destination: %s:%s' %
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
                                self.logger.debug('Flow with low order source '
                                                  'port. Deleting unnecessary '
                                                  'flow from Contracts DB.\nFl'
                                                  'ow #1:\nSource: %s:%s\nDest'
                                                  'ination: %s:%s\n Flow #2:\n'
                                                  'Source: %s:%s\nDestination:'
                                                  ' %s:%s' %
                                                  (tcp_ctrx[x].src_epg,
                                                   tcp_ctrx[x].tcp_src,
                                                   tcp_ctrx[x].dst_epg,
                                                   tcp_ctrx[x].tcp_dst,
                                                   tcp_ctrx[y].src_epg,
                                                   tcp_ctrx[y].tcp_src,
                                                   tcp_ctrx[y].dst_epg,
                                                   tcp_ctrx[y].tcp_dst))
                                self.session.delete(tcp_ctrx[x])
                                self.session.commit()

    def clean_udp_contracts(self):
        udp_ctrx = self.session.query(Contracts).filter(Contracts.protocol ==
                                                        'udp').all()
        udp_ctrx_len = len(udp_ctrx)
        for x in range(0, udp_ctrx_len):
            for y in range(0, udp_ctrx_len):
                if udp_ctrx[x].src_epg == udp_ctrx[y].dst_epg:
                    if udp_ctrx[x].udp_src == udp_ctrx[y].udp_dst:
                        if (int(udp_ctrx[x].udp_src) > 1024 and
                                int(udp_ctrx[y].udp_src) > 1024):
                            self.logger.debug('Flow with ephemeral ports in bo'
                                              'th source and destination, leav'
                                              'ing in Contracts DB.\nFlow #1:'
                                              '\nSource: %s:%s\nDestination: '
                                              '%s:%s\nFlow #2:\nSource: %s:%s'
                                              '\n Destination: %s:%s' %
                                              (udp_ctrx[x].src_epg,
                                               udp_ctrx[x].udp_src,
                                               udp_ctrx[x].dst_epg,
                                               udp_ctrx[x].udp_dst,
                                               udp_ctrx[y].src_epg,
                                               udp_ctrx[y].udp_src,
                                               udp_ctrx[y].dst_epg,
                                               udp_ctrx[y].udp_dst))
                        else:
                            if (int(udp_ctrx[x].udp_src) < 1025 and
                                    int(udp_ctrx[y].udp_src) > 1024):
                                self.logger.debug('Flow with low order source '
                                                  'port. Deleting unnecessary '
                                                  'flow from Contracts DB.\nFl'
                                                  'ow #1:\nSource: %s:%s\nDest'
                                                  'ination: %s:%s\n Flow #2:\n'
                                                  'Source: %s:%s\n Destination'
                                                  ': %s:%s' %
                                                  (udp_ctrx[x].src_epg,
                                                   udp_ctrx[x].udp_src,
                                                   udp_ctrx[x].dst_epg,
                                                   udp_ctrx[x].udp_dst,
                                                   udp_ctrx[y].src_epg,
                                                   udp_ctrx[y].udp_src,
                                                   udp_ctrx[y].dst_epg,
                                                   udp_ctrx[y].udp_dst))
                                self.session.delete(udp_ctrx[x])
                                self.session.commit()

    # THIS IS SHIT BUT WORKS FOR NOW... Really innefecient, need a way to bulk
    # clear table OR drop table and re-instantiate it (better option)
    def erase_table(self, table):
        all_records = eval("self.session.query(%s).all()" % table)
        for i in all_records:
            self.session.delete(i)
            self.session.commit()

    def show_table(self, table):
        query = eval("self.session.query(%s).all()" % table)
        pt = PrettyTable()
        if table == 'Endpoints':
            pt.field_names = ["DN", "IP", "Last Seen"]
            for row in query:
                pt.add_row([row.dn, row.ip, row.last_seen])
        elif table == 'Flows':
            pt.field_names = ["Source MAC", "Destination MAC", "Source IP",
                              "Destination IP", "Source TCP",
                              "Destination TCP", "Source UDP",
                              "Destination UDP", "Protocol",
                              "Last Seen", "Hits"]
            for row in query:
                pt.add_row([row.src_mac, row.dst_mac, row.src_ip, row.dst_ip,
                            row.tcp_src, row.tcp_dst, row.udp_src, row.udp_dst,
                            row.protocol, row.last_seen, row.hits])
        elif table == 'Contracts':
            pt.field_names = ["Source EPG", "Destination EPG", "Source TCP",
                              "Destination TCP", "Source UDP",
                              "Destination UDP", "Protocol", "Last Seen"]
            for row in query:
                pt.add_row([row.src_epg, row.dst_epg, row.tcp_src, row.tcp_dst,
                            row.udp_src, row.udp_dst, row.protocol,
                            row.last_seen])
        print(pt)

    # This is also shit, but works...
    def export_table(self, table):
        export_file = ('export-%s-%s.csv' %
                       (table, datetime.datetime.now()))
        query = eval("self.session.query(%s).all()" % table)
        query_len = len(query)
        if table == 'Endpoints':
            headings = ["DN", "IP", "Last Seen"]
            with open(export_file, 'w') as f:
                for item in headings:
                    f.write(item)
                    f.write(',')
                f.write('\n')
                for x in range(0, query_len):
                    write_me = ("%s,%s,%s\n" % (query[x].dn,
                                                query[x].ip,
                                                query[x].last_seen,))
                    f.write(write_me)
        elif table == 'Flows':
            headings = ["Source MAC", "Destination MAC", "Source IP",
                        "Destination IP", "Source TCP",
                        "Destination TCP", "Source UDP", "Destination UPD",
                        "Protocol", "Last Seen", "Hits"]
            with open(export_file, 'w') as f:
                for item in headings:
                    f.write(item)
                    f.write(',')
                f.write('\n')
                for x in range(0, query_len):
                    write_me = ("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %
                                (query[x].src_mac,
                                 query[x].dst_mac,
                                 query[x].src_ip,
                                 query[x].src_ip,
                                 query[x].tcp_src,
                                 query[x].tcp_dst,
                                 query[x].udp_src,
                                 query[x].udp_dst,
                                 query[x].protocol,
                                 query[x].last_seen,
                                 query[x].hits))
                    f.write(write_me)
        elif table == 'Contracts':
            headings = ["Source EPG", "Destination EPG", "Source TCP",
                        "Destination TCP", "Source UDP",
                        "Destination UDP", "Protocol", "Last Seen"]
            with open(export_file, 'w') as f:
                for item in headings:
                    f.write(item)
                    f.write(',')
                f.write('\n')
                for x in range(0, query_len):
                    write_me = ("%s,%s,%s,%s,%s,%s,%s,%s\n" %
                                (query[x].src_epg,
                                 query[x].dst_epg,
                                 query[x].tcp_src,
                                 query[x].tcp_dst,
                                 query[x].udp_src,
                                 query[x].udp_dst,
                                 query[x].protocol,
                                 query[x].last_seen))
                    f.write(write_me)
