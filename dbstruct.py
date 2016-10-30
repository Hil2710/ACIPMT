from sqlalchemy import Column, DateTime, String, Integer, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


# Endpoints table;
# dn = distinguished name in ACI
# ip = IP address as seen by ACI
# last_seen = the time the flow was last seen, this is
# 	essentially the current time for each merge
class Endpoints(Base):
    __tablename__ = 'endpoints'
    dn = Column(String(100), primary_key=True)
    ip = Column(String(15))
    last_seen = Column(DateTime, default=func.now())


# Flows table;
# src_ip = source ip of the flow
# dst_ip = destination ip of the flow
# udp_dst = destination UDP port, or 0 for default
# tcp_dst = destination TCP port, or 0 for default
# protocol = protocol of the flow
# last_seen = the time the flow was last seen, this is
# 	essentially the current time for each merge
# hits = integer to be incremented as the flow is seen
class Flows(Base):
    __tablename__ = 'flows'
    src_ip = Column(String(15), primary_key=True)
    dst_ip = Column(String(15), primary_key=True)
    tcp_src = Column(String(5), default=0)
    tcp_dst = Column(String(5), primary_key=True, default=0)
    udp_src = Column(String(5), default=0)
    udp_dst = Column(String(5), primary_key=True, default=0)
    protocol = Column(String(50), primary_key=True)
    last_seen = Column(DateTime, default=func.now())
    hits = Column(Integer, default=0)


# Contracts table;
# src_epg = source epg of the flow
# dst_epg = destination epg of the flow
# udp_dst = destination UDP port, or 0 for default
# tcp_dst = destination TCP port, or 0 for default
# protocol = protocol of the flow
# last_seen = the time the flow was last seen, this is
# 	essentially the current time for each merge
# NOTE: for some reason wouldnt take string of 255
#	(should be max VARCHAR size), 100 is probably too
#	short for some EPGs...
class Contracts(Base):
    __tablename__ = 'contracts'
    src_epg = Column(String(100), primary_key=True)
    dst_epg = Column(String(100), primary_key=True)
    tcp_src = Column(String(5), default=0)
    tcp_dst = Column(String(5), primary_key=True, default=0)
    udp_src = Column(String(5), default=0)
    udp_dst = Column(String(5), primary_key=True, default=0)
    protocol = Column(String(50), primary_key=True)
    last_seen = Column(DateTime, default=func.now())


engine = create_engine('mysql://acipmt:password@localhost/acipmt')
session = sessionmaker()
session.configure(bind=engine)
Base.metadata.create_all(engine)
