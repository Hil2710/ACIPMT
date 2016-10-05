# import subprocess to exec tshark commands
import subprocess
# import os to remove files when done
import os
import dbfunc


# function to start tshark
def tshark_process(tun_name, duration, cycle):
    # capture on 'mon0' interface (gre tunnel)
    tshark_int = '%s' % tun_name
    tshark_output = 'capture-%s.pcapng' % cycle
    tshark_duration = 'duration:%s' % duration
    # tshark cli to begin capture
    tshark_run = ('runuser -l acipmt -c "tshark -o erspan.fake_erspan:TRUE -i %s -n -w %s -a %s"' % (tshark_int, tshark_output, tshark_duration))
    p = subprocess.Popen(tshark_run, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    for line in p.stderr:
        print(line)
    p.wait()


# function to convert pcapng -> csv for easy parsing
def tshark_convert(session, convert_cycle):
    tshark_output = 'capture-%s.pcapng' % convert_cycle
    tshark_csvoutput = 'capture-%s.csv' % convert_cycle
    tshark_separator = ','
    tshark_out_fields = ['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ip.proto']
    if os.path.isfile(tshark_output):
        tshark_csvrun = ('runuser -l acipmt -c "tshark -o erspan.fake_erspan:TRUE -r %s -n -T fields -E separator=, -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.proto > %s"' % (tshark_output, tshark_csvoutput))
        p = subprocess.Popen(tshark_csvrun, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        for line in p.stderr:
            print(line)
        p.wait()
        dbfunc.csv_to_db(session, convert_cycle)
        print("Completed processing and adding to DB.")
    else:
        pass


def tshark_clean():
    if os.path.isfile('capture-a.pcapng'):
        os.remove('capture-a.pcapng')
    if os.path.isfile('capture-b.pcapng'):
        os.remove('capture-b.pcapng')
    if os.path.isfile('capture-a.csv'):
        os.remove('capture-a.csv')
    if os.path.isfile('capture-b.csv'):
        os.remove('capture-b.csv')
