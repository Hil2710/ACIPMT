# import subprocess to exec tshark commands
import subprocess
# import os to remove files when done
import os
import dbfunc


# function to start tshark
def tshark_process(tun_name, duration, cycle, logger):
    # capture on 'mon0' interface (gre tunnel)
    tshark_int = '%s' % tun_name
    tshark_output = 'capture-%s.pcapng' % cycle
    tshark_duration = 'duration:%s' % duration
    # tshark cli to begin capture
    tshark_run = ('runuser -l acipmt -c '
                  '"tshark -o erspan.fake_erspan:TRUE -i %s -n -w %s -a %s"'
                  % (tshark_int, tshark_output, tshark_duration))
    p = subprocess.Popen(tshark_run, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    for line in p.stderr:
        print(line)
    p.wait()
    logger.debug('TShark process for cycle "%s" complete.' % (cycle))


# function to convert pcapng -> csv for easy parsing
def tshark_convert(session, cycle, logger):
    tshark_output = 'capture-%s.pcapng' % cycle
    tshark_csvoutput = 'capture-%s.csv' % cycle
    if os.path.isfile(tshark_output):
        tshark_csvrun = ('runuser -l acipmt -c '
                         '"tshark -o erspan.fake_erspan:TRUE -r %s -n '
                         '-T fields -E separator=, -e eth.src -e eth.dst '
                         '-e ip.src -e ip.dst '
                         '-e tcp.srcport -e tcp.dstport '
                         '-e udp.srcport -e udp.dstport '
                         '-e ip.proto > %s"' %
                         (tshark_output, tshark_csvoutput))
        p = subprocess.Popen(tshark_csvrun, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        for line in p.stderr:
            print(line)
        p.wait()
        logger.debug('TShark convert for cycle "%s" complete.' % (cycle))
        dbfunc.csv_to_db(session, cycle, logger)
        logger.debug('Completed processing for cycle "%s" and adding to DB.'
                     % (cycle))
    else:
        pass


def tshark_clean(total_cycles, logger):
    while total_cycles > 0:
        if os.path.isfile('capture-%s.pcapng' % (str(total_cycles))):
            logger.debug('Removing file "capture-%s.pcapng"' %
                         (str(total_cycles)))
            os.remove('capture-%s.pcapng' % (str(total_cycles)))
        if os.path.isfile('capture-%s.csv' % (str(total_cycles))):
            logger.debug('Removing file "capture-%s.csv"' %
                         (str(total_cycles)))
            os.remove('capture-%s.csv' % (str(total_cycles)))
        total_cycles -= 1
