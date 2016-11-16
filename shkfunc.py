import quit
import subprocess
import os
from collections import Counter


class SHKsetup(object):
    def __init__(self, logger):
        self.logger = logger
        logger.debug('SHKsetup class initialized.')

    def shark_values_from_setup(self, setup_obj):
        section = 'TSHARK'
        section_options = ['prompt', 'duration']
        (section_true, setup_dict) = setup_obj.values(section, section_options)
        if section_true is True:
            self.logger.debug('\'shark_values_from_setup\' method loaded.')
            self.tshark_prompt = setup_dict['prompt']
            self.duration = setup_dict['duration']
            self.logger.debug('Setup file has the following values for TSHARK '
                              'section:\n\tDuration = %s' % (self.duration))
            if self.tshark_prompt == 'yes':
                self.logger.debug('Setup file values for TSHARK, but prompt is'
                                  ' set to "yes".')
                return False
            else:
                duration = self.duration[:-1]
                duration = int(duration)
                self.duration_to_seconds(duration)
                return True
        else:
            self.duration = '1m'
            self.logger.error('Setup file has errors for TSHARK section.')
            return False

    def shark_values_from_user(self):
        while True:
            print('In seconds (s), minutes (m), hours (h), or days (d), how lo'
                  'ng would you like the SPAN to run?')
            duration = input("Enter your selection (i.e. 1s, 5m, 10h or 1d): ")
            self.duration = duration or self.duration
            quit.quit(self.logger, self.duration)
            try:
                if (self.duration[-1] == 's' or self.duration[-1] == 'm' or
                        self.duration[-1] == 'h' or self.duration[-1] == 'd'):
                    try:
                        duration = self.duration[:-1]
                        duration = int(duration)
                        break
                    except:
                        self.logger.error('User entered "%s" please enter a va'
                                          'lid integer before time suffix, or '
                                          'type "quit".' % (self.duration))
                else:
                    self.logger.error('User entered "%s" please enter a vlid t'
                                      'ime suffix, (i.e. "s", "m", "h", or "d"'
                                      '), or type "quit".' % (self.duration))
            except:
                self.logger.error('User entered "%s" -- please enter a valid e'
                                  'ntry for Tshark duration.' %
                                  (self.duration))
            self.duration_to_seconds(duration)

    def duration_to_seconds(self, duration):
        if self.duration[-1] == 's':
            self.duration = duration
        elif self.duration[-1] == 'm':
            self.duration = duration * 60
        elif self.duration[-1] == 'h':
            self.duration = duration * 60 * 60
        elif self.duration[-1] == 'd':
            self.duration = duration * 60 * 60 * 24
        self.logger.debug('Tshark duration set to %s seconds' %
                          (self.duration))

    def run_shark(self, tun_name):
        if self.duration < 120:
            duration = self.duration
            self.cycle = 1
            self.logger.debug('TShark duration less than 120 seconds, beginnin'
                              'g single TShark capture.')
            self.shark_capture(tun_name, duration)
        else:
            self.logger.debug('TShark duration is over 120 seconds. Beginning '
                              'cycle of TShark captures.')
            self.cycle = 1
            while self.duration > 0:
                if self.duration - 60 >= 0:
                    duration = 60
                    self.duration = self.duration - 60
                else:
                    duration = self.duration
                    self.duration = self.duration - self.duration
                self.logger.debug('Begin TShark process for cycle "%s".' %
                                  (str(self.cycle)))
                self.shark_capture(tun_name, duration)
                self.cycle += 1
        self.total_cycles = int(self.cycle)
        return(self.total_cycles)

    def shark_capture(self, tun_name, duration):
        tshark_int = '%s' % tun_name
        tshark_output = 'capture-%s.pcapng' % self.cycle
        tshark_duration = 'duration:%s' % duration
        tshark_run = ('runuser -l acipmt -c "tshark -o erspan.fake_erspan:TRUE'
                      ' -i %s -n -w %s -a %s"' %
                      (tshark_int, tshark_output, tshark_duration))
        p = subprocess.Popen(tshark_run, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, shell=True)
        for line in p.stderr:
            print(line)
        p.wait()
        self.logger.debug('TShark process for cycle "%s" complete.' %
                          (self.cycle))

    # NEEDS CLEANUP
    def shark_convert(self):
        while self.cycle > 0:
            tshark_output = 'capture-%s.pcapng' % self.cycle
            tshark_csvoutput = 'capture-%s.csv' % self.cycle
            if os.path.isfile(tshark_output):
                tshark_csvrun = ('runuser -l acipmt -c '
                                 '"tshark -o erspan.fake_erspan:TRUE -r %s -n '
                                 '-T fields -E separator=, -e eth.src '
                                 '-e eth.dst  -e ip.src -e ip.dst '
                                 '-e tcp.srcport -e tcp.dstport '
                                 '-e udp.srcport -e udp.dstport '
                                 '-e ip.proto > %s"' %
                                 (tshark_output, tshark_csvoutput))
                p = subprocess.Popen(tshark_csvrun, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, shell=True)
                for line in p.stderr:
                    print(line)
                p.wait()
                self.logger.debug('TShark convert for cycle "%s" complete.' %
                                  (self.cycle))
                self.cycle -= 1
            else:
                self.cycle -= 1
                pass

    def shark_clean(self):
        cycle = self.total_cycles
        while cycle > 0:
            if os.path.isfile('capture-%s.pcapng' % (str(self.total_cycles))):
                self.logger.debug('Removing file "capture-%s.pcapng"' %
                                  (str(self.total_cycles)))
                os.remove('capture-%s.pcapng' % (str(self.total_cycles)))
            if os.path.isfile('capture-%s.csv' % (str(self.total_cycles))):
                self.logger.debug('Removing file "capture-%s.csv"' %
                                  (str(self.total_cycles)))
                os.remove('capture-%s.csv' % (str(self.total_cycles)))
            cycle -= 1

    def shark_dedupe_csv(self):
        cycle = self.total_cycles
        while cycle > 0:
            entries = []
            capfile = ('capture-%s.csv' % (cycle))
            self.logger.critical('capture-%s.csv being deduplicated.' %
                                 (cycle))
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
            self.logger.debug('capture-%s.csv deduplicated, consolidated %s li'
                              'nes.' % (cycle, lines_removed))
            cycle -= 1
