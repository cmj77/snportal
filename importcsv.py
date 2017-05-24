import sqlite3
import csv

_author_ = 'Michael Clark'
_project_ = 'Safe Networking'


def main():

    class csvrd(object):
        def csvFile(self):

            self.readFile('/Users/miclark/Downloads/safenetworking/3dDNSalerts.csv')

        def readFile(self, filename):
            conn = sqlite3.connect('sfnportal.db')
            cur = conn.cursor()
            conn.text_factory = str
            cur.execute(
                """CREATE TABLE IF NOT EXISTS sfnevents('Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type', 'Config Version', 'Generate Time', 'Source address', 'Destination address', 'NAT Source IP', 'NAT Destination IP', 'Rule', 'Source User', 'Destination User', 'Application', 'Virtual System', 'Source Zone', 'Destination Zone', 'Inbound Interface', 'Outbound Interface', 'Log Action', 'Time Logged', 'Session ID', 'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port', 'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL', 'Threat/Content Name', 'Category', 'Severity', 'Direction', 'seqno', 'actionflags', 'Source Country', 'Destination Country', 'cpadding', 'contenttype', 'pcap_id', 'filedigest', 'cloud', 'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 'subject','recipient', 'reportid','dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_nam', 'file_url')""")
            filename.encode('utf-8')
            print "Safe Networking"
            with open(filename) as f:
                reader = csv.reader(f)
                for field in reader:
                    cur.execute("INSERT INTO sfnevents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", field)

            conn.commit()
            conn.close()


    c = csvrd().csvFile()

if __name__ == "__main__":
    main()

print "Safe Networking Eats CSV"
