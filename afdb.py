import sqlite3


_author_ = 'Michael Clark'
_project_ = 'Safe Networking'


conn = sqlite3.connect('sfnportal.db')
cur = conn.cursor()

try:
    cur.execute(
        """CREATE TABLE IF NOT EXISTS afzoom('Source address', 'Destination address', 'Time Logged', 'Repeat Count', 'Destination Port', 'Threat/Content Name', 'Severity', 'Destination Country')""")
    conn.commit()
    print ("FoCuZing")

    cur.execute(
        'INSERT INTO afzoom select "Source address", "Destination address", "Time Logged", "Repeat Count", "Destination Port", "Threat/Content Name", "Severity", "Destination Country" from sfn2dnsthreatname group by "Threat/Content Name" ')
    conn.commit()
    print "Ready"

except:
        conn.rollback()
        conn.commit()

        conn.close()