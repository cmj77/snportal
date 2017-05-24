import sqlite3
import csv

_author_ = 'Michael Clark'
_project_ = 'Safe Networking'

conn = sqlite3.connect('sfnportal.db')
cur = conn.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS sfn2dnsevents('Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type', 'Config Version', 'Generate Time', 'Source address', 'Destination address', 'NAT Source IP', 'NAT Destination IP', 'Rule', 'Source User', 'Destination User', 'Application', 'Virtual System', 'Source Zone', 'Destination Zone', 'Inbound Interface', 'Outbound Interface', 'Log Action', 'Time Logged', 'Session ID', 'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port', 'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL', 'Threat/Content Name', 'Category', 'Severity', 'Direction', 'seqno', 'actionflags', 'Source Country', 'Destination Country', 'cpadding', 'contenttype', 'pcap_id', 'filedigest', 'cloud', 'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 'subject','recipient', 'reportid','dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_nam', 'file_url')""")
conn.commit()
print ("DNS Events Created")
cur.execute(
    """CREATE TABLE IF NOT EXISTS sfn2dnsthreatname('Source address', 'Destination address', 'Time Logged', 'Repeat Count', 'Destination Port', 'ThreatType', 'Threat/Content Name', 'Severity', 'Destination Country')"""
)
conn.commit()
conn.close()
print ("DNS Threatname Created")

conn = sqlite3.connect('sfnportal.db')
cur = conn.cursor()
cur.execute(
    "INSERT INTO 'sfn2dnsevents' SELECT * FROM sfnevents WHERE application='dns' " )
conn.commit()
cur.execute(
    "INSERT INTO sfn2dnsthreatname SELECT 'Source address', 'Destination address', 'Time Logged', 'Repeat Count', 'Destination Port', 'ThreatType', 'Threat/Content Name', 'Severity', 'Destination Country' FROM sfn2dnsevents GROUP BY 'Threat/Content Name' " )

conn.commit()
conn.close()
print "Extraction & Triage Successful"
