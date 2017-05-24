from flask import Flask
import csv
import StringIO
from flask import Flask, render_template
from jinja2 import Template
import psycopg2
from flask import Flask, jsonify
from flask import abort
from flask import request
from flask import Flask, make_response
from flask import Flask, Response
# from flask_restful import Resource, Api, reqparse
import pygal
from pygal.style import CleanStyle

app = Flask(__name__)

ingesters = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol',
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web',
        'done': False
    }
]


@app.route('/todo/api/v1.0/ingesters', methods=['GET'])
def get_ingester():
    return jsonify({'ingester': ingester})


@app.route('/todo/api/v1.0/ingesters/<int:ingester_id>', methods=['GET'])
def get_injester(ingester_id):
    ingester = [ingester for ingester in ingesters if ingester['id'] == ingester_id]
    if len(ingester) == 0:
        abort(404)
    return jsonify({'ingester': ingester[0]})


@app.route('/todo/api/v1.0/ingesters', methods=['POST'])
def create_injester():
    if not request.json or not 'title' in request.json:
        abort(400)
    ingester = {
        'id': ingesters[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    ingesters.append(ingester)
    return jsonify({'ingester': ingester}), 201
    print(ingesters)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('home'))
    return render_template('login.html', error=error)

@app.route("/")
def template_test():
    return render_template('index.html', name=template_test)


# @app.route('/')
# def hello_world():
#    return render_template('index.htm.html', name=ServiceProviderSolutions)




@app.route('/list')
def list():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    conn.row_factory = psycopg2.Row

    cur = conn.cursor()
    cur.execute(
        'SELECT "source address", "Destination address", "Time Logged", "ThreatType", "Threat/Content Name", "Severity", "Destination Country", "Threatname" FROM sfn2dnsthreatname')
    rows = cur.fetchall();
    conn.close()
    return render_template("list.html", rows=rows)


@app.route('/android')
def androidreport():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    t = ('Android APK',)
    cur = conn.cursor()
    cur.execute('SELECT create_date, filetype, domain, md5, size FROM afq WHERE filetype =?', t)
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("android.html", rows=rows)


@app.route('/botnet')
def botreport():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
    cur.execute('SELECT * FROM sfn2dnsthreatname WHERE "Destination Port" <> "53"')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("botnet.html", rows=rows)


@app.route('/srchits')
def srchits():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
#   conn.row_factory = psycopg2.Row

    cur = conn.cursor()
    cur.execute('''select "Source address", count("Source address") from sn1dnsevents group by "Source address" ORDER BY 2 DESC''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("srchits.html", rows=rows)



@app.route('/srcipreport')
@app.route('/srcipreport/<int:page>')
def srcipreport_paginated(page=1):
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
    offset = (page-1) * 50 # 50 is the page size
    if offset < 0:
      offset = 0
    cur.execute('''
        SELECT Distinct sn1dnsthreatname."Source address", sn1dnsthreatname."ThreatType", afqsn.tag, sn1dnsthreatname."Threat/Content Name", sn1dnsthreatname."Time Logged" FROM sn1dnsthreatname inner join afqsn on sn1dnsthreatname."Threat/Content Name" = afqsn.domain order by "Time Logged" desc offset %s limit 50''' % (offset))
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("srcipreport.html", rows=rows, page=page)

@app.route('/srcipreporttelus')
def srcipreporttelus():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')

    cur = conn.cursor()
    cur.execute('''
        SELECT Distinct sn1dnsthreatname."Source address", sn1dnsthreatname."ThreatType", afqsn.tag, sn1dnsthreatname."Threat/Content Name", sn1dnsthreatname."Time Logged" FROM sn1dnsthreatname inner join afqsn on sn1dnsthreatname."Threat/Content Name" = afqsn.domain''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("srcipreporttelus.html", rows=rows)


@app.route('/chart1')
def test():
    bar_chart = pygal.HorizontalStackedBar()
    bar_chart.title = "Remarquable sequences"
    bar_chart.x_labels = map(str, range(11))
    bar_chart.add('Fibonacci', [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55])
    bar_chart.add('Padovan', [1, 1, 1, 2, 2, 3, 4, 5, 7, 9, 12])
    chart = bar_chart.render(is_unicode=True)
    return render_template('chart.html', chart=chart)


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":
        conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
        conn.row_factory = psycopg2.Row
        cur = conn.cursor()
        cur.execute('select * from afq inner join artifact on afq._id = artifact.id')
        rows = cur.fetchall();
        cur.executemany('''select * from artifact where domain = %s''', request.form['search'])
        for r in cur.fetchall():
            print r[0], r[1], r[2]
            return redirect(url_for('search'))
    return render_template('search.html')


# @app.route('/chart/')

# def Pie_route():
#    conn = psycopg2.connect('sfnportal.db')
#    cur = conn.cursor()

#    cur.execute('''
#    SELECT
#    sum(CASE WHEN filetype="Apple DMG" THEN 1 ELSE 0 END) 'Apple DMG',
#    sum(CASE WHEN filetype="Android APK" THEN 1 ELSE 0 END) 'Android APK',
#    sum(CASE WHEN filetype="DLL" THEN 1 ELSE 0 END) 'DLL',
#    sum(CASE WHEN filetype="PE64" THEN 1 ELSE 0 END) 'PE64',
#    sum(CASE WHEN filetype="PE" THEN 1 ELSE 0 END) 'PE'
#    from afq
#    ''')
#    for row in cur:
#        print row
#	chart = pygal.Pie(width=150,height=150)
#        pie_chart = pygal.Pie(style=CleanStyle,width=400,height=200)
#        pie_chart.title = 'Malware by Filetype Count(c)'
#        pie_chart.add('APK c = %s' % row[1], [{'value': row[1], 'label': 'Android APK'}])
#        pie_chart.add('DMG c = %s' % row[0], [{'value': row[0], 'label': 'Apple DMG'}])
#        pie_chart.add('PE c = %s' % row[4], [{'value': row[4], 'label': 'Windows PE'}])
#        pie_chart.add('PE64 c = %s' % row[3], [{'value': row[3], 'label': 'Windows 64bit PE64'}])
#        pie_chart.add('DLL c = %s' % row[2], [{'value': row[2], 'label': 'Windows DLL'}])
#        chart = pie_chart.render(is_unicode=True)

#        return render_template('filetype.html', chart=chart)

@app.route('/exportcsv/', methods=['GET'])
def exportcsv():
    si = StringIO.StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
    cur.execute(
        'select "Source address", count("Source address") from telus1dnsevents group by "Source address" ORDER BY 2 DESC;')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=srciphits.csv'
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/exportcsvsrcipmalwarecat/', methods=['GET'])
def exportcsvsrcipmalwarecat():
    si = StringIO.StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='postgres', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
    cur = conn.cursor()
    cur.execute(
        'SELECT Distinct telus1dnsthreatname."Source address", telus1dnsthreatname.ThreatType, afqtelus.tag, telus1dnsthreatname."Threat/Content Name", telus1dnsthreatname."Time Logged" FROM telus1dnsthreatname inner join afqtelus on telus1dnsthreatname."Threat/Content Name" = afqtelus.domain')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=srcipwmalwarecategory.csv'
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/exportcsvfiletype/', methods=['GET'])
def exportcsvfiletype():
    si = StringIO.StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
    cur.execute('''
    SELECT
    sum(CASE WHEN filetype="Apple DMG" THEN 1 ELSE 0 END) 'Apple DMG',
    sum(CASE WHEN filetype="Android APK" THEN 1 ELSE 0 END) 'Android APK',
    sum(CASE WHEN filetype="DLL" THEN 1 ELSE 0 END) 'DLL',
    sum(CASE WHEN filetype="PE64" THEN 1 ELSE 0 END) 'PE64',
    sum(CASE WHEN filetype="PE" THEN 1 ELSE 0 END) 'PE'
    from afqtelus
    ''')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=malwarefiletype.csv'
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/TopDomains')
def TopDomains():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()

    cur.execute(
        '''select "Threat/Content Name", count("Threat/Content Name") from telus1dnsevents group by "Threat/Content Name" ORDER BY 2 DESC LIMIT 10''')
    bar1 = int(raw_input(" '%s' % row[1]"))
    #    bar2 =
    #    bar3 =
    #    bar4 =
    #    bar5 =
    for row in cur:
        print row
        #        line_chart = pygal.HorizontalBar()
        #        line_chart.title = 'Browser usage in February 2012 (in %)'
        #        line_chart.add('IE', 19.5)
        #        line_chart.add('Firefox', 36.6)
        #        line_chart.add('Chrome', 36.3)
        #        line_chart.add('Safari', 4.5)
        #        line_chart.add('Opera', 2.3)
        #        line_chart.render(is_unicode=True)
        line_chart = pygal.HorizontalBar()
        line_chart.title = 'Top 10 Domains (by hits)'
        line_chart.add('%s' % row[0], 8000)
        line_chart.add('%s' % row[0][0], 7000)
        line_chart.add('%s' % row[0], 6000)
        line_chart.add('%s' % row[0], [bar1])
        #        line_chart.add(dom '%s' % row[0], 2.3)
        #        line_chart.add(dom '%s' % row[0], 19.5)
        #        line_chart.add(dom '%s' % row[0], 36.6)
        #        line_chart.add(dom '%s' % row[0], 36.3)
        #        line_chart.add(dom '%s' % row[0], 4.5)
        #        line_chart.add(dom '%s' % row[0], 2.3)
        chart = line_chart.render(is_unicode=True)
        return render_template('TopDomains.html', chart=chart)


@app.route('/funnel/')
def Pie_route():
    
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()
   
    cur.execute('''
    SELECT filetype, count(*) as count from afqsn group by filetype
    ''')
    rows = cur.fetchall()
    print(rows)
    
    chart = pygal.Pie()
    pie_chart = pygal.Pie(width=800,height=600,truncate_legend=-1)
    
    pie_chart.title = 'Malware by Filetype Count'
    for row in rows:
        print row
        pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
    chart = pie_chart.render(is_unicode=True)

    return render_template('funnel.html', chart=chart)


@app.route('/malwarefamily/')
def malwarefamily():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='localhost', password='safeNETWORKING123!@#')
    cur = conn.cursor()

    cur.execute('''select "tag", count("tag") from afqsn where "tag" is not null group by "tag" ORDER BY 2 DESC''')

    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("malwarefamilyhits.html", rows=rows)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8888, debug=True)
