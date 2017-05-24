import sqlite3
import jinja2
import os
from jinja2 import Template
from jinjasql import JinjaSql
j = JinjaSql()
sqlite3.get_engine(current_app, bind='<your_bind>').execute('<your raw sql>')
conn = sqlite3.connect('sfn.db')
cur = conn.cursor()
conn.text_factory = str

latex_jinja_env = jinja2.Environment(
    block_start_string = '\BLOCK{',
    block_end_string = '}',
    variable_start_string = '\VAR{',
    variable_end_string = '}',
    comment_start_string = '\#{',
    comment_end_string = '}',
    line_statement_prefix = '%-',
    line_comment_prefix = '%#',
    trim_blocks = True,
    autoescape = False,
    loader = jinja2.FileSystemLoader(os.path.abspath('.'))
)


# Modify to specify the template
template = latex_jinja_env.get_template('test1.tex')


col_names = [cn[0] for cn in cur.description]
rows = cur.fetchall()
conn.close()

for row in rows:
    thedict=dict(zip(col_names,row))
    filename='zzpuma_' + row[0] + '.tex'
    folder='test3'
    outpath=os.path.join(folder,filename)
    outfile=open(outpath,'w')
    outfile.write(template.render(d=thedict))
    outfile.close()
    os.system("pdflatex -output-directory=" + folder + " " + outpath)

