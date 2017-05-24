FROM python:2.7         
ADD . /snPortal
WORKDIR /snPortal
EXPOSE 8888
EXPOSE 5432
#RUN apt-get install unixodbc unixodbc-dev
RUN apt-get update && apt-get install -y locales unixodbc libgss3 odbcinst devscripts debhelper dh-exec dh-autoreconf libreadline-dev libltdl-dev unixodbc-dev wget unzip
RUN pip install psycopg2
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "SafeNetworkingProject.py"]
MAINTAINER Michael Clark "miclark@paloaltonetworks.com"
