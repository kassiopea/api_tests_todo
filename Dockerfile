FROM python:3.8-slim
#FROM ubuntu:latest
#
#RUN apt-get update && \
#    apt-get install --no-install-recommends -y \
#    python3.8 python3-pip python3.8-dev
RUN mkdir -p var/www/app
RUN cd var/www/app
#RUN groupadd -r tester && useradd -r -s /bin/false -g tester tester
WORKDIR var/www/app
COPY requirements.txt .
RUN pip install -r requirements.txt
#RUN chown -R tester:tester /var/www/app
#USER tester
COPY . .
#CMD ["/var/www/app/entrypoint.sh"]
