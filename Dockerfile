FROM python:3.8-slim
RUN mkdir -p var/www/app && cd var/www/app
#RUN cd var/www/app
RUN groupadd -r tester && useradd -r -s /bin/false -g tester tester
WORKDIR var/www/app
COPY requirements.txt .
RUN pip install -r requirements.txt && chown -R tester:tester /var/www/app
#RUN chown -R tester:tester /var/www/app
USER tester
COPY . .
