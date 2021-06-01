FROM python:3.8-slim

RUN mkdir -p var/www/app
RUN cd var/www/app
RUN groupadd -r lirantal && useradd -r -s /bin/false -g lirantal lirantal
WORKDIR var/www/app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN chown -R lirantal:lirantal /var/www/app
USER lirantal
COPY . .
