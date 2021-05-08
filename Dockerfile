FROM python:3.8-slim

RUN mkdir -p var/www/app
RUN cd var/www/app
WORKDIR var/www/app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
