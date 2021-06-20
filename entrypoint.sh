#!/bin/sh

echo "Waiting for mongodb..."

while ! nc -z todo_list_api -db 27017; do
  sleep 0.1
done

echo "Mongodb started"