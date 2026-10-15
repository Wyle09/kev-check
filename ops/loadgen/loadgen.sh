#!/bin/sh
# Each request takes a random line from ids.txt and opens a new connection, so Docker
# DNS spreads the traffic across every app container.
while true; do
  id=$(shuf -n 1 /loadgen/ids.txt)
  curl -s -o /dev/null --max-time 5 "http://app:4000/process?id=$id"
  sleep 0.1
done
