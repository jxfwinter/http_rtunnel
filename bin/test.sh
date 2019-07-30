#!/bin/bash

curl -v -H 'JR-SID: test9955' -X POST --data '{"message": "sunshine"}' http://192.168.181.121:4080
curl -v -H 'JR-SID: test9955' -X POST --data '{"message": "sunshine"}' https://192.168.181.121:4443