#!/bin/bash

EPOCH=$(date +%s)

docker build -t 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:latest .
docker push 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:latest

docker build -t 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:$EPOCH .
docker push 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:$EPOCH
