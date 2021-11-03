#!/bin/bash

EPOCH=$(date +%s)

docker build -t 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:latest .
docker push 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:latest

docker build -t 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:$EPOCH .
docker push 722747748666.dkr.ecr.ap-southeast-1.amazonaws.com/notarise-mockpass:$EPOCH

aws ecs update-service --cluster notarise-mockpass --service arn:aws:ecs:ap-southeast-1:722747748666:service/notarise-mockpass/notarise-mockpass-service --force-new-deployment