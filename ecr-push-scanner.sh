#!/bin/bash

# ./ecr-push-scan.sh 272208797173  eu-west-1 vulnerable/powersploit:latest

AWS_ACCOUNT=$1
AWS_REGION=$2
FULL_IMAGE_NAME=$3
arrIN=(${FULL_IMAGE_NAME//:/ })
echo $FULL_IMAGE_NAME
AWS_ECR_REPO=${arrIN[0]}
BUILD_TAG=${arrIN[1]}
echo image name $AWS_ECR_REPO
echo image tag $BUILD_TAG
rm -f ecr.json
aws ecr describe-repositories --repository-names ${AWS_ECR_REPO}  --region ${AWS_REGION}  || aws ecr create-repository --repository-name ${AWS_ECR_REPO} --image-scanning-configuration scanOnPush=true --region ${AWS_REGION}
docker tag $AWS_ECR_REPO:$BUILD_TAG $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPO:$BUILD_TAG
aws ecr get-login-password --region $AWS_REGION   | \
docker login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com && \
docker push $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/$AWS_ECR_REPO:$BUILD_TAG && \
aws ecr wait image-scan-complete                		\
	--repository-name $AWS_ECR_REPO						\
	--image-id imageTag=$BUILD_TAG  					\
	--region $AWS_REGION && 							\
VULNS=$(aws ecr describe-image-scan-findings 			\
	--repository-name $AWS_ECR_REPO 					\
	--image-id imageTag=$BUILD_TAG 						\
	--region $AWS_REGION  								\
	--query imageScanFindings                        	\
	--output json)

echo $VULNS > ecr.json
echo results saved in ecr.json

