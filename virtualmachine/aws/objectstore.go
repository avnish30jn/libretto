package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
)

func GetS3BucketsList() ([]string, error) {
	// 1. Get s3 service client
	// 2. Fetch the list
	var bucketList []string
	s3Svc, err := getS3Client("us-east-1")
	if err != nil {
		fmt.Errorf("Failed to create s3 client")
		return bucketList, err
	}

	result, err := s3Svc.ListBuckets(nil)
	if err != nil {
		fmt.Errorf("Failed in fetching the bucket list: %v", err)
		return bucketList, err
	}

	for _, b := range result.Buckets {
		bucketList = append(bucketList, aws.StringValue(b.Name))
	}

	return bucketList, nil
}
