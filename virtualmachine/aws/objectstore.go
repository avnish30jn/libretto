package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3 struct {
	Name   string // required
	Region string // required
	Prefix string // for creating a bucket /obj1/obj2/obj3
	// TODO Add support for user details
}

func (s *S3) GetS3BucketsList() ([]string, error) {
	// 1. Get s3 service client
	// 2. Fetch the list
	var bucketList []string

	region := s.Region
	if region == "" {
		region = getRegionFromEnv()
	}

	s3Svc, err := getS3Client(region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client")
		return bucketList, aoerr
	}

	result, err := s3Svc.ListBuckets(nil)
	if err != nil {
		aoerr := fmt.Errorf("Failed in fetching the bucket list: %v", err)
		return bucketList, aoerr
	}

	for _, b := range result.Buckets {
		bucketList = append(bucketList, aws.StringValue(b.Name))
	}

	return bucketList, nil
}

func (s *S3) CreateBucket() error {

	region := s.Region
	if region == "" {
		region = getRegionFromEnv()
	}

	svc, err := getS3Client(region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client")
		return aoerr
	}

	s3Input := new(s3.CreateBucketInput)
	s3Input.Bucket = aws.String(s.Name)

	if region != "us-east-1" {
		s3Input.CreateBucketConfiguration.LocationConstraint = aws.String(s.Region)
	}

	_, err = svc.CreateBucket(s3Input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyExists:
				return fmt.Errorf("A bucket with same name already exists")
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				return fmt.Errorf("The bucket is already owned by you")
			default:
				return err
			}
		} else {
			err.Error()
		}
	}

	return nil
}

func (s *S3) DeleteBucket() error {

	region := s.Region
	if region == "" {
		region = getRegionFromEnv()
	}

	svc, err := getS3Client(region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client")
		return aoerr
	}

	input := &s3.DeleteBucketInput{
		Bucket: aws.String(s.Name),
	}

	_, err = svc.DeleteBucket(input)
	if err != nil {
		return err
	}

	return nil
}
