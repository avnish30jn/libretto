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

func (s3Obj *S3) GetS3BucketsList() ([]string, error) {
	// 1. Get s3 service client
	// 2. Fetch the list
	var bucketList []string

	s3Svc, err := getS3Client(s3Obj.Region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client: %v", err)
		return bucketList, aoerr
	}

	result, err := s3Svc.ListBuckets(nil)
	if err != nil {
		aoerr := fmt.Errorf("Failed in fetching the bucket list: %v", err)
		return bucketList, aoerr
	}

	for _, s3bkt := range result.Buckets {
		bucketList = append(bucketList, aws.StringValue(s3bkt.Name))
	}

	return bucketList, nil
}

func (s3Obj *S3) CreateBucket() error {

	svc, err := getS3Client(s3Obj.Region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client: %v", err)
		return aoerr
	}

	s3Input := new(s3.CreateBucketInput)
	s3Input.Bucket = aws.String(s3Obj.Name)

	// us-east-1 region is not supported as a location constrain. More details
	// at https://github.com/boto/boto3/issues/125
	if s3Obj.Region != "us-east-1" {
		s3Input.CreateBucketConfiguration.LocationConstraint = aws.String(s3Obj.Region)
	}

	_, err = svc.CreateBucket(s3Input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyExists:
				return fmt.Errorf("A bucket with same name already exists")
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				return fmt.Errorf("The bucket is already owned by the user")
			default:
				return err
			}
		} else {
			err.Error()
		}
	}

	return nil
}

func (s3Obj *S3) DeleteBucket() error {

	svc, err := getS3Client(s3Obj.Region)
	if err != nil {
		aoerr := fmt.Errorf("Failed to create s3 client: %v", err)
		return aoerr
	}

	input := &s3.DeleteBucketInput{
		Bucket: aws.String(s3Obj.Name),
	}

	_, err = svc.DeleteBucket(input)
	if err != nil {
		return err
	}

	return nil
}

func (s3Obj *S3) BucketExist() (bool, error) {
	list, err := s3Obj.GetS3BucketsList()
	if err != nil {
		aoerr := fmt.Errorf("Unable to fetch bucket list: %v", err)
		return false, aoerr
	}

	for _, s3bkt := range list {
		if s3bkt == s3Obj.Name {
			return true, nil
		}
	}

	return false, nil
}
