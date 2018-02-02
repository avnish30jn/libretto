package aws

import (
	"fmt"
	"reflect"
	"testing"

	"libretto/virtualmachine/common"
)

// Checks for an error in fetching bucket list and the functions return type
// to be a slice of strings

func TestGetS3BucketsList(t *testing.T) {
	s3 := S3{
		Name:   "",
		Region: "us-east-1",
		Prefix: "",
	}

	list, err := s3.GetS3BucketsList()

	if err != nil {
		t.Fail()
	} else if reflect.TypeOf(list).Elem().Kind() != reflect.String {
		t.Fail()
	}

	fmt.Println(list)
}

func TestCreateBucket(t *testing.T) {
	bucketName := common.RandStringRunes(5)

	s3 := S3{
		Name:   bucketName,
		Region: "us-east-1",
		Prefix: "",
	}

	err := s3.CreateBucket()
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}

	if exist, err := s3.BucketExist(); !exist {
		t.Errorf("Bucket not found: %v", err)
	}

	err = s3.DeleteBucket()
	if err != nil {
		t.Errorf("Failed in deleting bucket: %v", err)
	}

	if exist, err := s3.BucketExist(); exist {
		t.Errorf("Bucket still exists: %v", err)
	}
}
