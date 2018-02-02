package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
)

func getS3Client(region string) (svc *s3.S3, err error) {
	if isRegionEmpty(region) {
		region = getRegionFromEnv()
		if isRegionEmpty(region) {
			err = fmt.Errorf("Empty region provided")
			return svc, err
		}
	}

	sess, err := getSession(region)
	if err != nil {
		return svc, err
	}

	svc = s3.New(sess)

	return svc, err
}

func isRegionEmpty(region string) bool {
	if region == "" {
		return true
	} else {
		return false
	}
}
