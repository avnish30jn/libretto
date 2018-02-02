package aws

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	HttpClientTimeout = 30
)

func getSession(region string) (ss *session.Session, err error) {
	// TODO Use getSession for ec2 service too
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},               // check environment
			&credentials.SharedCredentialsProvider{}, // check home dir
		},
	)

	if isRegionEmpty(region) { // user didn't set region
		region = getRegionFromEnv()
		if isRegionEmpty(region) {
			err = fmt.Errorf("Empty region provided")
			return ss, err
		}
	}

	ss, err = session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
		HTTPClient: &http.Client{
			Timeout: HttpClientTimeout * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	return ss, nil
}
