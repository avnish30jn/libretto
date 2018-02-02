package aws

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	HttpClientTimeout = 30
)

func getSession(region string) (*session.Session, error) {
	// TODO Use getSession for ec2 service too
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},               // check environment
			&credentials.SharedCredentialsProvider{}, // check home dir
		},
	)

	if region == "" { // user didn't set region
		region = os.Getenv("AWS_DEFAULT_REGION") // aws cli checks this
		if region == "" {
			region = os.Getenv("AWS_REGION") // aws sdk checks this
		}
	}

	s, err := session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
		HTTPClient: &http.Client{
			Timeout: HttpClientTimeout * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	return s, nil
}
