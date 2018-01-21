package aws

import (
	"reflect"
	"testing"
)

// Checks for an error in fetching bucket list and the functions return type
// to be a slice of strings
func TestGetS3BucketsList(t *testing.T) {
	list, err := GetS3BucketsList()

	if err != nil {
		t.Fail()
	} else if reflect.TypeOf(list).Elem().Kind() != reflect.String {
		t.Fail()
	}
}
