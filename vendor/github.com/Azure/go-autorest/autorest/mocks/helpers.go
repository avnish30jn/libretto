package mocks

import (
	"fmt"
	"net/http"
	"time"
)

const (
	// TestAuthorizationHeader is a faux HTTP Authorization header value
	TestAuthorizationHeader = "BEARER SECRETTOKEN"

	// TestBadURL is a malformed URL
	TestBadURL = "                               "

	// TestDelay is the Retry-After delay used in tests.
	TestDelay = 0 * time.Second

	// TestHeader is the header used in tests.
	TestHeader = "x-test-header"

	// TestURL is the URL used in tests.
	TestURL = "https://microsoft.com/a/b/c/"

	// TestAzureAsyncURL is a URL used in Azure asynchronous tests
	TestAzureAsyncURL = "https://microsoft.com/a/b/c/async"

	// TestLocationURL is a URL used in Azure asynchronous tests
	TestLocationURL = "https://microsoft.com/a/b/c/location"
)

const (
	headerLocation   = "Location"
	headerRetryAfter = "Retry-After"
)

// NewRequest instantiates a new request.
func NewRequest() *http.Request {
	return NewRequestWithContent("")
}

// NewRequestWithContent instantiates a new request using the passed string for the body content.
func NewRequestWithContent(c string) *http.Request {
	r, _ := http.NewRequest("GET", "https://microsoft.com/a/b/c/", NewBody(c))
	return r
}

// NewRequestForURL instantiates a new request using the passed URL.
func NewRequestForURL(u string) *http.Request {
	r, err := http.NewRequest("GET", u, NewBody(""))
	if err != nil {
		panic(fmt.Sprintf("mocks: ERROR (%v) parsing testing URL %s", err, u))
	}
	return r
}

// NewResponse instantiates a new response.
func NewResponse() *http.Response {
	return NewResponseWithContent("")
}

// NewResponseWithContent instantiates a new response with the passed string as the body content.
func NewResponseWithContent(c string) *http.Response {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		Body:       NewBody(c),
		Request:    NewRequest(),
	}
}

// NewResponseWithStatus instantiates a new response using the passed string and integer as the
// status and status code.
func NewResponseWithStatus(s string, c int) *http.Response {
	resp := NewResponse()
	resp.Status = s
	resp.StatusCode = c
	return resp
}

// NewResponseWithBodyAndStatus instantiates a new response using the specified mock body,
// status and status code
func NewResponseWithBodyAndStatus(body *Body, c int, s string) *http.Response {
	resp := NewResponse()
	resp.Body = body
	resp.Status = s
	resp.StatusCode = c
	return resp
}

// SetResponseHeader adds a header to the passed response.
func SetResponseHeader(resp *http.Response, h string, v string) {
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set(h, v)
}

// SetResponseHeaderValues adds a header containing all the passed string values.
func SetResponseHeaderValues(resp *http.Response, h string, values []string) {
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	for _, v := range values {
		resp.Header.Add(h, v)
	}
}

// SetAcceptedHeaders adds the headers usually associated with a 202 Accepted response.
func SetAcceptedHeaders(resp *http.Response) {
	SetLocationHeader(resp, TestURL)
	SetRetryHeader(resp, TestDelay)
}

// SetLocationHeader adds the Location header.
func SetLocationHeader(resp *http.Response, location string) {
	SetResponseHeader(resp, http.CanonicalHeaderKey(headerLocation), location)
}

// SetRetryHeader adds the Retry-After header.
func SetRetryHeader(resp *http.Response, delay time.Duration) {
	SetResponseHeader(resp, http.CanonicalHeaderKey(headerRetryAfter), fmt.Sprintf("%v", delay.Seconds()))
}
