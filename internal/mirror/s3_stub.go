//go:build !s3

package mirror

import "errors"

func newS3Backend(_ string) (Mirror, error) {
	return nil, errors.New("s3 mirror support not compiled; rebuild with -tags s3")
}
