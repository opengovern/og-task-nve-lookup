package nve_lookup

import (
	"context"
	"encoding/json"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func marshalJSON(_ context.Context, d *transform.TransformData) (interface{}, error) {
	b, err := json.Marshal(d.Value)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}
