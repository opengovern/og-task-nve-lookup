package main

import (
	"github.com/opengovern/og-task-nve-lookup/cloudql/nve-lookup"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: nve_lookup.Plugin})
}
