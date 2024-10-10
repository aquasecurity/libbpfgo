// Deprecated: helpers package is deprecated and will be removed.
// See https://github.com/aquasecurity/tracee/pull/4090
package helpers

import (
	"golang.org/x/sys/unix"
)

var (
	Map32bit = MmapFlagArgument{rawValue: unix.MAP_32BIT, stringValue: "MAP_32BIT"}
)

func init() {
	mmapFlagMap[Map32bit.Value()] = Map32bit
}
