package upload

import "golang.org/x/sys/unix"

// The legacy management parent can grant traversal without read permission.
const managementSearchFlag = unix.O_PATH
