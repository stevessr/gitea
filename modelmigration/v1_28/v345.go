// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_28

import (
	"gitea.dev/modelmigration/base"
)

// AddLinuxDoTrustLevelToUser adds the linux_do_trust_level column to the user table
func AddLinuxDoTrustLevelToUser(x base.EngineMigration) error {
	type User struct {
		LinuxDoTrustLevel *int64 `xorm:"NULL"`
	}
	return x.Sync(new(User))
}
