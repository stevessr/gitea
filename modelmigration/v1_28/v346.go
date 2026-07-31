// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_28

import (
	"gitea.dev/modelmigration/base"
)

// AddRepoVisibilityColumn adds the visibility column to the repository table and backfills existing data
func AddRepoVisibilityColumn(x base.EngineMigration) error {
	type Repository struct {
		Visibility int `xorm:"NOT NULL DEFAULT 0"`
	}
	// Add column
	if err := x.Sync(new(Repository)); err != nil {
		return err
	}
	// Backfill: public repos -> Public(7), private repos -> Private(0)
	_, err := x.Exec("UPDATE repository SET visibility = 7 WHERE is_private = false AND visibility = 0")
	if err != nil {
		return err
	}
	_, err = x.Exec("UPDATE repository SET visibility = 0 WHERE is_private = true AND visibility = 0")
	return err
}
