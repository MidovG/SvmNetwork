package main

import (
	"svm/internal/consts"
	"svm/internal/repo"
)

var (
	gDatabase = repo.Connection(consts.DbDriverName, consts.DbConnStr)
)
