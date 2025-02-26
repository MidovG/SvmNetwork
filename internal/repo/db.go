package repo

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	db *sql.DB
}

func Connection(driverInfo, connectionInfo string) *Database {
	db, err := sql.Open(driverInfo, connectionInfo)

	if err != nil {
		panic(err)
	}

	err = db.Ping()

	if err != nil {
		panic(err)
	}

	return &Database{
		db: db,
	}
}

func (d *Database) Close() error {
	return d.db.Close()
}
