package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Client struct {
	*pgxpool.Pool
}

func NewClient(url string) (*Client, error) {
	// urlExample := "postgres://username:password@localhost:5432/database_name"
	// switch to config
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &Client{
		Pool: pool,
	}, err
}
