package db

import (
	"context"
	"fmt"
	"os"

	"ariga.io/atlas-go-sdk/atlasexec"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/exp/slog"
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

func (c *Client) RunMigrations() error {
	// Define the execution context, supplying a migration directory
	// and potentially an `atlas.hcl` configuration file using `atlasexec.WithHCL`.
	workdir, err := atlasexec.NewWorkingDir(
		atlasexec.WithMigrations(
			os.DirFS("./migrations"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to load working directory: %v", err)
	}
	// atlasexec works on a temporary directory, so we need to close it
	defer workdir.Close()

	// Initialize the client.
	client, err := atlasexec.NewClient(workdir.Path(), "atlas")
	if err != nil {
		return fmt.Errorf("failed to initialize client: %v", err)
	}
	// Run `atlas migrate apply` on a SQLite database under /tmp.
	res, err := client.Apply(context.Background(), &atlasexec.MigrateApplyParams{
		URL: c.Config().ConnString(),
	})
	if err != nil {
		return fmt.Errorf("failed to apply migrations: %v", err)
	}
	slog.Info("Applied migrations", slog.Any("applied", len(res.Applied)))
	return nil
}
