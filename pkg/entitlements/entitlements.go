package entitlements

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/backend-go/internal/db"
)

type Client struct {
	db  *db.Client
	opa *sdk.OPA
}

func NewClient(db *db.Client) Client {
	return Client{
		db: db,
	}
}

func (c Client) GetEntitlements(entityID string) (map[string][]string, error) {
	var entitlements map[string][]string = make(map[string][]string)

	args := pgx.NamedArgs{
		"entity_id": entityID,
	}
	rows, err := c.db.Query(context.TODO(), "SELECT namespace, name, value FROM tdf_entitlement.entity_attribute WHERE entity_id = @entity_id", args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var authority string
		var name string
		var value string
		err := rows.Scan(&authority, &name, &value)
		if err != nil {
			return nil, err
		}
		entitlements[entityID] = append(entitlements[entityID], fmt.Sprintf("%s/attr/%s/value/%s", authority, name, value))
	}
	return entitlements, nil
}

func (c Client) AddEntitlement(entityID string, attr []string) ([]string, error) {
	for _, a := range attr {
		u, err := url.Parse(a)
		if err != nil {
			return nil, err
		}
		// Need to check for properly formated url
		args := pgx.NamedArgs{
			"entity_id": entityID,
			"authority": u.Scheme + "://" + u.Host,
			"name":      strings.Split(u.Path, "/")[2],
			"value":     strings.Split(u.Path, "/")[4],
		}
		_, err = c.db.Exec(context.TODO(), `
		INSERT INTO tdf_entitlement.entity_attribute (entity_id, namespace, name, value)
		VALUES (@entity_id, @authority, @name, @value)`, args)
		if err != nil {
			return nil, err
		}
	}

	return attr, nil
}

func (c Client) RemoveEntitlement(entityID string, attr []string) error {
	for _, a := range attr {
		u, err := url.Parse(a)
		if err != nil {
			return err
		}
		// Need to check for properly formated url
		args := pgx.NamedArgs{
			"entity_id": entityID,
			"authority": u.Scheme + "://" + u.Host,
			"name":      strings.Split(u.Path, "/")[2],
			"value":     strings.Split(u.Path, "/")[4],
		}
		_, err = c.db.Exec(context.TODO(), `
		DELETE FROM tdf_entitlement.entity_attribute 
		WHERE entity_id = @entity_id 
		AND namespace = @authority 
		AND name = @name
		 AND value = @value`, args)
		if err != nil {
			return err
		}
	}
	return nil
}
