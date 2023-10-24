package attributes

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/backend-go/internal/db"
)

type Client struct {
	db *db.Client
}

func NewClient(db *db.Client) Client {
	return Client{
		db: db,
	}
}

type Attribute struct {
	ID          string   `json:"id,omitempty"`
	Authority   string   `json:"authority,omitempty"`
	Description *string  `json:"description,omitempty"`
	Name        string   `json:"name,omitempty"`
	Rule        string   `json:"rule,omitempty"`
	State       string   `json:"state,omitempty"`
	Order       []string `json:"order,omitempty" db:"values_array"`
	GroupBy     *struct {
		Authority string `json:"authority,omitempty"`
		Name      string `json:"name,omitempty" db:"group_by_attr"`
		Value     string `json:"value,omitempty" db:"group_by_value"`
	} `json:"groupBy" db:"group_by"`
}

func (c *Client) GetAuthorities() ([]string, error) {
	authorities := []string{}
	rows, err := c.db.Query(context.TODO(), "SELECT name FROM tdf_attribute.attribute_namespace")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var authority string
		err := rows.Scan(&authority)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, authority)
	}
	return authorities, nil
}

func (c *Client) CreateAuthority(authority string) error {
	args := pgx.NamedArgs{
		"authority": authority,
	}

	_, err := c.db.Exec(context.TODO(), `
		INSERT INTO tdf_attribute.attribute_namespace (name)
		VALUES (@authority)
	`, args)
	return err
}

func (c *Client) DeleteAuthority(authority string) error {
	args := pgx.NamedArgs{
		"authority": authority,
	}

	_, err := c.db.Exec(context.TODO(), `
		DELETE FROM tdf_attribute.attribute_namespace
		WHERE name = @authority
	`, args)
	return err
}

func (c *Client) GetAttributes(authority string) ([]Attribute, error) {
	attributes := []Attribute{}
	args := pgx.NamedArgs{
		"authority": authority,
	}
	rows, err := c.db.Query(context.TODO(), `
		SELECT
		  a.id,
			authority.name AS authority,
			a.name,
			a.description,
			a.rule,
			a.state,
			a.values_array,
			(
				SELECT json_build_object('authority', attr_authority."name", 'name', attr."name", 'value', a.group_by_attrval)
				FROM tdf_attribute.attribute AS attr
				INNER JOIN tdf_attribute.attribute_namespace AS attr_authority ON attr."namespace_id" = attr_authority."id"
				WHERE attr.id = a.group_by_attr
			) AS group_by
		FROM tdf_attribute.attribute a
		INNER JOIN tdf_attribute.attribute_namespace authority
			ON a.namespace_id = authority.id
		WHERE authority.name = @authority
	`, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	attributes, err = pgx.CollectRows(rows, pgx.RowToStructByName[Attribute])
	if err != nil {
		return nil, err
	}

	return attributes, nil
}

func (c *Client) CreateDefinition(attr Attribute) (Attribute, error) {
	// Need to figure out how to handle group by
	args := pgx.NamedArgs{
		"authority":    attr.Authority,
		"name":         attr.Name,
		"rule":         attr.Rule,
		"state":        attr.State,
		"description":  attr.Description,
		"values":       attr.Order,
		"groupByAttr":  nil,
		"groupByAttrV": nil,
	}
	_, err := c.db.Exec(context.TODO(), `
	INSERT INTO tdf_attribute.attribute (
		namespace_id,
		state,
		rule,
		name,
		description,
		values_array,
		group_by_attr,
		group_by_attrval
	)
	SELECT 
		authority.id,
	  @state,
		@rule,
		@name,
		@description,
		@values,
		@groupByAttr,
		@groupByAttrVal
	FROM tdf_attribute.attribute_namespace authority 
	WHERE authority."name" = @authority
	`, args)
	if err != nil {
		return Attribute{}, err
	}
	return attr, nil
}
