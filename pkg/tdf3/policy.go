package tdf3

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type Policy struct {
	UUID uuid.UUID `json:"uuid"`
	Body Body      `json:"body"`
}

type Body struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

type Attribute struct {
	Authority string
	Name      string
	Value     string
}

type serializedAttr struct {
	Attribute string `json:"attribute"`
}

func (at *Attribute) UnmarshalJSON(data []byte) error {
	var serAt serializedAttr
	if err := json.Unmarshal(data, &serAt); err != nil {
		return err
	}
	attr := serAt.Attribute
	valStart := strings.LastIndex(attr, "/")

	if valStart == -1 {
		return fmt.Errorf("illegal url, couldn't find attribute value [%s]", attr)
	}

	attrVal := attr[valStart+1:]
	attrVal, err := url.PathUnescape(attrVal)
	if err != nil {
		return err
	}

	idx := strings.LastIndex(attr[:valStart], "/")
	if attr[idx+1:valStart] != "val" {
		return fmt.Errorf("illegal attribute [%s], missing attribute value", attr)
	}

	nameStart := strings.LastIndex(attr[:idx], "/")
	if nameStart == -1 {
		return fmt.Errorf("illegal attribute [%s], missing attribute name", attr)
	}

	attrName := attr[nameStart+1 : idx]
	attrName, err = url.PathUnescape(attrName)
	if err != nil {
		return err
	}
	idx = strings.LastIndex(attr[:nameStart], "/")
	if idx == -1 {
		return fmt.Errorf("illegal attribute [%s], missing `attr`", attr)
	}

	if attr[idx+1:nameStart] != "attr" {
		return fmt.Errorf("illegal attribute [%s], missing `attr`", attr[idx+1:nameStart])
	}

	authority := attr[:idx]

	at.Authority = authority
	at.Name = attrName
	at.Value = attrVal

	return nil
}
