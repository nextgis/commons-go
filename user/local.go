package users

import "github.com/nextgis/commons-go/context"

// LocalAuthInfo Local Info structure
type LocalAuthInfo struct {
	Enable bool `form:"enable" json:"enable"`
}

// InitInfo Fill LocalAuthInfo structure by values
func (li *LocalAuthInfo) InitInfo() {
	li.Enable = context.BoolOption("LOCAL_LOGIN")
}
