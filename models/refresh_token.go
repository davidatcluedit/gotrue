package models

import "github.com/jinzhu/gorm"

type RefreshToken struct {
	ID int64

	Token string

	User   User
	UserID int

	Revoked bool
}

func CreateRefreshToken(db *gorm.DB, user *User) (*RefreshToken, error) {
	token := &RefreshToken{
		User:  *user,
		Token: secureToken(),
	}
	if err := db.Create(token).Error; err != nil {
		return nil, err
	}

	return token, nil
}
