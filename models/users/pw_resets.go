package users

import (
	"github.com/jinzhu/gorm"
	"lenslocked.com/hash"
	"lenslocked.com/models/errors"
	"lenslocked.com/rand"
)

type PWReset struct {
	gorm.Model
	UserID    uint   `gorm:"not null"`
	Token     string `gorm:"-"`
	TokenHash string `gorm:"not null;unique_index"`
}

type PWResetDB interface {
	ByToken(token string) (*PWReset, error)
	Create(pwr *PWReset) error
	Delete(id uint) error
}

func newPwResetValidator(db PWResetDB, hmac hash.HMAC) *pwResetValidator {
	return &pwResetValidator{
		PWResetDB: db,
		hmac:      hmac,
	}
}

type pwResetValidator struct {
	PWResetDB
	hmac hash.HMAC
}

func (pwrv *pwResetValidator) ByToken(token string) (*PWReset, error) {
	pwr := PWReset{Token: token}
	err := runPwResetValFns(&pwr, pwrv.hmacToken)
	if err != nil {
		return nil, err
	}
	return pwrv.PWResetDB.ByToken(pwr.TokenHash)
}

func (pwrv *pwResetValidator) Create(pwr *PWReset) error {
	err := runPwResetValFns(pwr,
		pwrv.requireUserID,
		pwrv.setTokenIfUnset,
		pwrv.hmacToken,
	)
	if err != nil {
		return err
	}
	return pwrv.PWResetDB.Create(pwr)
}

func (pwrv *pwResetValidator) Delete(id uint) error {
	if id <= 0 {
		return errors.ErrIDInvalid
	}
	return pwrv.PWResetDB.Delete(id)
}

type pwResetGorm struct {
	db *gorm.DB
}

func (pwrg *pwResetGorm) ByToken(tokenHash string) (*PWReset, error) {
	var pwr PWReset
	err := First(pwrg.db.Where("token_hash = ?", tokenHash), &pwr)
	if err != nil {
		return nil, err
	}
	return &pwr, nil
}

func (pwrg *pwResetGorm) Create(pwr *PWReset) error {
	return pwrg.db.Create(pwr).Error
}

func (pwrg *pwResetGorm) Delete(id uint) error {
	pwr := PWReset{Model: gorm.Model{ID: id}}
	return pwrg.db.Delete(&pwr).Error
}

func (pwrv *pwResetValidator) requireUserID(pwr *PWReset) error {
	if pwr.UserID <= 0 {
		return errors.ErrUserIDRequired
	}
	return nil
}

func (pwrv *pwResetValidator) setTokenIfUnset(pwr *PWReset) error {
	if pwr.Token != "" {
		return nil
	}
	token, err := rand.RememberToken()
	if err != nil {
		return err
	}
	pwr.Token = token
	return nil
}

func (pwrv *pwResetValidator) hmacToken(pwr *PWReset) error {
	if pwr.Token == "" {
		return nil
	}
	pwr.TokenHash = pwrv.hmac.Hash(pwr.Token)
	return nil
}

type pwResetValFn func(*PWReset) error

func runPwResetValFns(pwr *PWReset, fns ...pwResetValFn) error {
	for _, fn := range fns {
		if err := fn(pwr); err != nil {
			return err
		}
	}
	return nil
}
