// Copyright (c) - Damien Fontaine <damien.fontaine@lineolia.net>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>

package service

import (
	"errors"

	"github.com/DamienFontaine/lunarc-blog/model"
	"github.com/DamienFontaine/lunarc/datasource/mongo"
	"github.com/DamienFontaine/lunarc/security"
	"gopkg.in/mgo.v2/bson"
)

//IUserService interface
type IUserService interface {
	GetByID(id string) (model.User, error)
	Get(username string, password string) (model.User, error)
	Add(user model.User) (model.User, error)
	FindAll() ([]model.User, error)
	Delete(user model.User) error
	Update(id string, user model.User) error
}

//UserService works with User
type UserService struct {
	MongoService mongo.Service
}

//Get retourne l'utilisateur si celui-ci existe
func (u *UserService) Get(username string, password string) (user model.User, err error) {
	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()

	userCollection := mongo.Database.C("user")
	err = userCollection.Find(bson.M{"username": username}).One(&user)

	if err != nil {
		return model.User{}, err
	}

	valid, err := security.CheckPassword([]byte(password), []byte(user.Salt), []byte(user.Password))
	if err != nil {
		return model.User{}, err
	}
	if valid {
		return user, nil
	}
	return model.User{}, errors.New("Invalid password")
}

//GetByID retourne l'utilisateur d'après son ID
func (u *UserService) GetByID(id string) (user model.User, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Incorrect ID")
		}
	}()

	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()

	userCollection := mongo.Database.C("user")
	err = userCollection.FindId(bson.ObjectIdHex(id)).One(&user)

	if err != nil {
		return model.User{}, err
	}

	return user, nil
}

//FindAll retourne tout les utilisateurs
func (u *UserService) FindAll() (users []model.User, err error) {
	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()

	userCollection := mongo.Database.C("user")
	err = userCollection.Find(nil).All(&users)

	if err != nil {
		return users, errors.New("Error")
	}

	return users, nil
}

//Add ajoute un nouvel utilisateur
func (u *UserService) Add(user model.User) (model.User, error) {
	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()
	id := bson.NewObjectId()

	salt, err := security.GenerateSalt()
	if err != nil {
		return model.User{}, errors.New("Error when generatiing Salt")
	}
	user.Salt = string(salt[:32])

	password, err := security.HashPassword([]byte(user.Password), salt)
	if err != nil {
		return model.User{}, err
	}
	user.Password = string(password[:32])

	userCollection := mongo.Database.C("user")
	userCollection.Insert(&model.User{User: security.User{Username: user.Username, Password: user.Password, Salt: user.Salt, Email: user.Email}, ID: id, Firstname: user.Firstname, Lastname: user.Lastname})

	err = userCollection.FindId(id).One(&user)

	if err != nil {
		return model.User{}, errors.New("User not saved")
	}

	return user, nil
}

//Delete supprime un utilisateur
func (u *UserService) Delete(user model.User) (err error) {
	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()
	userCollection := mongo.Database.C("user")
	err = userCollection.Remove(bson.M{"_id": user.ID, "username": user.Username})
	return
}

//Update modifie un utilisateur existant
func (u *UserService) Update(id string, user model.User) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Incorrect ID")
		}
	}()

	mongo := u.MongoService.Mongo.Copy()
	defer mongo.Close()

	salt, err := security.GenerateSalt()
	if err != nil {
		return err
	}
	user.Salt = string(salt[:32])

	password, err := security.HashPassword([]byte(user.Password), salt)
	if err != nil {
		return err
	}
	user.Password = string(password[:32])

	userCollection := mongo.Database.C("user")
	err = userCollection.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"$set": bson.M{"username": user.Username, "lastname": user.Lastname, "firstname": user.Firstname, "password": user.Password, "salt": user.Salt, "email": user.Email}})

	return err
}
