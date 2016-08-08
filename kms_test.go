package main

import (
  "fmt"
  "testing"
  "github.com/aws/aws-sdk-go/service/kms"
)
const profile string =  "default"

func TestGetKMSSession(t *testing.T) {
  got := GetKMSSession(profile)

  fmt.Println(got)
}

func TestListAliases(t *testing.T) {
  session := GetKMSSession(profile)

  got := ListAliases(session)

  fmt.Println(got)
}

func TestFilterAliases(t *testing.T) {
  session := GetKMSSession(profile)

  aliases := ListAliases(session)

  result := FilterAliases(aliases, func(alias *kms.AliasListEntry) bool {
    return *alias.AliasName == "alias/myapp-staging"
  })

  fmt.Println(result)
}

func TestAliasExists(t *testing.T) {
  session := GetKMSSession(profile)

  aliases := ListAliases(session)

  result := AliasExists("alias/myapp-staginggg", aliases)

  fmt.Println(result)
}

func TestEncrypt(t *testing.T) {
  svc := GetKMSSession(profile)

  payload := []byte(`{"Name":"Alice","Body":"Hello","Time":1294706395881547000}`)
  app := "web"
  env := "staging"

  result := Encrypt(svc,app,env,payload)

  fmt.Println(result)
}

func TestDecrypt(t *testing.T) {

  svc := GetKMSSession(profile)

  payload := []byte(`{"Name":"Alice","Body":"Hello","Time":1294706395881547000}`)
  app := "web"
  env := "staging"

  encryptResult := Encrypt(svc,app,env,payload)

  decryptResult := Decrypt(svc, app, env, encryptResult)

  fmt.Println(string(decryptResult))
}

func TestCreateKey(t *testing.T) {
  svc := GetKMSSession(profile)

  result := CreateKey(svc, "blah")

  fmt.Println(result)
}

func TestCreateAlias(t *testing.T) {
  svc := GetKMSSession(profile)

  targetKey := "b829684d-5066-4cd7-ab44-3f3de80110dc"
  app := "myapp"
  env := "staging"

  result := CreateAlias(svc, app, env, targetKey)

  fmt.Println(result)
}

func TestCreateKeyWithAlias(t *testing.T) {
  svc := GetKMSSession(profile)

  app := "myapp2"
  env := "staging"

  CreateKeyWithAlias(svc, app, env)
}
