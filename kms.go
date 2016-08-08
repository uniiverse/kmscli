package main

import (
  "github.com/aws/aws-sdk-go/aws"
  "github.com/aws/aws-sdk-go/aws/session"
  "github.com/aws/aws-sdk-go/aws/credentials"
  "github.com/aws/aws-sdk-go/service/kms"
)

func GetKMSSession(profile string) *kms.KMS {
  config := &aws.Config{
    Region: aws.String("us-east-1"),
    Credentials: credentials.NewSharedCredentials("",profile)}
  svc := kms.New(session.New(), config)

  return svc
}

func ListAliases(svc *kms.KMS) ([]*kms.AliasListEntry) {
  resp, err := svc.ListAliases(nil)
  if(err != nil) {
    panic(err)

    /*
    * TODO: Handle errors more gracefully
     if awsErr, ok := err.(awserr.Error); ok {
      fmt.Println(awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
      if reqErr, ok := err.(awserr.RequestFailure); ok {
        fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
      }
    } else {
      fmt.Println(err.Error())
    }*/
  }

  return resp.Aliases
}

func FilterAliases(entries []*kms.AliasListEntry, f func(*kms.AliasListEntry) bool) []*kms.AliasListEntry {
  result := make([]*kms.AliasListEntry, 0)

  for _, v := range entries {
    if f(v) {
      result = append(result, v)
    }
  }
  return result
}

func AliasExists(aliasName string, entries []*kms.AliasListEntry) bool {
  aliases := FilterAliases(entries, func(alias *kms.AliasListEntry) bool {
    return *alias.AliasName == aliasName
  })

  if (len(aliases) == 0) {
    return false
  } else if (len(aliases) > 1) {
    panic("Multiple Keys matching app and env found!")
  } else {
    //One found
    return true
  }
}

func GetAliasName(app, env string) string {
 return "alias/" + app + "-" + env
}

func Encrypt(svc *kms.KMS, app, env string, payload []byte) []byte { //*kms.EncryptOutput

  params := &kms.EncryptInput{
    KeyId:     aws.String(GetAliasName(app, env)), // Required
    Plaintext: payload,           // Required
    EncryptionContext: map[string]*string{
      "App": aws.String(app), // Required
      "Env": aws.String(env), // Required
    },
    //GrantTokens: []*string{
    //  aws.String("GrantTokenType"),
    //},
  }

  resp, err := svc.Encrypt(params)

  if err != nil {
    panic(err)
  }
  return resp.CiphertextBlob
}

func Decrypt(svc *kms.KMS, app, env string, payload []byte) []byte { //*kms.DecryptOutput
  params := &kms.DecryptInput{
    CiphertextBlob: payload,
    EncryptionContext: map[string]*string{
        "App": aws.String(app), // Required
        "Env": aws.String(env),
    },
  }

  resp, err := svc.Decrypt(params)

  if(err != nil) {
    panic(err)
  }

  return resp.Plaintext
}

func CreateKey(svc *kms.KMS, desc string) *kms.CreateKeyOutput {
  params := &kms.CreateKeyInput{
    Description: aws.String(desc),
  }

  resp, err := svc.CreateKey(params)

  if(err != nil) {
    panic(err)
  }

  return resp
}

func CreateAlias(svc *kms.KMS, app, env, targetKeyId string) *kms.CreateAliasOutput {
  params := &kms.CreateAliasInput{
    AliasName: aws.String(GetAliasName(app, env)),
    TargetKeyId: aws.String(targetKeyId),
  }

  resp, err := svc.CreateAlias(params)

  if(err != nil) {
    panic(err)
  }

  return resp
}

func CreateKeyWithAlias(svc *kms.KMS, app, env string) {
  desc := app + "-" + env
  key := CreateKey(svc, desc)
  CreateAlias(svc, app, env, *key.KeyMetadata.KeyId)
}
