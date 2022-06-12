package jwt

/**
创建token
token由三部分组成
header、payload、signature
@Title  CreateToken
@Description  用于创建一个token
@Author  hlccd 2021.6.14
@Version 1.0
*/
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"
)

/**
header
@Description  适配token中header的结构体
其中包含两个属性,分别是'声明类型'和'声明加密算法'
*/

type header struct {
	//声明类型
	Typ string `json:"typ"`
	//声明加密算法
	Alg string `json:"alg"`
}

/**
payload
@Description  适配token中payload的结构体
荷载信息
承载信息主要包括签发者、面向群体、接收方、签发时间、生效时间、过期时间
以及所要放置的其他信息
*/
type payload struct {
	//签发者
	Iss string `json:"iss"`
	//该jwt所面向的群体
	Sub string `json:"sub"`
	//接受该jwt的用户
	Aud string `json:"aud"`
	//签发时间
	Iat string `json:"iat"`
	//生效时间
	Nbf string `json:"nbf"`
	//过期时间
	Exp string `json:"exp"`
	//荷载信息
	Mes interface{}
}

/**
createHeader
@Description
创建header的Base64加密后的string格式并返回
当序列号失败时返回“”
@param nil
@return H string Base64加密后的header
*/
func createHeader() (H string) {
	h := header{
		Typ: "jwt",
		Alg: "HS256",
	}
	bytes, err := json.Marshal(h)
	if err != nil {
		log.Printf("marshal failed!error message：%v", err)
		return ""
	}
	H = base64.StdEncoding.EncodeToString(bytes)
	return H
}

/**
createHeader
创建payload的Base64加密后的string格式并返回
当序列号失败时返回“”
@param uid int64 用户ID
@param message interface{} 需要荷载的信息,类型自定
@return P string Base64加密后的payload
*/
func createPayload(uid int64, message interface{}) (P string) {
	p := payload{
		Iss: "hlccd",
		Sub: "regular_user",
		Aud: strconv.FormatInt(uid,10),
		Iat: strconv.FormatInt(time.Now().Unix(), 10),
		Nbf: strconv.FormatInt(time.Now().Unix(), 10),
		Exp: strconv.FormatInt(time.Now().Add(15*24*time.Hour).Unix(), 10),
		//Exp: strconv.FormatInt(time.Now().Add(15*24*time.Hour).Unix(), 10),
		Mes: message,
	}
	bytes, err := json.Marshal(p)
	if err != nil {
		log.Printf("marshal failed!error message：%v", err)
		return ""
	}
	P = base64.StdEncoding.EncodeToString(bytes)
	return P
}

/**
createSignature
创建signature的Base64加密后的string格式并返回
@param h string Base64加密后的header
@param p string Base64加密后的payload
@return S string Base64加密后的signature
*/
func createSignature(h string, p string) (S string) {
	str := strings.Join([]string{h, p}, ".")
	key := "hlccd2975"
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(str))
	s := hash.Sum(nil)
	S = base64.StdEncoding.EncodeToString(s)
	return S
}

/**
CreateToken
创建token的Base64加密后的string格式并返回
@param uid int64 用户ID
@param message interface{} 需要荷载的信息,类型自定
@return T string Base64加密后的token
*/

func CreateToken(uid int64, message interface{}) (T string) {
	h := createHeader()
	p := createPayload(uid, message)
	s := createSignature(h, p)
	T = strings.Join([]string{h, p}, ".") + "." + s
	return T
}
