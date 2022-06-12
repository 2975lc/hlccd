package jwt
/**
检测token
@Title  CheckToken
@Description  用于检测我方签发的token
@Author  hlccd 2021.6.15
@Version 1.0
*/
import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/hlccd/util/response"
	"log"
	"strings"
	"time"
	"strconv"
)
/**
@Title  CheckToken
@Description  将传递过来的token进行检测
如果存在Base64解密失败或超期以及未到使用期,则终止后续操作
如果Base64解密成功同时在有效期内,则将aub和mes放入上下文中并进行后续操作
@return gin.HandlerFunc 中间件
 */
func CheckToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		//获取token并分为header,payload和signature三部分用以进行进行Base64解密
		token := ctx.Request.Header.Get("Authorization")
		split := strings.Split(token, ".")
		if len(split) != 3 {
			err := errors.New("check token error")
			log.Println(err)
			response.Error(ctx,"check token error", err)
			ctx.Abort()
			return
		}
		//解密header部分
		_, err := base64.StdEncoding.DecodeString(split[0])
		if err != nil {
			err = errors.New("header analysis error")
			log.Println(err)
			response.Error(ctx,"header analysis error",err)
			ctx.Abort()
			return
		}
		//解密payload部分
		p, err := base64.StdEncoding.DecodeString(split[1])
		if err != nil {
			err = errors.New("payload analysis error")
			log.Println(err)
			response.Error(ctx,"payload analysis error",err)
			ctx.Abort()
			return
		}
		//解密signature部分
		_, err = base64.StdEncoding.DecodeString(split[2])
		if err != nil {
			err = errors.New("signature analysis error")
			log.Println(err)
			response.Error(ctx,"signature analysis error",err)
			ctx.Abort()
			return
		}
		//将解密后的payload部分进行反序列化
		var P payload
		err = json.Unmarshal(p, &P)
		if err != nil {
			log.Printf("unmarshal failed!error message：%v", err)
			response.Error(ctx,"unmarshal fail",err)
			ctx.Abort()
			return
		}
		//检测该token是否处于有效期内
		nbf, _ := strconv.ParseInt(P.Nbf, 10, 64)
		exp, _ := strconv.ParseInt(P.Exp, 10, 64)
		if nbf>time.Now().Unix() {
			err = errors.New("This token is not valid")
			log.Println(err)
			response.Error(ctx,"This token is not valid",err)
			ctx.Abort()
			return
		}
		if exp<time.Now().Unix() {
			err = errors.New("This token has expired")
			log.Println(err)
			response.Error(ctx,"This token has expired",err)
			ctx.Abort()
			return
		}
		//检测通过,将token的aud和mes放入上下文中并挂起
		ctx.Set("operator", P.Aud)
		ctx.Set("message", P.Mes)
		ctx.Next()
	}
}