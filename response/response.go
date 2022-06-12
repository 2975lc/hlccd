package response

/**
@Title  response
@Description  用于序列化web响应消息,主要包括成功和失败两种
@Author  hlccd 2021.6.14
@Version 1.0
*/
import (
	"github.com/gin-gonic/gin"
	"net/http"
)

/**
Ok
@Description
统一化的成功应答
@parame ctx *gin.Contex 上下文
@parame message interface{} 应答中所要承载的内容
*/
func Ok(ctx *gin.Context, message interface{}) {
	ctx.JSON(http.StatusOK, gin.H{
		"code":    200,
		"info":    "success",
		"message": message,
	})
}
func Redirect(ctx *gin.Context,  message interface{}) {
	ctx.JSON(http.StatusOK, gin.H{
		"code":    300,
		"info":    "redirect",
		"message": message,
	})
}
/**
Error
@Description
统一化的错误响应
@parame ctx *gin.Contex 上下文
@parame err error 错误内容
*/
func Error(ctx *gin.Context, info string, message interface{}) {
	ctx.JSON(http.StatusOK, gin.H{
		"code":    500,
		"info":    info,
		"message": message,
	})
}
