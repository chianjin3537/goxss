// wscheck — 临时验证脚本：连接 /ws 并等待推送事件
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	ws, _, err := websocket.DefaultDialer.Dial("ws://localhost:8080/ws", nil)
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer ws.Close()

	// 连接成功后请求 /demo 页（里面 3 秒后触发回传）
	go func() {
		time.Sleep(500 * time.Millisecond)
		http.Get("http://localhost:8080/demo")
	}()

	ws.SetReadDeadline(time.Now().Add(12 * time.Second))
	for i := 0; i < 5; i++ {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			fmt.Println("read end:", err)
			return
		}
		fmt.Printf("event: %s\n", msg)
	}
}
