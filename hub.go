package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ══════════════ WebSocket Hub ══════════════
// 维护在线面板连接，实时广播回显与项目变更事件

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	// 面板与 hook.js 场景允许跨域连接
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]chan struct{}
}

func newHub() *Hub { return &Hub{clients: map[*websocket.Conn]chan struct{}{}} }

func (h *Hub) add(conn *websocket.Conn) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	done := make(chan struct{})
	h.clients[conn] = done
	return done
}

func (h *Hub) remove(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if done, ok := h.clients[conn]; ok {
		close(done)
		delete(h.clients, conn)
	}
}

func (h *Hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// broadcast 向所有在线面板推送事件，消息格式 {"type": "...", "data": ...}
func (h *Hub) broadcast(eventType string, data any) {
	msg, err := json.Marshal(map[string]any{"type": eventType, "data": data})
	if err != nil {
		return
	}
	h.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	for _, c := range conns {
		// 写超时 5s，失败即踢掉
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			h.remove(c)
			_ = c.Close()
		}
	}
}

// serveWS 处理面板的 WebSocket 连接
func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	done := h.add(conn)
	log.Printf("[ws] 面板已连接（在线 %d）", h.count())

	defer func() {
		h.remove(conn)
		_ = conn.Close()
		log.Printf("[ws] 面板断开（在线 %d）", h.count())
	}()

	// 发送欢迎消息，前端收到即认为连接就绪
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"hello","data":null}`))

	// 读泵：只处理关闭/心跳，忽略业务消息
	go func() {
		<-done
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
