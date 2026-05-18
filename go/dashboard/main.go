package main

import (
	"bufio"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type DashboardPacket struct {
	Timestamp uint64 `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Payload   []byte `json:"payload"`
	Index     int    `json:"index"`
	Info      string `json:"info"`
	Country   string `json:"country"`
}

func getPacketInfo(pkt *DashboardPacket) string {
	switch pkt.Protocol {
	case "TCP":
		return fmt.Sprintf("%d -> %d [ack] seq=0 ack=0 win=64240 len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "UDP":
		return fmt.Sprintf("%d -> %d len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "ICMP":
		return "echo (ping) request"
	default:
		return fmt.Sprintf("protocol %s message", strings.ToLower(pkt.Protocol))
	}
}

type RingBuffer struct {
	mu    sync.RWMutex
	data  []DashboardPacket
	size  int
	head  int
	count int
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]DashboardPacket, size),
		size: size,
	}
}

func (r *RingBuffer) Add(p DashboardPacket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[r.head] = p
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
}

func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.count = 0
}

func (r *RingBuffer) GetAll(reversed bool) []DashboardPacket {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]DashboardPacket, r.count)
	for i := 0; i < r.count; i++ {
		var idx int
		if reversed {
			idx = (r.head - 1 - i + r.size) % r.size
		} else {
			start := 0
			if r.count == r.size {
				start = r.head
			}
			idx = (start + i) % r.size
		}
		res[i] = r.data[idx]
	}
	return res
}

//go:embed index.html
var content embed.FS

var (
	historyBuffer = NewRingBuffer(5000)
	isScanning    = true
	filterStr     = ""
	packetCounter = 0
	seenIPs       = make(map[string]bool)
	geoCache      = make(map[string]string)
	mu            sync.Mutex
	geoMu         sync.Mutex
	geoReqChan    = make(chan string, 1000)
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var (
	clients   = make(map[chan []byte]bool)
	clientsMu sync.Mutex
)

func broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for ch := range clients {
		select {
		case ch <- data:
		default:
		}
	}
}

func isPrivateIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return true
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified()
}

func getCountry(ip string) string {
	if isPrivateIP(ip) {
		return "local"
	}
	geoMu.Lock()
	if c, ok := geoCache[ip]; ok {
		geoMu.Unlock()
		return c
	}
	geoCache[ip] = "searching..."
	geoMu.Unlock()

	select {
	case geoReqChan <- ip:
	default:
	}

	return "searching..."
}

func geoWorker() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	client := &http.Client{Timeout: 5 * time.Second}

	for ip := range geoReqChan {
		<-ticker.C
		resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country", ip))
		if err != nil {
			continue
		}

		var res struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && res.Country != "" {
			geoMu.Lock()
			geoCache[ip] = strings.ToLower(res.Country)
			geoMu.Unlock()

			saveGeoCacheToDisk()

			broadcast(map[string]interface{}{
				"type":    "geo_update",
				"ip":      ip,
				"country": strings.ToLower(res.Country),
			})
		} else {
			geoMu.Lock()
			delete(geoCache, ip)
			geoMu.Unlock()
		}
		resp.Body.Close()
	}
}

func saveGeoCacheToDisk() {
	geoMu.Lock()
	defer geoMu.Unlock()
	if data, err := json.Marshal(geoCache); err == nil {
		os.WriteFile("geocache.json", data, 0644)
	}
}

func loadGeoCache() {
	geoMu.Lock()
	defer geoMu.Unlock()
	if data, err := os.ReadFile("geocache.json"); err == nil {
		json.Unmarshal(data, &geoCache)
	}
}

func serveWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ch := make(chan []byte, 1024)
	clientsMu.Lock()
	clients[ch] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, ch)
		clientsMu.Unlock()
	}()

	for msg := range ch {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
}

func main() {
	packetChan := make(chan DashboardPacket, 1000)

	loadGeoCache()

	go geoWorker()

	go func() {
		const (
			minInterval = 2 * time.Second
			maxInterval = 60 * time.Second
		)
		consecutiveFailures := 0

		for {
			if consecutiveFailures > 0 {
				backoff := minInterval * (1 << uint(consecutiveFailures-1))
				if backoff > maxInterval || backoff < minInterval {
					backoff = maxInterval
				}
				fmt.Fprintf(os.Stderr, "[RECONNECT] Consecutive failures: %d. Waiting %v before next attempt...\r\n", consecutiveFailures, backoff)
				time.Sleep(backoff)
			}

			dialer := net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp", "127.0.0.1:9003")
			if err != nil {
				consecutiveFailures++
				continue
			}

			if consecutiveFailures > 0 {
				fmt.Printf("[RECONNECT] Connection restored.\r\n")
			}
			consecutiveFailures = 0

			fmt.Printf("Connected to Rust packet service.\r\n")
			scanner := bufio.NewScanner(conn)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024)

			for scanner.Scan() {
				var pkt DashboardPacket
				if err := json.Unmarshal(scanner.Bytes(), &pkt); err == nil {
					packetChan <- pkt
				}
			}

			conn.Close()
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Connection lost: %v. Retrying...\r\n", err)
			}
			consecutiveFailures++
		}
	}()

	go func() {
		for pkt := range packetChan {
			mu.Lock()
			if !isScanning {
				mu.Unlock()
				continue
			}
			packetCounter++
			pkt.Index = packetCounter
			pkt.Info = getPacketInfo(&pkt)
			if len(seenIPs) > 10000 {
				seenIPs = make(map[string]bool)
			}
			seenIPs[pkt.SrcIP] = true
			seenIPs[pkt.DstIP] = true

			if !isPrivateIP(pkt.SrcIP) {
				pkt.Country = getCountry(pkt.SrcIP)
			} else if !isPrivateIP(pkt.DstIP) {
				pkt.Country = getCountry(pkt.DstIP)
			} else {
				pkt.Country = "local"
			}

			match := false
			if filterStr == "" {
				match = true
			} else if strings.HasPrefix(filterStr, "STREAM:") {
				f := strings.Split(filterStr, ":")
				if len(f) == 5 && pkt.Protocol == "TCP" {
					match = (pkt.SrcIP == f[1] && fmt.Sprintf("%d", pkt.SrcPort) == f[2] && pkt.DstIP == f[3] && fmt.Sprintf("%d", pkt.DstPort) == f[4]) ||
						(pkt.SrcIP == f[3] && fmt.Sprintf("%d", pkt.SrcPort) == f[4] && pkt.DstIP == f[1] && fmt.Sprintf("%d", pkt.DstPort) == f[2])
				}
			} else {
				match = strings.Contains(strings.ToLower(pkt.Protocol), strings.ToLower(filterStr)) ||
					strings.Contains(pkt.SrcIP, filterStr) ||
					strings.Contains(pkt.DstIP, filterStr)
			}

			if match {
				historyBuffer.Add(pkt)
				broadcast(map[string]interface{}{
					"type":   "packet",
					"packet": pkt,
				})
			}
			mu.Unlock()
		}
	}()

	http.HandleFunc("/api/packets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reversed := historyBuffer.GetAll(true)
		f := filterStr
		s := isScanning
		w.Header().Set("Content-Type", "application/json")

		ips := make([]string, 0, len(seenIPs))
		for ip := range seenIPs {
			ips = append(ips, ip)
		}
		mu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"packets":    reversed,
			"isScanning": s,
			"filter":     f,
			"ips":        ips,
		})
	})

	http.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		history := historyBuffer.GetAll(false)
		mu.Unlock()

		w.Header().Set("Content-Disposition", "attachment; filename=\"pacsni_capture.pcap\"")
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")

		binary.Write(w, binary.LittleEndian, uint32(0xa1b2c3d4))
		binary.Write(w, binary.LittleEndian, uint16(2))
		binary.Write(w, binary.LittleEndian, uint16(4))
		binary.Write(w, binary.LittleEndian, int32(0))
		binary.Write(w, binary.LittleEndian, uint32(0))
		binary.Write(w, binary.LittleEndian, uint32(65535))
		binary.Write(w, binary.LittleEndian, uint32(1))

		for i := 0; i < len(history); i++ {
			p := history[i]
			payload := p.Payload
			sec := uint32(p.Timestamp / 1000000)
			usec := uint32(p.Timestamp % 1000000)

			binary.Write(w, binary.LittleEndian, sec)
			binary.Write(w, binary.LittleEndian, usec)
			binary.Write(w, binary.LittleEndian, uint32(len(payload)))
			binary.Write(w, binary.LittleEndian, uint32(len(payload)))
			w.Write(payload)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		action := query.Get("action")
		switch action {
		case "clear":
			mu.Lock()
			historyBuffer.Clear()
			broadcast(map[string]interface{}{"type": "clear"})
			mu.Unlock()
		case "toggle":
			mu.Lock()
			isScanning = !isScanning
			mu.Unlock()
			broadcast(map[string]interface{}{"type": "status", "isScanning": isScanning})
			query.Del("action")
			r.URL.RawQuery = query.Encode()
			http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
			return
		}

		if f, ok := query["filter"]; ok {
			mu.Lock()
			if filterStr != f[0] {
				filterStr = f[0]
				broadcast(map[string]interface{}{"type": "status", "isScanning": isScanning, "filter": filterStr})
			}
			mu.Unlock()
		}

		mu.Lock()
		btnText, statusLabel := "Start", "Paused"
		if isScanning {
			btnText, statusLabel = "Stop", "Active"
		}
		currentFilter := filterStr
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		tmpl, err := template.ParseFS(content, "index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, struct {
			BtnText     string
			Filter      string
			StatusLabel string
			IsScanning  bool
		}{
			BtnText:     btnText,
			Filter:      currentFilter,
			StatusLabel: statusLabel,
			IsScanning:  isScanning,
		})
	})

	http.HandleFunc("/ws", serveWs)
	fmt.Printf("Dashboard started! Access the browser dash at: http://localhost:8080\r\n")
	http.ListenAndServe(":8080", nil)
}
