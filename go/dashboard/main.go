package main

import (
	"bufio"
	"container/list"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type DashboardPacket struct {
	Timestamp    uint64 `json:"timestamp"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstPort      uint16 `json:"dst_port"`
	SrcMAC       string `json:"src_mac"`
	DstMAC       string `json:"dst_mac"`
	Protocol     string `json:"protocol"`
	HasTcpAo     bool   `json:"has_tcp_ao"`
	TcpFlags     uint8  `json:"tcp_flags"`
	L3Offset     uint8  `json:"l3_offset"`
	L4Offset     uint8  `json:"l4_offset"`
	Payload      []byte `json:"payload"`
	Index        int    `json:"index"`
	Info         string `json:"info"`
	SrcMacVendor string `json:"src_mac_vendor"`
	DstMacVendor string `json:"dst_mac_vendor"`
	Country      string `json:"country"`
}

func getPacketInfo(pkt *DashboardPacket) string {
	if pkt.SrcPort == 53 || pkt.DstPort == 53 {
		return fmt.Sprintf("DNS Message %d -> %d", pkt.SrcPort, pkt.DstPort)
	}

	switch pkt.Protocol {
	case "TCP":
		var flags []string
		if pkt.TcpFlags&0x02 != 0 { // SYN
			flags = append(flags, "<span style='color:#fbbf24; font-weight:800;'>SYN</span>")
		}
		if pkt.TcpFlags&0x01 != 0 { // FIN
			flags = append(flags, "<span style='color:#a855f7; font-weight:800;'>FIN</span>")
		}
		if pkt.TcpFlags&0x04 != 0 { // RST
			flags = append(flags, "<span style='color:#f43f5e; font-weight:800;'>RST</span>")
		}
		if pkt.TcpFlags&0x10 != 0 { // ACK
			flags = append(flags, "ACK")
		}
		if pkt.TcpFlags&0x08 != 0 { // PSH
			flags = append(flags, "PSH")
		}

		info := fmt.Sprintf("%d -> %d", pkt.SrcPort, pkt.DstPort)
		if len(flags) > 0 {
			info += " [" + strings.Join(flags, ",") + "]"
		}
		return fmt.Sprintf("%s seq=0 ack=0 win=64240 len=%d", info, len(pkt.Payload))
	case "UDP":
		return fmt.Sprintf("%d -> %d len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "DHCP":
		return fmt.Sprintf("DHCP Message %d -> %d len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "HTTP":
		return fmt.Sprintf("HTTP Request/Response %d -> %d len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "ICMP":
		return "echo (ping) request"
	case "ARP":
		srcVendor := ""
		if pkt.SrcMacVendor != "" {
			srcVendor = fmt.Sprintf(" (%s)", pkt.SrcMacVendor)
		}
		dstVendor := ""
		if pkt.DstMacVendor != "" {
			dstVendor = fmt.Sprintf(" (%s)", pkt.DstMacVendor)
		}
		return fmt.Sprintf("ARP Request/Reply %s%s -> %s%s", pkt.SrcIP, srcVendor, pkt.DstIP, dstVendor)
	case "ND":
		return "Neighbor Discovery (Solicitation/Advertisement)"
	case "ICMPv6":
		return "ICMPv6 Control Message"
	case "OSPF":
		return "OSPF Routing Protocol Message"
	case "STP":
		dstVendor := ""
		if pkt.DstMacVendor != "" {
			dstVendor = fmt.Sprintf(" (%s)", pkt.DstMacVendor)
		}
		return fmt.Sprintf("Spanning Tree Protocol Message to %s%s", pkt.DstMAC, dstVendor)
	default:
		return fmt.Sprintf("protocol %s message", strings.ToLower(pkt.Protocol))
	}
}

type RingBuffer[T any] struct {
	mu    sync.RWMutex
	data  []T
	size  int
	head  int
	count int
}

func NewRingBuffer[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{
		data: make([]T, size),
		size: size,
	}
}

func (r *RingBuffer[T]) Add(p T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[r.head] = p
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
}

func (r *RingBuffer[T]) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.count = 0
}

func (r *RingBuffer[T]) GetAll(reversed bool) []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]T, r.count)
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

//go:embed index.html script.js
var content embed.FS

var (
	historyBuffer = NewRingBuffer[DashboardPacket](5000)
	isScanning    = true
	filterStr     = ""
	filterRegex   *regexp.Regexp
	packetCounter = 0
	seenIPs       = make(map[string]bool)
	geoCache      = NewLRUCache(10000)
	mu            sync.Mutex
	geoReqChan    = make(chan string, 1000)
)

type lruEntry struct {
	key   string
	value string
}

type lruCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	mu       sync.Mutex
}

func NewLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *lruCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, found := c.cache[key]; found {
		c.list.MoveToFront(element)
		return element.Value.(*lruEntry).value, true
	}
	return "", false
}

func (c *lruCache) Add(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, found := c.cache[key]; found {
		c.list.MoveToFront(element)
		element.Value.(*lruEntry).value = value
		return
	}
	if c.list.Len() >= c.capacity {
		oldest := c.list.Back()
		if oldest != nil {
			c.list.Remove(oldest)
			delete(c.cache, oldest.Value.(*lruEntry).key)
		}
	}
	entry := &lruEntry{key: key, value: value}
	element := c.list.PushFront(entry)
	c.cache[key] = element
}

func (c *lruCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, found := c.cache[key]; found {
		c.list.Remove(element)
		delete(c.cache, key)
	}
}

func (c *lruCache) GetAll() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	allEntries := make(map[string]string, c.list.Len())
	for _, element := range c.cache {
		entry := element.Value.(*lruEntry)
		allEntries[entry.key] = entry.value
	}
	return allEntries
}

func (c *lruCache) Load(data map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*list.Element)
	c.list = list.New()
	for key, value := range data {
		entry := &lruEntry{key: key, value: value}
		element := c.list.PushFront(entry)
		c.cache[key] = element
	}
}

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
	// Treat non-global unicast (loopback, link-local, etc.) or RFC1918 private IPs as local
	return !parsed.IsGlobalUnicast() || parsed.IsPrivate()
}

func getCountry(ip string) string {
	if isPrivateIP(ip) {
		return "local"
	}
	if c, ok := geoCache.Get(ip); ok {
		return c
	}
	select {
	case geoReqChan <- ip:
	default:
	}
	return "searching..."
}

var macVendors = map[string]string{
	"00:00:00": "Xerox",
	"00:00:0C": "Cisco",
	"00:00:0F": "Fujitsu",
	"00:00:1C": "Intel",
	"00:00:2D": "Apple",
	"00:00:33": "IBM",
	"00:00:3F": "Motorola",
	"00:00:5E": "IANA",
	"00:00:86": "HP",
	"00:00:A7": "Dell",
	"00:00:C0": "Western Digital",
	"00:00:E8": "Samsung",
	"00:01:42": "Microsoft",
	"00:01:4F": "Netgear",
	"00:01:6C": "Linksys",
	"00:01:96": "Huawei",
	"00:02:B3": "Google",
	"00:03:93": "Juniper",
	"00:04:20": "Nokia",
	"00:05:00": "VMware",
	"00:05:1A": "Broadcom",
	"00:05:9A": "D-Link",
}

func getMacVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	oui := strings.ToUpper(mac[0:8])
	return macVendors[oui]
}

func geoWorker() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for ip := range geoReqChan {
		<-ticker.C
		resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country", ip))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[GEO ERROR] Request failed for %s: %v\n", ip, err)
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			fmt.Fprintf(os.Stderr, "[GEO ERROR] Rate limit hit for %s. Sleeping 1m...\n", ip)
			resp.Body.Close()
			time.Sleep(1 * time.Minute)
			continue
		}
		var res struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && res.Country != "" {
			geoCache.Add(ip, strings.ToLower(res.Country))
			saveGeoCacheToDisk()
			broadcast(map[string]interface{}{
				"type":    "geo_update",
				"ip":      ip,
				"country": strings.ToLower(res.Country),
			})
		} else {
			if err != nil {
				fmt.Fprintf(os.Stderr, "[GEO ERROR] Failed to decode response for %s: %v\n", ip, err)
			}
			geoCache.Remove(ip)
		}
		resp.Body.Close()
	}
}

func saveGeoCacheToDisk() {
	dataToSave := geoCache.GetAll()
	if data, err := json.Marshal(dataToSave); err == nil {
		os.WriteFile("geocache.json", data, 0644)
	}
}

func loadGeoCache() {
	if data, err := os.ReadFile("geocache.json"); err == nil {
		var loadedMap map[string]string
		if json.Unmarshal(data, &loadedMap) == nil {
			geoCache.Load(loadedMap)
		}
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

	rustServiceHost := os.Getenv("RUST_SERVICE_HOST")
	if rustServiceHost == "" {
		rustServiceHost = "127.0.0.1"
	}
	rustServicePort := os.Getenv("RUST_SERVICE_PORT")
	if rustServicePort == "" {
		rustServicePort = "9003"
	}
	rustServiceAddr := net.JoinHostPort(rustServiceHost, rustServicePort)

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
			conn, err := dialer.Dial("tcp", rustServiceAddr)
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
			if pkt.Protocol == "ARP" || pkt.Protocol == "STP" { // Only lookup for protocols where MAC vendor is relevant
				pkt.SrcMacVendor = getMacVendor(pkt.SrcMAC)
				pkt.DstMacVendor = getMacVendor(pkt.DstMAC)
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
			} else if filterRegex != nil {
				match = filterRegex.MatchString(pkt.Protocol) ||
					filterRegex.MatchString(pkt.SrcIP) ||
					filterRegex.MatchString(pkt.DstIP) ||
					filterRegex.MatchString(pkt.Info) ||
					filterRegex.MatchString(pkt.Country)
			} else {
				match = true
				parts := strings.Fields(strings.ToLower(filterStr))
				lowProto := strings.ToLower(pkt.Protocol)
				lowSrc := strings.ToLower(pkt.SrcIP)
				lowDst := strings.ToLower(pkt.DstIP)
				lowInfo := strings.ToLower(pkt.Info)
				lowCountry := strings.ToLower(pkt.Country)

				for _, part := range parts {
					negate := strings.HasPrefix(part, "-")
					checkPart := part
					if negate {
						checkPart = strings.TrimPrefix(part, "-")
					}
					partMatch := strings.Contains(lowProto, checkPart) ||
						strings.Contains(lowSrc, checkPart) ||
						strings.Contains(lowDst, checkPart) ||
						strings.Contains(lowInfo, checkPart) ||
						strings.Contains(lowCountry, checkPart) ||
						((checkPart == "tcp-ao" || checkPart == "ao") && pkt.HasTcpAo)
					if negate {
						partMatch = !partMatch
					}

					// Functional CIDR support: if it looks like CIDR, perform a subnet check
					if !partMatch && strings.Contains(checkPart, "/") {
						if _, ipnet, err := net.ParseCIDR(checkPart); err == nil {
							found := ipnet.Contains(net.ParseIP(pkt.SrcIP)) || ipnet.Contains(net.ParseIP(pkt.DstIP))
							partMatch = found
							if negate {
								partMatch = !found
							}
						}
					}
					if !partMatch {
						match = false
						break
					}
				}
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
				if strings.HasPrefix(strings.ToLower(filterStr), "regex:") {
					filterRegex, _ = regexp.Compile("(?i)" + filterStr[6:])
				} else {
					filterRegex = nil
				}
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

	http.HandleFunc("/script.js", func(w http.ResponseWriter, r *http.Request) {
		data, err := content.ReadFile("script.js")
		if err != nil {
			http.Error(w, "Script not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(data)
	})

	http.HandleFunc("/ws", serveWs)
	fmt.Printf("Dashboard started! Access the browser dash at: http://localhost:8080\r\n")
	http.ListenAndServe(":8080", nil)
}
