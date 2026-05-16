package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// DashboardPacket matches the Rust struct
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
}

// getPacketInfo generates a Wireshark-style summary string
func getPacketInfo(pkt *DashboardPacket) string {
	switch pkt.Protocol {
	case "TCP":
		return fmt.Sprintf("%d → %d [ack] seq=0 ack=0 win=64240 len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "UDP":
		return fmt.Sprintf("%d → %d len=%d", pkt.SrcPort, pkt.DstPort, len(pkt.Payload))
	case "ICMP":
		return "echo (ping) request"
	default:
		return fmt.Sprintf("protocol %s message", strings.ToLower(pkt.Protocol))
	}
}

var (
	packetHistory []DashboardPacket
	isScanning    = true
	filterStr     = ""
	packetCounter = 0
	seenIPs       = make(map[string]bool)
	mu            sync.Mutex
)

func main() {
	// Connect to the Rust service's broadcast port
	conn, err := net.Dial("tcp", "127.0.0.1:9003")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not connect to Rust service on 127.0.0.1:9003. Ensure the Rust service is running.\nOriginal error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Start a goroutine to read from Rust and update our history
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			mu.Lock()
			if isScanning {
				var pkt DashboardPacket
				if err := json.Unmarshal(scanner.Bytes(), &pkt); err == nil {
					packetCounter++
					pkt.Index = packetCounter
					pkt.Info = getPacketInfo(&pkt)
					seenIPs[pkt.SrcIP] = true
					seenIPs[pkt.DstIP] = true

					// Advanced filtering logic
					match := false
					if filterStr == "" {
						match = true
					} else if strings.HasPrefix(filterStr, "STREAM:") {
						f := strings.Split(filterStr, ":")
						if len(f) == 5 && pkt.Protocol == "TCP" {
							// Match bi-directional flow: (Src1:Port1 -> Dst1:Port1) OR (Dst1:Port1 -> Src1:Port1)
							match = (pkt.SrcIP == f[1] && fmt.Sprintf("%d", pkt.SrcPort) == f[2] && pkt.DstIP == f[3] && fmt.Sprintf("%d", pkt.DstPort) == f[4]) ||
								(pkt.SrcIP == f[3] && fmt.Sprintf("%d", pkt.SrcPort) == f[4] && pkt.DstIP == f[1] && fmt.Sprintf("%d", pkt.DstPort) == f[2])
						}
					} else {
						match = strings.Contains(strings.ToLower(pkt.Protocol), strings.ToLower(filterStr)) ||
							strings.Contains(pkt.SrcIP, filterStr) ||
							strings.Contains(pkt.DstIP, filterStr)
					}

					if match {
						packetHistory = append([]DashboardPacket{pkt}, packetHistory...)
						if len(packetHistory) > 100 {
							packetHistory = packetHistory[:100]
						}
					}
				}
			}
			mu.Unlock()
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from Rust service: %v\n", err)
		}
	}()

	// API endpoint for raw packet data
	http.HandleFunc("/api/packets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		ips := make([]string, 0, len(seenIPs))
		for ip := range seenIPs {
			ips = append(ips, ip)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"packets":    packetHistory,
			"isScanning": isScanning,
			"filter":     filterStr,
			"ips":        ips,
		})
	})

	// Serve the web dashboard
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Handle Controls
		query := r.URL.Query()
		action := query.Get("action")
		if action == "clear" {
			mu.Lock()
			packetHistory = []DashboardPacket{}
			mu.Unlock()
		} else if action == "toggle" {
			mu.Lock()
			isScanning = !isScanning
			mu.Unlock()

			// Redirect to clean the URL. This prevents the 'action=toggle' from
			// remaining in the URL and causing a flip-flop during refreshes.
			query.Del("action")
			r.URL.RawQuery = query.Encode()
			http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
			return
		}

		if f, ok := query["filter"]; ok {
			mu.Lock()
			if filterStr != f[0] {
				filterStr = f[0]
				packetHistory = []DashboardPacket{} // Clear history on filter change
			}
			mu.Unlock()
		}

		mu.Lock()
		btnText, statusLabel := "start", "paused"
		if isScanning {
			btnText, statusLabel = "stop", "active"
		}
		currentFilter := filterStr
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		bt := "`"
		html := `
		<html>
		<head>
			<title>pacsni | terminal</title>
			<link rel="stylesheet" href="https://rsms.me/inter/inter.css">
			<style>
				:root {
					--bg: #09090b; --surf: #18181b; --border: #27272a;
					--text: #e4e4e7; --muted: #a1a1aa; --accent: #3f3f46; --highlight: #3b82f6;
				}
				body { font-family: 'inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; display: flex; flex-direction: column; height: 100vh; overflow: hidden; text-transform: lowercase; }
				
				/* Custom Scrollbar */
				::-webkit-scrollbar { width: 8px; height: 8px; }
				::-webkit-scrollbar-track { background: var(--bg); }
				::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
				::-webkit-scrollbar-thumb:hover { background: #3f3f46; }

				.toolbar { background: var(--surf); padding: 10px 20px; display: flex; gap: 15px; border-bottom: 1px solid var(--border); align-items: center; z-index: 50; }
				.toolbar h1 { margin: 0; font-size: 16px; font-weight: 800; color: white; letter-spacing: -0.05em; margin-right: 20px; }
				
				.pane-list { height: 70%%; flex: none; overflow-y: auto; border-bottom: 1px solid var(--border); }
				.resizer { height: 6px; background: var(--border); cursor: ns-resize; flex-shrink: 0; transition: background 0.2s; z-index: 100; border-top: 1px solid var(--bg); border-bottom: 1px solid var(--bg); }
				.resizer:hover { background: var(--highlight); }
				.pane-detail { height: 15%%; flex: none; overflow-y: auto; background: var(--surf); padding: 15px; border-bottom: 1px solid var(--border); }
				.pane-hex { flex: 1; overflow-y: auto; background: var(--bg); font-family: 'fira code', monospace; padding: 15px; font-size: 11px; white-space: pre; color: #10b981; }
				
				table { width: 100%%; border-collapse: collapse; table-layout: fixed; }
				th { background: var(--surf); position: sticky; top: 0; text-align: left; padding: 10px 8px; font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; border-bottom: 1px solid var(--border); }
				td { padding: 8px; font-size: 12px; border-bottom: 1px solid rgba(255,255,255,0.02); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; cursor: pointer; transition: background 0.1s; }
				tr:hover { background: rgba(255,255,255,0.03); }
				tr.selected { background: var(--highlight) !important; color: white; }
				
				/* Protocol Badges */
				.proto-cell { font-weight: 700; font-size: 10px; padding: 2px 6px; border-radius: 4px; background: #27272a; }
				.proto-TCP { color: #eee; }
				.proto-UDP { color: #ccc; }
				.proto-ICMP { color: #aaa; }
				
				.detail-item { margin-bottom: 6px; font-size: 13px; border-left: 2px solid var(--border); padding-left: 10px; }
				.detail-item b { color: var(--muted); display: block; font-size: 11px; text-transform: lowercase; margin-bottom: 2px; }
				.selected .detail-item b { color: white; opacity: 0.8; }

				.btn { background: var(--surf); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
				.btn:hover { border-color: var(--muted); background: #27272a; }
				.btn-primary { background: #3b82f6; border-color: #3b82f6; color: white; }
				.btn-primary:hover { background: #2563eb; border-color: #2563eb; }
				
				input { background: var(--bg); border: 1px solid var(--border); padding: 6px 12px; border-radius: 6px; color: white; width: 300px; font-size: 12px; }
				input:focus { outline: none; border-color: var(--accent); }

				.status-tag { font-size: 10px; padding: 2px 8px; border-radius: 10px; background: rgba(16, 185, 129, 0.1); color: #10b981; }
				.status-paused { background: rgba(244, 63, 94, 0.1); color: #f43f5e; }

				/* Context Menu */
				#context-menu {
					position: fixed; background: var(--surf); border: 1px solid var(--border);
					display: none; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
					border-radius: 4px; padding: 5px 0; min-width: 150px;
				}
				#context-menu div { padding: 8px 15px; cursor: pointer; font-size: 12px; color: var(--text); }
				#context-menu div:hover { background: var(--highlight); color: white; }

				.settings-group { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); margin-left: 10px; border-left: 1px solid var(--border); padding-left: 15px; }
			</style>
		</head>
		<body>
			<div id="context-menu"></div>
			<div class="toolbar">
				<h1>pacsni</h1>
				<form method="GET" style="margin:0; display:flex; gap:10px;">
					<button name="action" value="toggle" class="btn btn-primary">%s</button>
					<button name="action" value="clear" class="btn">clear history</button>
					<input type="text" name="filter" list="filter-suggestions" placeholder="filter packets (e.g. tcp, stream...)" value="%s">
					<datalist id="filter-suggestions">
						<option value="tcp">
						<option value="udp">
						<option value="icmp">
						<option value="127.0.0.1">
						<option value="stream:127.0.0.1:">
					</datalist>
					<button type="submit" class="btn">apply filter</button>
				</form>
				<div class="settings-group">
					<label>auto-scroll</label>
					<input type="checkbox" id="auto-scroll" checked style="width: auto;">
					<label style="margin-left: 10px;">refresh rate</label>
					<select id="refresh-rate" class="btn" style="padding: 2px 5px;"><option value="1000">1s</option><option value="500">0.5s</option><option value="2000">2s</option></select>
				</div>
				<div id="status-label" class="status-tag" style="margin-left: auto;">%s</div>
			</div>

			<div class="pane-list" id="pane-list">
				<table>
					<thead>
						<tr>
							<th style="width:60px; padding-left:20px;">no.</th>
							<th style="width:100px;">time</th>
							<th style="width:150px;">source</th>
							<th style="width:150px;">destination</th>
							<th style="width:100px;">protocol</th>
							<th style="width:80px;">length</th>
							<th style="width:auto;">info</th>
						</tr>
					</thead>
					<tbody id="packet-body"></tbody>
				</table>
			</div>
			<div class="resizer" id="resizer"></div>

			<div class="pane-detail" id="pane-detail"></div>

			<div class="pane-hex" id="pane-hex"></div>

			<script>
				let packets = [];
				let selectedIdx = -1;
				let refreshTimer = null;
				if (selectedIdx === -1) document.getElementById('pane-detail').innerHTML = '<div style="color:var(--muted); font-size:12px;">select a packet for deep inspection</div>';

				// resizer logic
				const resizer = document.getElementById('resizer');
				const paneList = document.getElementById('pane-list');
				let isResizing = false;

				resizer.addEventListener('mousedown', (e) => {
					isResizing = true;
					document.body.style.cursor = 'ns-resize';
					document.body.style.userSelect = 'none';
				});

				window.addEventListener('mousemove', (e) => {
					if (!isResizing) return;
					const toolbarHeight = document.querySelector('.toolbar').offsetHeight;
					const newHeight = e.clientY - toolbarHeight;
					if (newHeight > 100 && newHeight < window.innerHeight - 200) {
						paneList.style.height = newHeight + 'px';
					}
				});

				window.addEventListener('mouseup', () => {
					isResizing = false;
					document.body.style.cursor = 'default';
					document.body.style.userSelect = 'auto';
				});

				window.addEventListener('click', () => { document.getElementById('context-menu').style.display = 'none'; });

				function formatHex(b64) {
					if (!b64) return "";
					const bin = atob(b64);
					let hexPart = "", asciiPart = "", result = "";
					for (let i = 0; i < bin.length; i++) {
						const c = bin.charCodeAt(i);
						hexPart += c.toString(16).padStart(2, '0') + " ";
						asciiPart += (c >= 32 && c <= 126) ? bin[i] : ".";
						if ((i + 1) %% 16 === 0 || i === bin.length - 1) {
							result += '<span style="color:var(--muted)">' + i.toString(16).padStart(4, '0') + '</span>   ' + hexPart.padEnd(48) + '   <span style="color:#60a5fa">' + asciiPart + '</span>\n';
							hexPart = ""; asciiPart = "";
						}
					}
					return result;
				}

				function showContextMenu(e, idx) {
					e.preventDefault();
					const pkt = packets.find(p => p.index === idx);
					if (!pkt || pkt.protocol !== 'TCP') return;

					const menu = document.getElementById('context-menu');
					menu.style.display = 'block';
					menu.style.left = e.pageX + 'px';
					menu.style.top = e.pageY + 'px';
					menu.innerHTML = %s<div onclick="followStream('${pkt.src_ip}', ${pkt.src_port}, '${pkt.dst_ip}', ${pkt.dst_port})">follow tcp stream</div>%s;
				}

				function followStream(src, sport, dst, dport) {
					window.location.href = '/?filter=stream:' + src + ':' + sport + ':' + dst + ':' + dport;
				}

				function selectPacket(idx) {
					selectedIdx = idx;
					const pkt = packets.find(p => p.index === idx);
					if (!pkt) return;

					document.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
					document.getElementById('pkt-' + idx).classList.add('selected');

					document.getElementById('pane-detail').innerHTML = %s
						<div class="detail-item"><b>metadata</b>frame #${pkt.index} — captured ${pkt.payload ? atob(pkt.payload).length : 0} bytes</div>
						<div class="detail-item"><b>layer 2 (ethernet)</b>source: ff:ff:ff:ff:ff:ff → destination: 00:00:00:00:00:00</div>
						<div class="detail-item"><b>layer 3 (internet)</b>source ip: ${pkt.src_ip} → destination ip: ${pkt.dst_ip}</div>
						<div class="detail-item"><b>layer 4 (${pkt.protocol.toLowerCase()})</b>port: ${pkt.src_port} → port: ${pkt.dst_port}</div>
					%s;
					document.getElementById('pane-hex').innerHTML = formatHex(pkt.payload);
				}

				function updateTable() {
					fetch('/api/packets' + window.location.search)
						.then(res => res.json())
						.then(data => {
							packets = data.packets;
							const dl = document.getElementById('filter-suggestions');
							if (data.ips) {
								const currentIPs = Array.from(dl.options).map(o => o.value);
								data.ips.forEach(ip => {
									if (!currentIPs.includes(ip)) {
										const opt = document.createElement('option');
										opt.value = ip;
										dl.appendChild(opt);
										const optStream = document.createElement('option');
										optStream.value = 'stream:' + ip + ':';
										dl.appendChild(optStream);
									}
								});
							}

							const body = document.getElementById('packet-body');
							body.innerHTML = data.packets.map(pkt => 
								'<tr id="pkt-' + pkt.index + '" onclick="selectPacket(' + pkt.index + ')" oncontextmenu="showContextMenu(event, ' + pkt.index + ')" class="' + (pkt.index === selectedIdx ? 'selected' : '') + '">' +
									'<td style="padding-left:20px; color:var(--muted);">' + pkt.index + '</td>' +
									'<td>' + new Date(pkt.timestamp/1000).toLocaleTimeString([], {hour12:false}) + '</td>' +
									'<td>' + pkt.src_ip + '</td>' +
									'<td>' + pkt.dst_ip + '</td>' +
									'<td><span class="proto-cell proto-' + pkt.protocol + '">' + pkt.protocol.toLowerCase() + '</span></td>' +
									'<td>' + (pkt.payload ? atob(pkt.payload).length : 0) + '</td>' +
									'<td style="color:var(--muted); font-size:11px;">' + pkt.info + '</td>' +
								'</tr>'
							).join('');
							
							if (document.getElementById('auto-scroll').checked && selectedIdx === -1) {
								const list = document.querySelector('.pane-list');
								list.scrollTop = 0;
							}

							const status = document.getElementById('status-label');
							status.innerText = data.isScanning ? "live feed" : "paused";
							status.className = data.isScanning ? "status-tag" : "status-tag status-paused";
						});
				}

				function setRefresh() {
					if (refreshTimer) clearInterval(refreshTimer);
					const rate = document.getElementById('refresh-rate').value;
					refreshTimer = setInterval(() => { if (%t) updateTable(); }, rate);
				}

				document.getElementById('refresh-rate').addEventListener('change', setRefresh);
				setRefresh();
				updateTable();
			</script>
		</body>
		</html>`

		fmt.Fprintf(w, html,
			strings.ToLower(btnText), currentFilter, statusLabel,
			bt, bt, bt, bt, isScanning,
		)
	})

	fmt.Println("Dashboard started! Access the browser dash at: http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
