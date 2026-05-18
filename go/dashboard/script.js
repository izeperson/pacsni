let packets = [];
let selectedIdx = -1;
let needsUpdate = false;
let searchQuery = '';
const ROW_HEIGHT = 32;
const VISIBLE_BUFFER = 5;

if (selectedIdx === -1) document.getElementById('pane-detail').innerHTML = '<div style="color:var(--muted); font-size:12px;">Select a packet for deep inspection</div>';
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

// Re-render visible window on scroll
paneList.addEventListener('scroll', () => { needsUpdate = true; });

window.addEventListener('click', () => { document.getElementById('context-menu').style.display = 'none'; });

function toggleTheme() {
    document.body.classList.toggle('light-mode');
    const isLight = document.body.classList.contains('light-mode');
    document.getElementById('theme-toggle').innerText = isLight ? 'Dark Mode' : 'Light Mode';
}

function updateSearch(val) {
    searchQuery = val.toLowerCase();
    needsUpdate = true;
}

function formatHex(b64) {
    if (!b64) return "";
    let bin;
    try {
        bin = atob(b64);
    } catch(e) {
        console.error("Base64 decode failed", e);
        return "[binary data]";
    }
    let hexPart = "", asciiPart = "", result = "";
    for (let i = 0; i < bin.length; i++) {
        const c = bin.charCodeAt(i);
        hexPart += c.toString(16).padStart(2, '0') + " ";
        asciiPart += (c >= 32 && c <= 126) ? bin[i] : ".";
        if ((i + 1) % 16 === 0 || i === bin.length - 1) {
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
    menu.innerHTML = `<div onclick="followStream('${pkt.src_ip}', ${pkt.src_port}, '${pkt.dst_ip}', ${pkt.dst_port})">Follow TCP Stream</div>`;
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

    document.getElementById('pane-detail').innerHTML = `
        <div class="detail-item"><b>Metadata</b>Frame #${pkt.index} - Captured ${pkt.payload ? (typeof pkt.payload === 'string' ? atob(pkt.payload).length : pkt.payload.length) : 0} bytes</div>
        <div class="detail-item"><b>Layer 2 (Ethernet)</b>Source: ${pkt.src_mac || 'ff:ff:ff:ff:ff:ff'} -> Destination: ${pkt.dst_mac || '00:00:00:00:00:00'}</div>
        <div class="detail-item"><b>Layer 3 (Internet)</b>Source IP: ${pkt.src_ip} -> Destination IP: ${pkt.dst_ip} [${pkt.country || 'Local'}]</div>
        <div class="detail-item"><b>Layer 4 (${pkt.protocol})</b>Port: ${pkt.src_port} -> Port: ${pkt.dst_port}</div>
    `;
    document.getElementById('pane-hex').innerHTML = formatHex(pkt.payload);
}

function displayData(data = {}) {
    if (data.packets) {
        packets = data.packets;
    }
    
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
    
    const filteredPackets = !searchQuery ? packets : packets.filter(p => 
        p.src_ip.toLowerCase().includes(searchQuery) ||
        p.dst_ip.toLowerCase().includes(searchQuery) ||
        p.protocol.toLowerCase().includes(searchQuery) ||
        p.info.toLowerCase().includes(searchQuery) ||
        (p.country && p.country.toLowerCase().includes(searchQuery))
    );

    const scrollTop = paneList.scrollTop;
    const containerHeight = paneList.clientHeight;
    
    const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - VISIBLE_BUFFER);
    const endIdx = Math.min(filteredPackets.length, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + VISIBLE_BUFFER);

    const visiblePackets = filteredPackets.slice(startIdx, endIdx);
    
    const paddingTop = startIdx * ROW_HEIGHT;
    const paddingBottom = (filteredPackets.length - endIdx) * ROW_HEIGHT;

    const rowsHtml = visiblePackets.map(pkt => 
        '<tr id="pkt-' + pkt.index + '" onclick="selectPacket(' + pkt.index + ')" oncontextmenu="showContextMenu(event, ' + pkt.index + ')" class="' + (pkt.index === selectedIdx ? 'selected' : '') + '">' +
            '<td style="padding-left:20px; color:var(--muted);">' + pkt.index + '</td>' +
            '<td>' + new Date(pkt.timestamp/1000).toLocaleTimeString([], {hour12:false}) + '</td>' +
            '<td>' + pkt.src_ip + '</td>' +
            '<td>' + pkt.dst_ip + '</td>' +
            '<td>' + (pkt.country || '—') + '</td>' +
            '<td><span class="proto-cell proto-' + (pkt.protocol || 'Unknown') + '">' + (pkt.protocol || 'Unknown') + '</span></td>' +
            '<td>' + (pkt.decodedLength || 0) + '</td>' +
            '<td style="color:var(--muted); font-size:11px;">' + pkt.info + '</td>' +
        '</tr>'
    ).join('');

    body.innerHTML = `<tr style="height: ${paddingTop}px"><td colspan="8"></td></tr>` + 
                        rowsHtml + 
                        `<tr style="height: ${paddingBottom}px"><td colspan="8"></td></tr>`;
    
    if (document.getElementById('auto-scroll').checked && selectedIdx === -1) {
        paneList.scrollTop = 0;
    }

    if (data.isScanning !== undefined) {
        const status = document.getElementById('status-label');
        status.innerText = data.isScanning ? "Active" : "Paused";
        status.className = data.isScanning ? "status-tag" : "status-tag status-paused";
    }
}

function updateTable() {
    fetch('/api/packets' + window.location.search)
        .then(res => res.json())
        .then(displayData);
}

function startWebSocket() {
    const proto = location.protocol === "https:" ? "wss://" : "ws://";
    const ws = new WebSocket(proto + location.host + "/ws");
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'packet') {
            try {
                msg.packet.decodedLength = msg.packet.payload ? atob(msg.packet.payload).length : 0;
            } catch(e) { msg.packet.decodedLength = 0; }
            
            packets.unshift(msg.packet);
            if (packets.length > 5000) packets.pop();
            needsUpdate = true;
        } else if (msg.type === 'geo_update') {
            packets.forEach(p => {
                if (p.src_ip === msg.ip || p.dst_ip === msg.ip) {
                    p.country = msg.country;
                }
            });
            needsUpdate = true;
        } else if (msg.type === 'status') {
            displayData(msg);
        } else if (msg.type === 'clear') {
            packets = [];
            needsUpdate = true;
        }
    };
    ws.onclose = () => setTimeout(startWebSocket, 2000);
}

setInterval(() => {
    if (needsUpdate) {
        displayData({packets});
        needsUpdate = false;
    }
}, 100);

updateTable();
startWebSocket();