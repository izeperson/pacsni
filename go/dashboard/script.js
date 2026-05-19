let packets = [];
let selectedIdx = -1;
let needsUpdate = false;
let searchQuery = '';
const ROW_HEIGHT = 32;
const VISIBLE_BUFFER = 5;
const SUGGESTIONS = ['tcp', 'udp', 'icmp', 'arp', 'nd', 'dns', 'ospf', 'stp', 'dhcp', 'http', 'tcp-ao', 'ao', 'regex:', 'stream:'];
let knownIPs = new Set();
let activeSuggestionIdx = -1;

if (selectedIdx === -1) document.getElementById('pane-detail').innerHTML = '<div style="color:var(--muted); font-size:12px;">Select a packet for deep inspection</div>';
const resizer = document.getElementById('resizer');
const resizerDetail = document.getElementById('resizer-detail');
const paneList = document.getElementById('pane-list');
const paneDetail = document.getElementById('pane-detail');
let isResizing = false;
let isResizingDetail = false;

resizer.addEventListener('mousedown', (e) => {
    isResizing = true;
    document.body.style.cursor = 'ns-resize';
    document.body.style.userSelect = 'none';
});

resizerDetail.addEventListener('mousedown', (e) => {
    isResizingDetail = true;
    document.body.style.cursor = 'ns-resize';
    document.body.style.userSelect = 'none';
});

window.addEventListener('mousemove', (e) => {
    const toolbarHeight = document.querySelector('.toolbar').offsetHeight;
    if (isResizing) {
        const newHeight = e.clientY - toolbarHeight;
        if (newHeight > 100 && newHeight < window.innerHeight - 150) {
            paneList.style.height = newHeight + 'px';
        }
    } else if (isResizingDetail) {
        const listHeight = paneList.offsetHeight;
        const topResizerHeight = resizer.offsetHeight;
        const newDetailHeight = e.clientY - toolbarHeight - listHeight - topResizerHeight;
        if (newDetailHeight > 50 && newDetailHeight < window.innerHeight - listHeight - 150) {
            paneDetail.style.height = newDetailHeight + 'px';
        }
    }
});

window.addEventListener('mouseup', () => {
    isResizing = false;
    isResizingDetail = false;
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

function updateFilterHighlight() {
    const input = document.getElementById('filter-input');
    const display = document.getElementById('filter-highlight');
    if (!input || !display) return;

    let val = input.value;
    if (!val) {
        display.innerHTML = '<span style="opacity:0.4">Filter packets (e.g. tcp -80)</span>';
        return;
    }

    const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    let highlighted = escape(val)
        .replace(/\b-(tcp|udp|icmp|tcp-ao|ao)\b/gi, '<span class="hl-neg">$&</span>')
        .replace(/\b-(?=[a-z0-9])/gi, '<span class="hl-neg">-</span>')
        .replace(/^(regex:)(.*)/i, '<span class="hl-key">$1</span><span class="hl-regex">$2</span>')
        .replace(/^(stream:)([^:]+)(:)([0-9]+)(:)([^:]+)(:)([0-9]+)/i, '<span class="hl-key">$1</span>$2$3<span class="hl-num">$4</span>$5$6$7<span class="hl-num">$8</span>')
        .replace(/^(stream:)/i, '<span class="hl-key">$1</span>')
        .replace(/\b(tcp|udp|icmp|arp|nd|dns|ospf|stp|dhcp|http|tcp-ao|ao)\b/gi, (m, p1, offset) => {
             return val[offset-1] === '-' ? m : `<span class="hl-proto">${m}</span>`;
        })
        .replace(/\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\/[0-9]{1,2})?)\b/g, '<span class="hl-num">$&</span>');

    display.innerHTML = highlighted;
}

function handleFilterInput(e) {
    updateFilterHighlight();
    const val = e.target.value;
    const box = document.getElementById('autocomplete-box');
    
    if (!val || val.includes('regex:') || val.includes('stream:')) {
        box.style.display = 'none';
        return;
    }

    const parts = val.split(/\s+/);
    const lastPart = parts[parts.length - 1].toLowerCase().replace(/^-/, '');
    
    if (lastPart.length < 1) {
        box.style.display = 'none';
        return;
    }

    const allSuggestions = [...SUGGESTIONS, ...Array.from(knownIPs)];
    const matches = allSuggestions.filter(s => s.startsWith(lastPart) && s !== lastPart);
    
    if (matches.length > 0) {
        activeSuggestionIdx = -1;
        box.innerHTML = matches.map((m, i) => `<div class="suggestion-item" onclick="applySuggestion('${m}')">${m}</div>`).join('');
        box.style.display = 'block';
    } else {
        box.style.display = 'none';
    }
}

function handleFilterKey(e) {
    const box = document.getElementById('autocomplete-box');
    if (box.style.display === 'none') return;

    const items = box.getElementsByClassName('suggestion-item');
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeSuggestionIdx = (activeSuggestionIdx + 1) % items.length;
        updateActiveSuggestion(items);
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeSuggestionIdx = (activeSuggestionIdx - 1 + items.length) % items.length;
        updateActiveSuggestion(items);
    } else if (e.key === 'Enter' && activeSuggestionIdx > -1) {
        e.preventDefault();
        applySuggestion(items[activeSuggestionIdx].innerText);
    } else if (e.key === 'Escape') {
        box.style.display = 'none';
    }
}

function updateActiveSuggestion(items) {
    for (let i = 0; i < items.length; i++) {
        items[i].classList.toggle('active', i === activeSuggestionIdx);
    }
}

function applySuggestion(word) {
    const input = document.getElementById('filter-input');
    const parts = input.value.split(/\s+/);
    const last = parts[parts.length - 1];
    const prefix = last.startsWith('-') ? '-' : '';
    
    parts[parts.length - 1] = prefix + word;
    input.value = parts.join(' ') + ' ';
    input.focus();
    document.getElementById('autocomplete-box').style.display = 'none';
    updateFilterHighlight();
}

function ipInCIDR(ip, cidr) {
    try {
        const [range, bits] = cidr.split('/');
        const mask = ~(Math.pow(2, 32 - bits) - 1);
        const ipNum = ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
        const rangeNum = range.split('.').reduce((acc, oct) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
        return (ipNum & mask) === (rangeNum & mask);
    } catch (e) { return false; }
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
    let result = "";
    for (let i = 0; i < bin.length; i += 16) {
        result += `<span style="color:var(--muted)">${i.toString(16).padStart(4, '0')}</span>   `;
        let hexPart = "";
        let asciiPart = "";
        for (let j = 0; j < 16; j++) {
            const idx = i + j;
            if (idx < bin.length) {
                const c = bin.charCodeAt(idx);
                const hex = c.toString(16).padStart(2, '0');
                const char = (c >= 32 && c <= 126) ? bin[idx] : ".";
                hexPart += `<span class="hex-byte" data-offset="${idx}">${hex}</span> `;
                asciiPart += `<span class="hex-byte" data-offset="${idx}">${char === ' ' ? '&nbsp;' : (char === '<' ? '&lt;' : (char === '>' ? '&gt;' : char))}</span>`;
            } else {
                hexPart += "   ";
            }
        }
        result += hexPart + '   <span style="color:#60a5fa">' + asciiPart + '</span>\n';
    }
    return result;
}

function showContextMenu(e, idx) {
    e.preventDefault();
    const pkt = packets.find(p => p.index === idx);
    if (!pkt) return;

    const menu = document.getElementById('context-menu');
    menu.style.display = 'block';
    menu.style.left = e.pageX + 'px';
    menu.style.top = e.pageY + 'px';
    
    let html = '';
    if (pkt.protocol === 'TCP') {
        html += `<div onclick="followStream('${pkt.src_ip}', ${pkt.src_port}, '${pkt.dst_ip}', ${pkt.dst_port})">Follow TCP Stream</div>`;
    }
    html += `<div onclick="copyAsCArray(${idx})">Copy as C Array</div>`;
    menu.innerHTML = html;
}

function copyAsCArray(idx) {
    const pkt = packets.find(p => p.index === idx);
    if (!pkt) return;
    const bin = atob(pkt.payload);
    let hex = 'unsigned char pkt[] = {\n    ';
    for (let i = 0; i < bin.length; i++) {
        hex += '0x' + bin.charCodeAt(i).toString(16).padStart(2, '0');
        if (i < bin.length - 1) hex += (i % 12 === 11) ? ',\n    ' : ', ';
    }
    hex += '\n};';
    navigator.clipboard.writeText(hex).then(() => alert('Copied to clipboard!'));
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

    const l3 = pkt.l3_offset || 14;
    const l4 = pkt.l4_offset || 34;

    document.getElementById('pane-detail').innerHTML = `
        <div class="detail-item" data-layer="meta"><b>Metadata</b>Frame #${pkt.index} - Captured ${pkt.payload ? (typeof pkt.payload === 'string' ? atob(pkt.payload).length : pkt.payload.length) : 0} bytes</div>
        <div class="detail-item" data-layer="l2" onmouseover="highlightHexRange(0, ${l3}, true)" onmouseout="highlightHexRange(0, ${l3}, false)"><b>Layer 2 (Ethernet)</b>
            Source: ${pkt.src_mac || 'ff:ff:ff:ff:ff:ff'}${pkt.src_mac_vendor ? ` (${pkt.src_mac_vendor})` : ''} ->
            Destination: ${pkt.dst_mac || '00:00:00:00:00:00'}${pkt.dst_mac_vendor ? ` (${pkt.dst_mac_vendor})` : ''}
        </div>
        <div class="detail-item" data-layer="l3" onmouseover="highlightHexRange(${l3}, ${l4}, true)" onmouseout="highlightHexRange(${l3}, ${l4}, false)"><b>Layer 3 (Internet)</b>Source IP: ${pkt.src_ip} -> Destination IP: ${pkt.dst_ip} [${pkt.country || 'Local'}]</div>
        <div class="detail-item" data-layer="l4" onmouseover="highlightHexRange(${l4}, -1, true)" onmouseout="highlightHexRange(${l4}, -1, false)"><b>Layer 4 (${pkt.protocol})</b>Port: ${pkt.src_port} -> Port: ${pkt.dst_port}${pkt.has_tcp_ao ? ' <span class="badge-ao" title="TCP Authentication Option (RFC 5925)" style="cursor:help; margin-left:10px;" onclick="alert(\'RFC 5925 (TCP-AO): Provides authentication for TCP segments, protecting against spoofing and connection hijacking by signing segments with shared secrets.\')">AO</span>' : ''}</div>
    `;
    document.getElementById('pane-hex').innerHTML = formatHex(pkt.payload);
}

function highlightHexRange(start, end, active) {
    const bytes = document.querySelectorAll('.hex-byte');
    bytes.forEach(b => {
        const off = parseInt(b.getAttribute('data-offset'));
        if (off >= start && (end === -1 || off < end)) {
            b.classList.toggle('hover', active);
        }
    });
}

// Event delegation for the Hex Pane
document.getElementById('pane-hex').addEventListener('mouseover', (e) => {
    const target = e.target.closest('.hex-byte');
    if (target) {
        const offset = target.getAttribute('data-offset');
        const pkt = packets.find(p => p.index === selectedIdx);
        if (!pkt) return;

        // Highlight all spans sharing this offset (Hex and ASCII part)
        document.querySelectorAll(`.hex-byte[data-offset="${offset}"]`).forEach(el => el.classList.add('hover'));
        
        let layer = "l4";
        const off = parseInt(offset);
        if (off < (pkt.l3_offset || 14)) layer = "l2";
        else if (off < (pkt.l4_offset || 34)) layer = "l3";

        const detail = document.getElementById('pane-detail').querySelector(`.detail-item[data-layer="${layer}"]`);
        if (detail) detail.classList.add('highlight');
    }
});

document.getElementById('pane-hex').addEventListener('mouseout', (e) => {
    if (e.target.classList.contains('hex-byte')) {
        const offset = e.target.getAttribute('data-offset');
        document.querySelectorAll(`.hex-byte[data-offset="${offset}"]`).forEach(el => el.classList.remove('hover'));
        document.querySelectorAll('.detail-item').forEach(el => el.classList.remove('highlight'));
    }
});

document.getElementById('pane-hex').addEventListener('contextmenu', (e) => {
    if (selectedIdx !== -1) {
        showContextMenu(e, selectedIdx);
    }
});

function displayData(data = {}) {
    if (data.packets) {
        packets = data.packets;
        packets.forEach(p => {
            if (p.decodedLength === undefined) {
                try {
                    p.decodedLength = p.payload ? atob(p.payload).length : 0;
                } catch(e) { p.decodedLength = 0; }
            }
        });
    }
    
    if (data.ips) {
        data.ips.forEach(ip => knownIPs.add(ip));
    }

    const body = document.getElementById('packet-body');
    
    const filteredPackets = !searchQuery ? packets : packets.filter(p => {
        if (searchQuery.startsWith('regex:')) {
            try {
                const re = new RegExp(searchQuery.substring(6), 'i');
                return re.test(p.src_ip) || re.test(p.dst_ip) || re.test(p.protocol) || re.test(p.info) || (p.country && re.test(p.country));
            } catch(e) { return false; }
        }
        const parts = searchQuery.split(/\s+/).filter(part => part.length > 0);
        return parts.every(part => {
            const negate = part.startsWith('-');
            const check = negate ? part.substring(1) : part;
            if (!check) return true;
            
            const found = p.src_ip.toLowerCase().includes(check) ||
                p.dst_ip.toLowerCase().includes(check) ||
                p.protocol.toLowerCase().includes(check) ||
                (p.src_mac_vendor && p.src_mac_vendor.toLowerCase().includes(check)) ||
                (p.dst_mac_vendor && p.dst_mac_vendor.toLowerCase().includes(check)) ||
                p.info.toLowerCase().includes(check) ||
                (p.country && p.country.toLowerCase().includes(check));
            
            if (!found && check.includes('/')) {
                found = ipInCIDR(p.src_ip, check) || ipInCIDR(p.dst_ip, check);
            }

            if (!found) found = ((check === 'tcp-ao' || check === 'ao') && p.has_tcp_ao);
                
            return negate ? !found : found;
        });
    });

    const scrollTop = paneList.scrollTop;
    const containerHeight = paneList.clientHeight;
    
    const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - VISIBLE_BUFFER);
    const endIdx = Math.min(filteredPackets.length, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + VISIBLE_BUFFER);

    const visiblePackets = filteredPackets.slice(startIdx, endIdx);
    
    const paddingTop = startIdx * ROW_HEIGHT;
    const paddingBottom = (filteredPackets.length - endIdx) * ROW_HEIGHT;

    const rowsHtml = visiblePackets.map(pkt => 
        '<tr id="pkt-' + pkt.index + '" onclick="selectPacket(' + pkt.index + ')" oncontextmenu="showContextMenu(event, ' + pkt.index + ')" class="' + (pkt.index === selectedIdx ? 'selected' : '') + (pkt.decodedLength === 0 ? ' empty-packet' : '') + '">' +
            '<td style="padding-left:20px; color:var(--muted);">' + pkt.index + '</td>' +
            '<td>' + new Date(pkt.timestamp/1000).toLocaleTimeString([], {hour12:false}) + '</td>' +
            '<td>' + pkt.src_ip + '</td>' +
            '<td>' + pkt.dst_ip + '</td>' +
            '<td>' + (pkt.country || '—') + '</td>' +
            '<td><span class="proto-cell proto-' + (pkt.protocol || 'Unknown') + '">' + (pkt.protocol || 'Unknown') + '</span>' + (pkt.has_tcp_ao ? ' <span class="badge-ao" title="TCP Authentication Option (RFC 5925)" style="cursor:help;" onclick="event.stopPropagation(); alert(\'RFC 5925 (TCP-AO): Provides cryptographic authentication for TCP segments using Key Chains.\')">AO</span>' : '') + '</td>' +
            '<td class="' + (pkt.decodedLength === 0 ? 'len-zero' : '') + '">' + (pkt.decodedLength || 0) + '</td>' +
            '<td style="color:var(--muted); font-size:11px;">' + pkt.info + '</td>' +
        '</tr>'
    ).join('');

    body.innerHTML = `<tr style="height: ${paddingTop}px; border:none;"><td colspan="8" style="padding:0; border:none; height:${paddingTop}px"></td></tr>` + 
                        rowsHtml + 
                        `<tr style="height: ${paddingBottom}px; border:none;"><td colspan="8" style="padding:0; border:none; height:${paddingBottom}px"></td></tr>`;
    
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

function updateLoop() {
    if (needsUpdate) {
        displayData({packets});
        needsUpdate = false;
    }
    requestAnimationFrame(updateLoop);
}
requestAnimationFrame(updateLoop);

updateFilterHighlight();
updateTable();
startWebSocket();