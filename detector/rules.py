# Tunable thresholds
SYN_FLOOD_THRESHOLD  = 5   # SYNs per second from 1 IP
PORT_SCAN_THRESHOLD  = 5    # unique ports hit in 1 second

def check_rules(f):
    """
    f = feature dict from extract_features()
    Returns an alert dict, or None if traffic looks normal.
    """
    flags = f['flags']
    src   = f['src_ip']
    dst   = f['dst_ip']
    port  = f['dport']

    # ── SYN Flood ─────────────────────────────────
    if 'S' in flags and 'A' not in flags:
        if f['syn_rate'] > SYN_FLOOD_THRESHOLD:
            return _alert('SYN FLOOD', src, dst, port, 'HIGH',
                          f'SYN rate: {f["syn_rate"]}/sec')

    # ── Port Scan ─────────────────────────────────
    if f['ports_hit'] > PORT_SCAN_THRESHOLD:
        return _alert('PORT SCAN', src, dst, port, 'MEDIUM',
                      f'Ports hit: {f["ports_hit"]}')

    # ── NULL Scan (no flags) ──────────────────────
    if flags == '' or str(flags) == '0':
        return _alert('NULL SCAN', src, dst, port, 'MEDIUM',
                      'No TCP flags set')

    # ── XMAS Scan (FIN+PSH+URG) ──────────────────
    if 'F' in flags and 'P' in flags and 'U' in flags:
        return _alert('XMAS SCAN', src, dst, port, 'MEDIUM',
                      'FIN+PSH+URG flags')

    # ── FIN Scan (FIN with no session) ────────────
    if 'F' in flags and 'A' not in flags and not f['has_session']:
        return _alert('FIN SCAN', src, dst, port, 'MEDIUM',
                      'FIN with no prior session')

    # ── RST Injection ─────────────────────────────
    if 'R' in flags and not f['has_session']:
        return _alert('RST INJECTION', src, dst, port, 'HIGH',
                      'RST with no session')

    return None   # No attack detected

def _alert(attack_type, src, dst, port, severity, detail):
    return {
        "attack_type": attack_type,
        "src_ip":      src,
        "dst_ip":      dst,
        "port":        port,
        "severity":    severity,
        "detail":      detail,
    }
