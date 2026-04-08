# =============================================================================
# mtk-go-kaskad.rsc
# =============================================================================

# =============================================================================
# 1. ОПРЕДЕЛЕНИЕ ХОСТОВ
# =============================================================================

# Формат: { "IP"; {tcp_ports}; {udp_ports} }
:local HOSTS {
    {"35.1.11.5"; {80;443}; {}}
    {"3.68.87.68"; {}; {1194;500;4500}}
    # {"10.0.0.10"; {22;8080}; {53}}   # Пример добавления нового хоста
}

:local WAN_INTERFACE "ether1"
:local ENABLE_LOGGING false
:local ENABLE_INPUT_RULES true
:local USE_STRICT_MASQUERADE true

# =============================================================================
# 2. ОЧИСТКА И БАЗОВЫЕ НАСТРОЙКИ
# =============================================================================

:put "=== Cleaning old KASKAD rules ==="
/ip firewall nat remove [find comment~"KASKAD"]
/ip firewall filter remove [find comment~"KASKAD"]

:put "=== System settings ==="
/ip settings set ip-forward=yes
/ip settings set tcp-syncookies=yes

# =============================================================================
# 3. ОСНОВНОЕ ПРАВИЛО FORWARD
# =============================================================================

:put "=== Forward rules ==="
/ip firewall filter add chain=forward action=accept comment="KASKAD_ALLOW_FORWARD"

# =============================================================================
# 4. ГЕНЕРАЦИЯ ПРАВИЛ ДЛЯ ВСЕХ ХОСТОВ
# =============================================================================

:put "=== Generating NAT rules ==="

:local tcp_ports_for_fasttrack {}
:local udp_ports_for_fasttrack {}

:foreach host in=$HOSTS do={
    :local target_ip [:tostr ($host->0)]
    :local tcp_ports ($host->1)
    :local udp_ports ($host->2)
    
    # TCP правила
    :foreach port in=$tcp_ports do={
        /ip firewall nat add chain=dstnat \
            in-interface=$WAN_INTERFACE \
            protocol=tcp dst-port=$port \
            action=dst-nat to-addresses=$target_ip to-ports=$port \
            comment="KASKAD_TCP_${port}_TO_${target_ip}"
        :put "  TCP $port -> $target_ip"
        
        # Собираем порты для FastTrack
        :set tcp_ports_for_fasttrack ($tcp_ports_for_fasttrack, $port)
    }
    
    # UDP правила
    :foreach port in=$udp_ports do={
        /ip firewall nat add chain=dstnat \
            in-interface=$WAN_INTERFACE \
            protocol=udp dst-port=$port \
            action=dst-nat to-addresses=$target_ip to-ports=$port \
            comment="KASKAD_UDP_${port}_TO_${target_ip}"
        :put "  UDP $port -> $target_ip"
        
        # Собираем порты для FastTrack
        :set udp_ports_for_fasttrack ($udp_ports_for_fasttrack, $port)
    }
    
    # Masquerade для этого хоста (если включен strict mode)
    if ($USE_STRICT_MASQUERADE = true) do={
        /ip firewall nat add chain=srcnat \
            dst-address=$target_ip \
            out-interface=$WAN_INTERFACE \
            action=masquerade \
            comment="KASKAD_MASQ_TO_${target_ip}"
        :put "  Masquerade for $target_ip"
    }
}

# Широкий masquerade (если не strict)
if ($USE_STRICT_MASQUERADE = false) do={
    /ip firewall nat add chain=srcnat \
        out-interface=$WAN_INTERFACE \
        action=masquerade \
        comment="KASKAD_MASQUERADE_ALL"
    :put "  Wide masquerade enabled"
}

# =============================================================================
# 5. INPUT ПРАВИЛА
# =============================================================================

if ($ENABLE_INPUT_RULES = true) do={
    :put "=== Input rules ==="
    
    # Преобразуем списки в строки для dst-port
    :local tcp_ports_str ""
    :local udp_ports_str ""
    
    :foreach port in=$tcp_ports_for_fasttrack do={
        :if ($tcp_ports_str != "") do={ :set tcp_ports_str ($tcp_ports_str . ",") }
        :set tcp_ports_str ($tcp_ports_str . $port)
    }
    
    :foreach port in=$udp_ports_for_fasttrack do={
        :if ($udp_ports_str != "") do={ :set udp_ports_str ($udp_ports_str . ",") }
        :set udp_ports_str ($udp_ports_str . $port)
    }
    
    if ($tcp_ports_str != "") do={
        /ip firewall filter add chain=input \
            in-interface=$WAN_INTERFACE \
            protocol=tcp dst-port=$tcp_ports_str \
            action=accept \
            comment="KASKAD_INPUT_TCP"
    }
    
    if ($udp_ports_str != "") do={
        /ip firewall filter add chain=input \
            in-interface=$WAN_INTERFACE \
            protocol=udp dst-port=$udp_ports_str \
            action=accept \
            comment="KASKAD_INPUT_UDP"
    }
}

# =============================================================================
# 6. FASTTRACK ОПТИМИЗАЦИЯ
# =============================================================================

:put "=== FastTrack optimization ==="

# Собираем все порты в один список
:local all_ports {}
:set all_ports ($tcp_ports_for_fasttrack, $udp_ports_for_fasttrack)

:local ports_str ""
:foreach port in=$all_ports do={
    :if ($ports_str != "") do={ :set ports_str ($ports_str . ",") }
    :set ports_str ($ports_str . $port)
}

if ($ports_str != "") do={
    /ip firewall filter add chain=forward \
        dst-port=$ports_str \
        action=accept \
        place-before=[find action=fasttrack-connection] \
        comment="KASKAD_BYPASS_FASTTRACK"
    :put "  FastTrack bypass for ports: $ports_str"
}

# =============================================================================
# 7. ЛОГИРОВАНИЕ
# =============================================================================

if ($ENABLE_LOGGING = true) do={
    :put "=== Logging enabled ==="
    
    if ($tcp_ports_str != "") do={
        /ip firewall filter add chain=forward \
            in-interface=$WAN_INTERFACE protocol=tcp dst-port=$tcp_ports_str \
            action=log log-prefix="KASKAD_TCP" \
            comment="KASKAD_LOG_TCP"
    }
    
    if ($udp_ports_str != "") do={
        /ip firewall filter add chain=forward \
            in-interface=$WAN_INTERFACE protocol=udp dst-port=$udp_ports_str \
            action=log log-prefix="KASKAD_UDP" \
            comment="KASKAD_LOG_UDP"
    }
}

# =============================================================================
# 8. ИТОГОВЫЙ ОТЧЕТ
# =============================================================================

:put ""
:put "=========================================="
:put "KASKAD CONFIGURATION APPLIED"
:put "=========================================="
:put "Total hosts configured: $[:len $HOSTS]"
:put "Interface: $WAN_INTERFACE"
:put "Strict masquerade: $USE_STRICT_MASQUERADE"
:put ""
:put "Active rules:"
/ip firewall nat print where comment~"KASKAD" 
:put ""
:put "=========================================="
