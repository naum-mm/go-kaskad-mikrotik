# =============================================================================
# go-kaskad-mikrotik.rsc - Полноценный каскадный проброс портов
# =============================================================================

# =============================================================================
# 1. НАСТРОЙКА ПЕРЕМЕННЫХ
# =============================================================================

# ФОРМАТ ДЛЯ ДОБАВЛЕНИЯ ПРАВИЛ:
# {"IP_адрес"; 
#  {{"tcp", входной_порт, выходной_порт}; {"tcp", входной_порт, выходной_порт}; ...};
#  {{"udp", входной_порт, выходной_порт}; {"udp", входной_порт, выходной_порт}; ...}}
#
# ПРИМЕРЫ:
# - Одинаковые порты: {"tcp", 80, 80}
# - Разные порты:   {"tcp", 8080, 80}
# - Можно смешивать

:local HOSTS {
    # Сервер 1: Веб-трафик (TCP)
    {"77.212.17.5"; 
        {{"tcp", 80, 80};
         {"tcp", 443, 443}};
        {}
    }
    
    # Сервер 2: VPN-трафик (UDP)
    {"16.25.11.68"; 
        {};
        {{"udp", 1194, 1194};
         {"udp", 500, 500};
         {"udp", 4500, 4500}}
    }
    
    # ========== ПРИМЕРЫ РАЗНЫХ ПОРТОВ (РАСКОММЕНТИРУЙТЕ ДЛЯ ТЕСТА) ==========
    # Пример 1: Проброс внешнего порта 2222 на внутренний 22 (SSH)
    # {"10.0.0.100"; 
    #     {{"tcp", 2222, 22}};
    #     {}
    # }
    
    # Пример 2: Проброс внешнего порта 10000 на внутренний 1194 (OpenVPN на нестандартном порту)
    # {"10.0.0.200"; 
    #     {};
    #     {{"udp", 10000, 1194}}
    # }
    
    # Пример 3: Смешанный пример (и TCP, и UDP с разными портами)
    # {"192.168.1.50"; 
    #     {{"tcp", 8080, 80};
    #      {"tcp", 8443, 443}};
    #     {{"udp", 5300, 53};
    #      {"udp", 5400, 1194}}
    # }
}

# Основные настройки
:local WAN_INTERFACE "ether1"           # Ваш WAN интерфейс
:local ENABLE_LOGGING false             # Включить логирование (true/false)
:local ENABLE_INPUT_RULES true          # Добавить INPUT правила для доступа к самому MT
:local USE_STRICT_MASQUERADE true       # Masquerade только для целевых IP (экономит CPU)

# =============================================================================
# 2. ОЧИСТКА СТАРЫХ ПРАВИЛ
# =============================================================================

:put "=== Cleaning old KASKAD rules ==="
/ip firewall nat remove [find comment~"KASKAD"]
/ip firewall filter remove [find comment~"KASKAD"]
:put "  Old rules removed"

# =============================================================================
# 3. БАЗОВЫЕ НАСТРОЙКИ СИСТЕМЫ
# =============================================================================

:put "=== Configuring system settings ==="
/ip settings set ip-forward=yes
/ip settings set tcp-syncookies=yes
:put "  IP forwarding enabled"

# =============================================================================
# 4. ОСНОВНОЕ ПРАВИЛО FORWARD
# =============================================================================

:put "=== Configuring forward rules ==="
/ip firewall filter add chain=forward action=accept comment="KASKAD_ALLOW_FORWARD"
:put "  Forward allowed"

# =============================================================================
# 5. ГЕНЕРАЦИЯ ПРАВИЛ NAT (С ПОДДЕРЖКОЙ РАЗНЫХ ПОРТОВ)
# =============================================================================

:put "=== Generating NAT rules ==="
:put ""

# Для сбора портов для FastTrack
:local tcp_ports_in {}
:local udp_ports_in {}
:local all_targets {}

:foreach host in=$HOSTS do={
    :local target_ip [:tostr ($host->0)]
    :local tcp_rules ($host->1)
    :local udp_rules ($host->2)
    
    :set all_targets ($all_targets, $target_ip)
    
    # Обработка TCP правил
    :foreach rule in=$tcp_rules do={
        :local protocol [:tostr ($rule->0)]
        :local in_port [:tonum ($rule->1)]
        :local out_port [:tonum ($rule->2)]
        
        # Добавляем DNAT правило
        /ip firewall nat add chain=dstnat \
            in-interface=$WAN_INTERFACE \
            protocol=$protocol \
            dst-port=$in_port \
            action=dst-nat \
            to-addresses=$target_ip \
            to-ports=$out_port \
            comment="KASKAD_TCP_${in_port}_TO_${target_ip}_${out_port}"
        
        :put "  TCP: port $in_port -> $target_ip:$out_port"
        
        # Собираем входные порты для FastTrack
        :set tcp_ports_in ($tcp_ports_in, $in_port)
    }
    
    # Обработка UDP правил
    :foreach rule in=$udp_rules do={
        :local protocol [:tostr ($rule->0)]
        :local in_port [:tonum ($rule->1)]
        :local out_port [:tonum ($rule->2)]
        
        # Добавляем DNAT правило
        /ip firewall nat add chain=dstnat \
            in-interface=$WAN_INTERFACE \
            protocol=$protocol \
            dst-port=$in_port \
            action=dst-nat \
            to-addresses=$target_ip \
            to-ports=$out_port \
            comment="KASKAD_UDP_${in_port}_TO_${target_ip}_${out_port}"
        
        :put "  UDP: port $in_port -> $target_ip:$out_port"
        
        # Собираем входные порты для FastTrack
        :set udp_ports_in ($udp_ports_in, $in_port)
    }
}

:put ""

# =============================================================================
# 6. MASQUERADE (SOURCE NAT) - ОПТИМИЗИРОВАННЫЙ
# =============================================================================

:put "=== Configuring masquerade rules ==="

if ($USE_STRICT_MASQUERADE = true) do={
    # Точечный masquerade для каждого целевого IP
    :foreach target in=$all_targets do={
        /ip firewall nat add chain=srcnat \
            dst-address=$target \
            out-interface=$WAN_INTERFACE \
            action=masquerade \
            comment="KASKAD_MASQ_TO_${target}"
        :put "  Masquerade for: $target"
    }
} else={
    # Широкий masquerade для всего трафика
    /ip firewall nat add chain=srcnat \
        out-interface=$WAN_INTERFACE \
        action=masquerade \
        comment="KASKAD_MASQUERADE_ALL"
    :put "  Wide masquerade enabled (all traffic)"
}

:put ""

# =============================================================================
# 7. INPUT ПРАВИЛА (ДЛЯ ДОСТУПА К САМОМУ МАРШРУТИЗАТОРУ)
# =============================================================================

if ($ENABLE_INPUT_RULES = true) do={
    :put "=== Configuring input rules ==="
    
    # Преобразуем списки портов в строки для dst-port
    :local tcp_ports_str ""
    :local udp_ports_str ""
    
    :foreach port in=$tcp_ports_in do={
        :if ($tcp_ports_str != "") do={ :set tcp_ports_str ($tcp_ports_str . ",") }
        :set tcp_ports_str ($tcp_ports_str . $port)
    }
    
    :foreach port in=$udp_ports_in do={
        :if ($udp_ports_str != "") do={ :set udp_ports_str ($udp_ports_str . ",") }
        :set udp_ports_str ($udp_ports_str . $port)
    }
    
    if ($tcp_ports_str != "") do={
        /ip firewall filter add chain=input \
            in-interface=$WAN_INTERFACE \
            protocol=tcp dst-port=$tcp_ports_str \
            action=accept \
            comment="KASKAD_INPUT_TCP"
        :put "  INPUT TCP allowed: $tcp_ports_str"
    }
    
    if ($udp_ports_str != "") do={
        /ip firewall filter add chain=input \
            in-interface=$WAN_INTERFACE \
            protocol=udp dst-port=$udp_ports_str \
            action=accept \
            comment="KASKAD_INPUT_UDP"
        :put "  INPUT UDP allowed: $udp_ports_str"
    }
    :put ""
}

# =============================================================================
# 8. FASTTRACK ОПТИМИЗАЦИЯ
# =============================================================================

:put "=== FastTrack optimization ==="

# Собираем все входные порты (и TCP, и UDP)
:local all_in_ports {}
:set all_in_ports ($tcp_ports_in, $udp_ports_in)

:local ports_str ""
:foreach port in=$all_in_ports do={
    :if ($ports_str != "") do={ :set ports_str ($ports_str . ",") }
    :set ports_str ($ports_str . $port)
}

if ($ports_str != "") do={
    # Проверяем, существует ли правило FastTrack
    :local fasttrack_exists [/ip firewall filter find action=fasttrack-connection]
    if ([:len $fasttrack_exists] > 0) do={
        /ip firewall filter add chain=forward \
            dst-port=$ports_str \
            action=accept \
            place-before=$fasttrack_exists \
            comment="KASKAD_BYPASS_FASTTRACK"
        :put "  FastTrack bypass added for ports: $ports_str"
    } else={
        :put "  FastTrack not active, no bypass needed"
    }
} else={
    :put "  No ports to optimize"
}

:put ""

# =============================================================================
# 9. ЛОГИРОВАНИЕ (ТОЛЬКО ДЛЯ ОТЛАДКИ)
# =============================================================================

if ($ENABLE_LOGGING = true) do={
    :put "=== Enabling logging (debug mode) ==="
    
    :local tcp_ports_str ""
    :local udp_ports_str ""
    
    :foreach port in=$tcp_ports_in do={
        :if ($tcp_ports_str != "") do={ :set tcp_ports_str ($tcp_ports_str . ",") }
        :set tcp_ports_str ($tcp_ports_str . $port)
    }
    
    :foreach port in=$udp_ports_in do={
        :if ($udp_ports_str != "") do={ :set udp_ports_str ($udp_ports_str . ",") }
        :set udp_ports_str ($udp_ports_str . $port)
    }
    
    if ($tcp_ports_str != "") do={
        /ip firewall filter add chain=forward \
            in-interface=$WAN_INTERFACE \
            protocol=tcp dst-port=$tcp_ports_str \
            action=log log-prefix="KASKAD_TCP" \
            comment="KASKAD_LOG_TCP"
        :put "  TCP logging enabled for ports: $tcp_ports_str"
    }
    
    if ($udp_ports_str != "") do={
        /ip firewall filter add chain=forward \
            in-interface=$WAN_INTERFACE \
            protocol=udp dst-port=$udp_ports_str \
            action=log log-prefix="KASKAD_UDP" \
            comment="KASKAD_LOG_UDP"
        :put "  UDP logging enabled for ports: $udp_ports_str"
    }
    :put ""
}

# =============================================================================
# 10. ДОПОЛНИТЕЛЬНАЯ ОПТИМИЗАЦИЯ ДЛЯ UDP (УВЕЛИЧИВАЕМ TIMEOUT)
# =============================================================================

:put "=== UDP optimization ==="
/ip firewall connection tracking set udp-timeout=60s
/ip firewall connection tracking set udp-stream-timeout=180s
:put "  UDP timeouts increased for VPN stability"

:put ""

# =============================================================================
# 11. ИТОГОВЫЙ ОТЧЕТ
# =============================================================================

:put "=========================================="
:put " KASKAD CONFIGURATION APPLIED SUCCESSFULLY"
:put "=========================================="
:put ""
:put "Configuration summary:"
:put "  Total hosts: $[:len $HOSTS]"
:put "  WAN interface: $WAN_INTERFACE"
:put "  Strict masquerade: $USE_STRICT_MASQUERADE"
:put "  Logging: $ENABLE_LOGGING"
:put "  Input rules: $ENABLE_INPUT_RULES"
:put ""
:put "Active NAT rules:"
/ip firewall nat print where comment~"KASKAD"
:put ""
:put "Active Filter rules:"
/ip firewall filter print where comment~"KASKAD"
:put ""
:put "=========================================="
:put "To test your configuration:"
:put "  - Check NAT: /ip firewall nat print where comment~\"KASKAD\""
:put "  - Check connections: /ip firewall connection print where dst-address~\"37.252.11\""
:put "  - Monitor traffic: /tool torch interface=$WAN_INTERFACE"
:put "=========================================="
