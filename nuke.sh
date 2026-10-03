#!/bin/bash
#
# NUKE -- recon via APIs publicas + analise de JS feita em bash (sem depender de
# subfinder/webanalyze/subjs/getjs/jshunter/js_snitch, que nao tem API).
#
# Fontes usadas:
#   - crt.sh                (subdominios, Certificate Transparency, sem key)
#   - crt.name v1           (subdominios, CT alternativo, sem key) [NOVO]
#   - SecurityTrails API    (subdominios, PRECISA de API key -- opcional)
#   - OTX AlienVault        (subdominios + URLs + IPs, sem key) [NOVO]
#   - urlscan.io            (subdominios/domains + IPs, sem key) [NOVO]
#   - VirusTotal v2         (subdomains + siblings + IPs, PRECISA key) [NOVO]
#   - dns.google            (DNS-over-HTTPS: TXT/SPF, A/AAAA, NS, MX, SOA, PTR)
#   - dnsrecon-equivalente  (NS/SOA/MX/AXFR via dig/host ou dns.google) [NOVO]
#   - rdap.org              (WHOIS via RDAP)
#   - web.archive.org/cdx   (Wayback Machine)
#   - favicon hash          (Shodan http.favicon.hash hunting) [NOVO]
#   - openssl/nmap ssl-cert (verificar se IP pertence a empresa) [NOVO]
#   - Shodan/ZoomEye        (dorks + API opcional) [NOVO]
#   - dirscan embutido      (wordlist curada, paralelo, sem ffuf/gobuster) [NOVO]
#   - o proprio alvo        (status/headers HTTP, HTML, arquivos .js)
#
# Analise de JS: feita aqui mesmo, via curl + grep/sed.
# Descoberta de IP original: consolida A-records + OTX + urlscan + VT +
#   SPF (ip4/include) + siblings, e filtra CDN/WAF via RDAP org.
#
# TUDO sai em um unico arquivo .txt.
#
# Uso:
#   bash recon.sh dominio.com [SECURITYTRAILS_KEY] [VIRUSTOTAL_KEY]
#   # ou via env (recomendado, nunca commitar key):
#   export SECURITYTRAILS_API_KEY="..."
#   export VT_APIKEY="..."
#   export SHODAN_API_KEY="..."     # opcional
#   export ZOOMEYE_KEY="..."        # opcional
#   bash recon.sh dominio.com
#

set -u

# ------------------------------------------------------------------
# API KEYS (SOMENTE via env var ou argumento -- NUNCA hardcode no arquivo)
#   export SECURITYTRAILS_API_KEY="sua_key"
#   export VT_APIKEY="sua_key"
#   export SHODAN_API_KEY="sua_key"   # opcional
#   export ZOOMEYE_KEY="sua_key"      # opcional
# ------------------------------------------------------------------
DOMAIN="${1:-}"
ST_KEY="${2:-${SECURITYTRAILS_API_KEY:-}}"
VT_KEY="${3:-${VT_APIKEY:-}}"
SHODAN_KEY="${SHODAN_API_KEY:-}"
ZOOMEYE_KEY="${ZOOMEYE_KEY:-}"

banner() {
    cat <<'ASCIIEOF'

    _   _ _   _ _  _______ 
   | \ | | | | | |/ / ____|
   |  \| | | | | ' /|  _|  
   | |\  | |_| | . \| |___ 
   |_| \_|\___/|_|\_\_____|

        N U K E  //  recon & attack surface mapper
        -----------------------------------------

ASCIIEOF
}

if [[ -z "$DOMAIN" ]]; then
    banner
    echo "Uso: bash recon.sh dominio.com [SECURITYTRAILS_KEY] [VIRUSTOTAL_KEY]"
    echo "     (keys tambem via env: SECURITYTRAILS_API_KEY / VT_APIKEY)"
    exit 1
fi

OUT="recon_${DOMAIN}.txt"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

: > "$OUT"

log() {
    echo -e "$1" | tee -a "$OUT"
}

section() {
    log "\n==================================================================="
    log "== $1"
    log "===================================================================\n"
}

have() { command -v "$1" >/dev/null 2>&1; }

clear 2>/dev/null || true
banner
echo "[*] Recon via APIs -- ${DOMAIN}  (saida: ${OUT})"

IPREGEX='([0-9]{1,3}\.){3}[0-9]{1,3}'

# ==================================================================
# 1. Subdominios via crt.sh
# ==================================================================
section "1. SUBDOMINIOS (crt.sh - Certificate Transparency)"

CRT_HTTP=$(curl -s --max-time 30 -o "$TMPDIR/crtsh.json" -w "%{http_code}" "https://crt.sh/?q=%25.${DOMAIN}&output=json")
if [[ "$CRT_HTTP" != "200" ]]; then
    log "[!] crt.sh retornou HTTP ${CRT_HTTP} (rate limit e comum). Aguardando 10s e tentando de novo..."
    sleep 10
    CRT_HTTP=$(curl -s --max-time 30 -o "$TMPDIR/crtsh.json" -w "%{http_code}" "https://crt.sh/?q=%25.${DOMAIN}&output=json")
fi
if [[ "$CRT_HTTP" != "200" ]]; then
    log "[!] crt.sh ainda HTTP ${CRT_HTTP}. Pulando -- reexecute o script depois."
    : > "$TMPDIR/subs_crtsh.txt"
else
    grep -o '"name_value":"[^"]*"' "$TMPDIR/crtsh.json" \
        | sed -E 's/"name_value":"//; s/"$//' \
        | sed 's/\\n/\n/g' \
        | tr -d '*' \
        | grep -i "\.${DOMAIN}\$\|^${DOMAIN}\$" \
        | sort -u > "$TMPDIR/subs_crtsh.txt" || : > "$TMPDIR/subs_crtsh.txt"
fi

cat "$TMPDIR/subs_crtsh.txt" | tee -a "$OUT"
log "\n[Total crt.sh]: $(wc -l < "$TMPDIR/subs_crtsh.txt")"

# ==================================================================
# 2. Subdominios via crt.name (NOVO)
#    https://crt.name/v1/search?apex=site.com.br
#    Retorna texto puro, 1 host por linha. Sem key.
# ==================================================================
section "2. SUBDOMINIOS (crt.name v1 - https://crt.name/v1/search?apex=${DOMAIN})"

curl -s --max-time 30 "https://crt.name/v1/search?apex=${DOMAIN}" \
    | tr -d '\r' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | grep -iv '^$' \
    | tr -d '*' \
    | grep -i "\.${DOMAIN}\$\|^${DOMAIN}\$" \
    | sort -u > "$TMPDIR/subs_crtname.txt" || : > "$TMPDIR/subs_crtname.txt"

cat "$TMPDIR/subs_crtname.txt" | tee -a "$OUT"
log "\n[Total crt.name]: $(wc -l < "$TMPDIR/subs_crtname.txt")"

# ==================================================================
# 3. Subdominios via SecurityTrails (opcional, precisa de key)
# ==================================================================
section "3. SUBDOMINIOS (SecurityTrails API)"

if [[ -z "$ST_KEY" ]]; then
    log "[!] Nenhuma API key do SecurityTrails informada. Etapa pulada."
    log "    Pegue uma key gratuita em https://securitytrails.com/app/signup"
    log "    e rode: export SECURITYTRAILS_API_KEY='SUACHAVE' ; bash recon.sh ${DOMAIN}"
    : > "$TMPDIR/subs_st.txt"
else
    curl -s --max-time 30 -H "APIKEY: ${ST_KEY}" \
        "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains" \
        > "$TMPDIR/st_raw.json"

    if grep -q '"subdomains"' "$TMPDIR/st_raw.json"; then
        grep -o '"subdomains":\[[^]]*\]' "$TMPDIR/st_raw.json" \
            | grep -o '"[^"]*"' \
            | tr -d '"' \
            | grep -v '^subdomains$' \
            | sed "s/\$/.${DOMAIN}/" \
            | sort -u > "$TMPDIR/subs_st.txt"

        cat "$TMPDIR/subs_st.txt" | tee -a "$OUT"
        log "\n[Total SecurityTrails]: $(wc -l < "$TMPDIR/subs_st.txt")"
    else
        log "[!] Resposta inesperada da API (key invalida, rate limit ou erro)."
        log "    Resposta bruta: $(head -c 500 "$TMPDIR/st_raw.json")"
        : > "$TMPDIR/subs_st.txt"
    fi
fi

# ==================================================================
# 4. OTX AlienVault (NOVO)
#    https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1
#    Serve p/ 2 coisas: descobrir subdominios (campo hostname) e IPs
#    (result.urlworker.ip). Sem key.
# ==================================================================
section "4. OTX ALIENVAULT (subdominios + URLs + IPs)"

OTX_URL="https://otx.alienvault.com/api/v1/indicators/hostname/${DOMAIN}/url_list?limit=500&page=1"
log "[*] GET ${OTX_URL}"
curl -s --max-time 30 "$OTX_URL" > "$TMPDIR/otx.json" || echo -n "" > "$TMPDIR/otx.json"

# 4a. hostnames -> subdominios (OTX usa JSON com espaco: "hostname": "x")
grep -oE '"hostname": *"[^"]*"' "$TMPDIR/otx.json" \
    | sed -E 's/"hostname": *"//; s/"$//' \
    | grep -i "\.${DOMAIN}\$\|^${DOMAIN}\$" \
    | sort -u > "$TMPDIR/subs_otx.txt" || : > "$TMPDIR/subs_otx.txt"

log "[Subdominios via OTX]: $(wc -l < "$TMPDIR/subs_otx.txt")"
cat "$TMPDIR/subs_otx.txt" | tee -a "$OUT"

# 4b. URLs observadas
log "\n[URLs observadas no OTX (top 50)]:"
grep -oE '"url": *"[^"]*"' "$TMPDIR/otx.json" \
    | sed -E 's/"url": *"//; s/"$//' \
    | sort -u | head -n 50 | tee -a "$OUT"

# 4c. IPs observados (equivale ao seu pipe: jq '.url_list[].result?.urlworker?.ip' + grep IP)
log "\n[IPs observados no OTX]:"
grep -oE "$IPREGEX" "$TMPDIR/otx.json" \
    | sort -u > "$TMPDIR/ips_otx.txt" || : > "$TMPDIR/ips_otx.txt"
cat "$TMPDIR/ips_otx.txt" | tee -a "$OUT"
log "[Total IPs OTX]: $(wc -l < "$TMPDIR/ips_otx.txt")"

# ==================================================================
# 5. urlscan.io (NOVO)
#    https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000
#    Extraimos page.ip (IPs) e page.domain/task.domain (hosts). Sem key.
#    size=1000 por padrao p/ nao estourar; ajuste se quiser.
# ==================================================================
section "5. URLSCAN.IO (domains + IPs)"

URLSCAN_SIZE="${URLSCAN_SIZE:-1000}"
URLSCAN_URL="https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=${URLSCAN_SIZE}"
log "[*] GET ${URLSCAN_URL}  (URLSCAN_SIZE=${URLSCAN_SIZE}; export URLSCAN_SIZE=10000 p/ maximo)"
curl -s --max-time 40 "$URLSCAN_URL" > "$TMPDIR/urlscan.json" || echo -n "" > "$TMPDIR/urlscan.json"

grep -oE '"domain": *"[^"]*"' "$TMPDIR/urlscan.json" \
    | sed -E 's/"domain": *"//; s/"$//' \
    | grep -i "\.${DOMAIN}\$\|^${DOMAIN}\$" \
    | sort -u > "$TMPDIR/subs_urlscan.txt" || : > "$TMPDIR/subs_urlscan.txt"

log "[Subdominios/domains via urlscan]: $(wc -l < "$TMPDIR/subs_urlscan.txt")"
cat "$TMPDIR/subs_urlscan.txt" | tee -a "$OUT"

log "\n[IPs observados no urlscan]:"
grep -oE '"ip": *"[^"]*"' "$TMPDIR/urlscan.json" \
    | sed -E 's/"ip": *"//; s/"$//' \
    | grep -Eo "$IPREGEX" \
    | sort -u > "$TMPDIR/ips_urlscan.txt" || : > "$TMPDIR/ips_urlscan.txt"
cat "$TMPDIR/ips_urlscan.txt" | tee -a "$OUT"
log "[Total IPs urlscan]: $(wc -l < "$TMPDIR/ips_urlscan.txt")"

log "\n[ASN/Server vistos no urlscan (amostra)]:"
grep -oE '"asnname": *"[^"]*"' "$TMPDIR/urlscan.json" | sed -E 's/"asnname": *"//; s/"$//' | sort | uniq -c | sort -rn | head -n 10 | tee -a "$OUT"
grep -oE '"server": *"[^"]*"' "$TMPDIR/urlscan.json" | sed -E 's/"server": *"//; s/"$//' | sort | uniq -c | sort -rn | head -n 10 | tee -a "$OUT"

# ==================================================================
# 6. VirusTotal v2 domain report (NOVO)
#    - subdomains / domain_siblings -> candidatos a IP original
#    - ..ip_address -> todos os IPs vistos
#    Equivale aos seus pipes com jq '.. .ip_address?' e '.domain_siblings[]'.
# ==================================================================
section "6. VIRUSTOTAL v2 (subdomains + siblings + IPs)"

if [[ -z "$VT_KEY" ]]; then
    log "[!] Sem VT_APIKEY. Etapa pulada."
    log "    export VT_APIKEY='suachave'  (https://www.virustotal.com/gui/my-apikey)"
    : > "$TMPDIR/subs_vt.txt"; : > "$TMPDIR/ips_vt.txt"; : > "$TMPDIR/siblings_vt.txt"
else
    curl -s --max-time 30 \
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_KEY}&domain=${DOMAIN}" \
        > "$TMPDIR/vt.json" || echo -n "" > "$TMPDIR/vt.json"

    if grep -q '"subdomains"' "$TMPDIR/vt.json" || grep -q '"domain_siblings"' "$TMPDIR/vt.json"; then
        grep -o '"subdomains":\[[^]]*\]' "$TMPDIR/vt.json" \
            | grep -o '"[^"]*"' | tr -d '"' | grep -v '^subdomains$' \
            | grep -i "\.${DOMAIN}\$\|^${DOMAIN}\$" | sort -u > "$TMPDIR/subs_vt.txt" || : > "$TMPDIR/subs_vt.txt"

        grep -o '"domain_siblings":\[[^]]*\]' "$TMPDIR/vt.json" \
            | grep -o '"[^"]*"' | tr -d '"' | grep -v '^domain_siblings$' \
            | sort -u > "$TMPDIR/siblings_vt.txt" || : > "$TMPDIR/siblings_vt.txt"

        # ..ip_address?  -> qualquer ocorrencia de "ip_address":"x.x.x.x"
        grep -o '"ip_address":"[^"]*"' "$TMPDIR/vt.json" \
            | sed -E 's/"ip_address":"//; s/"$//' \
            | grep -Eo "$IPREGEX" | sort -u > "$TMPDIR/ips_vt.txt" || : > "$TMPDIR/ips_vt.txt"
        # fallback: qualquer IPv4 no JSON
        if [[ ! -s "$TMPDIR/ips_vt.txt" ]]; then
            grep -oE "$IPREGEX" "$TMPDIR/vt.json" | sort -u > "$TMPDIR/ips_vt.txt" || : > "$TMPDIR/ips_vt.txt"
        fi

        log "[Subdominios via VT]: $(wc -l < "$TMPDIR/subs_vt.txt")"
        cat "$TMPDIR/subs_vt.txt" | tee -a "$OUT"
        log "\n[Domain siblings via VT (mesmo IP = possivel origem / vhost vizinho)]:"
        cat "$TMPDIR/siblings_vt.txt" | tee -a "$OUT"
        log "\n[IPs via VT]:"
        cat "$TMPDIR/ips_vt.txt" | tee -a "$OUT"
    else
        log "[!] Resposta inesperada do VT (key invalida, rate limit, dominio desconhecido?)."
        log "    Resposta bruta: $(head -c 500 "$TMPDIR/vt.json")"
        : > "$TMPDIR/subs_vt.txt"; : > "$TMPDIR/ips_vt.txt"; : > "$TMPDIR/siblings_vt.txt"
    fi
fi

# ------------------------------------------------------------------
# Consolida TODAS as fontes de subdominio
# ------------------------------------------------------------------
section "7. SUBDOMINIOS CONSOLIDADOS (todas as fontes)"

cat "$TMPDIR"/subs_*.txt 2>/dev/null | sort -u | grep -v '^$' > "$TMPDIR/subs_all.txt" || : > "$TMPDIR/subs_all.txt"

log "crt.sh=$(wc -l < "$TMPDIR/subs_crtsh.txt") | crt.name=$(wc -l < "$TMPDIR/subs_crtname.txt") | securitytrails=$(wc -l < "$TMPDIR/subs_st.txt") | otx=$(wc -l < "$TMPDIR/subs_otx.txt") | urlscan=$(wc -l < "$TMPDIR/subs_urlscan.txt") | virustotal=$(wc -l < "$TMPDIR/subs_vt.txt")"
log "[TOTAL unicos]: $(wc -l < "$TMPDIR/subs_all.txt")\n"
cat "$TMPDIR/subs_all.txt" | tee -a "$OUT"

# ==================================================================
# 8. DNS: TXT/SPF + equivalente dnsrecon -d (NOVO/MELHORADO)
#    - TXT via dns.google (inclui SPF)
#    - destrincha SPF: ip4:/ip6:/include:/a/mx (pista de infra/IP origem)
#    - NS/MX/SOA/A/AAAA via dns.google (+ dig/host se existirem)
#    - tentativa de AXFR (zone transfer) nos NS autoritativos
#    Web: https://mxtoolbox.com/ (SPF Lookup) e https://viewdns.info/
# ==================================================================
section "8. DNS (TXT/SPF + NS/MX/SOA + tentativa AXFR -- equiv. dnsrecon -d)"

log "[TXT via dns.google]:"
curl -s --max-time 20 -H "accept: application/dns-json" \
    "https://dns.google/resolve?name=${DOMAIN}&type=TXT" \
    > "$TMPDIR/dns_txt.json" || echo -n "" > "$TMPDIR/dns_txt.json"
# Answer apenas (Authority traz SOA que poluiria o SPF)
grep -o '"Answer":\[[^]]*\]' "$TMPDIR/dns_txt.json" \
    | grep -o '"data":"[^"]*"' | sed -E 's/"data":"//; s/"$//' | tee -a "$OUT" > "$TMPDIR/dns_txt_only.txt" || : > "$TMPDIR/dns_txt_only.txt"

log "\n[SPF destrinchado (pistas de infra -- confira tb em https://mxtoolbox.com/SuperTool.aspx)]:"
grep -i 'v=spf' "$TMPDIR/dns_txt_only.txt" | tee -a "$OUT" > "$TMPDIR/spf.txt" || echo -n "" > "$TMPDIR/spf.txt"
if [[ -s "$TMPDIR/spf.txt" ]]; then
    log "-- mecanismos ip4/ip6/include/a/mx extraidos --"
    grep -oE 'ip4:[^ ]+|ip6:[^ ]+|include:[^ ]+|[+]?[a-z]+:[^ ]*' "$TMPDIR/spf.txt" | sort -u | tee -a "$OUT"
    grep -oE "$IPREGEX" "$TMPDIR/spf.txt" | sort -u > "$TMPDIR/ips_spf.txt" || : > "$TMPDIR/ips_spf.txt"
    log "-- IPs literais dentro do SPF --"
    cat "$TMPDIR/ips_spf.txt" | tee -a "$OUT"
else
    log "(nenhum registro SPF encontrado)"
    : > "$TMPDIR/ips_spf.txt"
fi

for TYPE in NS MX SOA A AAAA; do
    log "\n[${TYPE} via dns.google]:"
    dns_resp=$(curl -s --max-time 20 -H "accept: application/dns-json" \
        "https://dns.google/resolve?name=${DOMAIN}&type=${TYPE}")
    dns_ans=$(echo "$dns_resp" | grep -o "\"Answer\":\[[^]]*\]")
    if [[ -n "$dns_ans" ]]; then
        echo "$dns_ans" | grep -o "\"data\":\"[^\"]*\"" | sed -E 's/"data":"//; s/"$//' | tee -a "$OUT"
    else
        dns_status=$(echo "$dns_resp" | grep -o "\"Status\":[0-9]*" || true)
        log "(sem registro ${TYPE} -- ${dns_status})"
    fi
done

log "\n[Tentativa de Zone Transfer AXFR (equiv. dnsrecon --axfr)]:"
NSLIST=$(curl -s --max-time 20 -H "accept: application/dns-json" \
    "https://dns.google/resolve?name=${DOMAIN}&type=NS" \
    | grep -o '"Answer":\[[^]]*\]' | grep -o '"data":"[^"]*"' | sed -E 's/"data":"//; s/"$//; s/\.$//' | sort -u)
if [[ -z "$NSLIST" ]]; then
    log "(sem NS encontrados, AXFR pulado)"
elif have dig; then
    for ns in $NSLIST; do
        log "-- dig AXFR @${ns} ${DOMAIN} --"
        dig AXFR "$DOMAIN" "@$ns" +time=5 +tries=1 2>&1 | head -n 30 | tee -a "$OUT"
    done
elif have host; then
    for ns in $NSLIST; do
        log "-- host -T -l ${DOMAIN} ${ns} --"
        host -T -l "$DOMAIN" "$ns" 2>&1 | head -n 30 | tee -a "$OUT"
    done
else
    log "(dig/host nao instalados; confira manualmente os NS acima. NS=${NSLIST})"
    log "(equivalente: dnsrecon -d ${DOMAIN} -t axfr)"
fi
log "\n[Dica] cheque tambem https://viewdns.info/ e https://mxtoolbox.com/ p/ DNS/SPF historico."

# ==================================================================
# 9. WHOIS via RDAP
# ==================================================================
section "9. WHOIS / RDAP do dominio (rdap.org)"

curl -sL --max-time 20 "https://rdap.org/domain/${DOMAIN}" > "$TMPDIR/rdap_domain.json" || echo -n "" > "$TMPDIR/rdap_domain.json"

{
    grep -o '"ldhName":"[^"]*"' "$TMPDIR/rdap_domain.json" | sed -E 's/"ldhName":"//; s/"$//'
    grep -o '"status":\[[^]]*\]' "$TMPDIR/rdap_domain.json"
} | tee -a "$OUT"

# ==================================================================
# 10. IPs, reverse DNS, RDAP de IP, status HTTP -- por host
# ==================================================================
section "10. IPS / REVERSE DNS / RDAP-IP / STATUS HTTP (por host)"

resolve_ips_api() {
    # le SOMENTE o bloco Answer (sem isso, NXDOMAIN traz SOA do Authority)
    curl -s --max-time 15 -H "accept: application/dns-json" \
        "https://dns.google/resolve?name=$1&type=A" \
        | grep -o '"Answer":\[[^]]*\]' | grep -o '"data":"[0-9.]*"' | sed -E 's/"data":"//; s/"$//'
}

reverse_dns_api() {
    local reversed ans
    reversed=$(echo "$1" | awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
    ans=$(curl -s --max-time 15 -H "accept: application/dns-json" \
        "https://dns.google/resolve?name=${reversed}&type=PTR" \
        | grep -o '"Answer":\[[^]]*\]')
    [[ -z "$ans" ]] && return 0
    echo "$ans" | grep -o '"data":"[^"]*"' | sed -E 's/"data":"//; s/"$//; s/\.$//'
}

rdap_ip_org() {
    local j name fn
    j=$(curl -sL --max-time 10 "https://rdap.org/ip/$1")
    name=$(echo "$j" | grep -oE "\"name\" *: *\"[^\"]*\"" | sed -E 's/"name" *: *"//; s/"$//' | head -n 1)
    if [[ -n "$name" ]]; then echo "$name"; return 0; fi
    fn=$(echo "$j" | grep -oE "\"fn\", *\{\}, *\"text\", *\"[^\"]*\"" | sed -E 's/.*"text", *"//; s/"$//' | head -n 1)
    echo "$fn"
}

: > "$TMPDIR/live_hosts.txt"
: > "$TMPDIR/host_ip_map.txt"

{ echo "$DOMAIN"; cat "$TMPDIR/subs_all.txt"; } | sort -u | while IFS= read -r h; do
    [[ -z "$h" ]] && continue

    ips=$(resolve_ips_api "$h")
    [[ -z "$ips" ]] && continue

    status=$(curl --connect-timeout 3 --max-time 10 -s -o /dev/null -w "%{http_code}" "https://${h}")
    server=$(curl --connect-timeout 3 --max-time 10 -s -I "https://${h}" 2>/dev/null | grep -i "^server:" | cut -d" " -f2- | tr -d '\r')

    echo "$ips" | while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        rev=$(reverse_dns_api "$ip")
        org=$(rdap_ip_org "$ip")
        echo "HOST: ${h} | IP: ${ip} | STATUS: ${status} | SERVER: ${server} | REVERSE: ${rev} | RDAP_ORG: ${org}" | tee -a "$OUT"
        echo "${h} ${ip}" >> "$TMPDIR/host_ip_map.txt"
    done

    # so guarda como "vivo" se respondeu algo diferente de 000
    [[ "$status" != "000" ]] && echo "$h" >> "$TMPDIR/live_hosts.txt"
done

sort -u "$TMPDIR/live_hosts.txt" -o "$TMPDIR/live_hosts.txt" 2>/dev/null || : > "$TMPDIR/live_hosts.txt"
sort -u "$TMPDIR/host_ip_map.txt" -o "$TMPDIR/host_ip_map.txt" 2>/dev/null || : > "$TMPDIR/host_ip_map.txt"

log "\n[Hosts vivos (responderam HTTPS)]: $(wc -l < "$TMPDIR/live_hosts.txt")"

# ==================================================================
# 11. FAVICON HASH p/ Shodan + verificacao de certificado (NOVO)
#    - calcula murmur3 do favicon no padrao Shodan (http.favicon.hash:X)
#    - links: https://favicon-hash.kmsec.uk/ e https://favicons.teamtailor-cdn.com/
#    - dork Shodan: Ssl.cert.subject.CN:"alvo" (+ consulta via API se tiver key)
#    - nmap --script ssl-cert -p 443 <IP> + openssl p/ confirmar se o IP e da empresa
# ==================================================================
section "11. FAVICON HASH (Shodan hunting) + VERIFICACAO SSL DO IP"

log "[*] Baixando /favicon.ico dos hosts vivos e calculando hash padrao Shodan..."
log "    Confira manualmente tb em: https://favicon-hash.kmsec.uk/"
log "    e https://favicons.teamtailor-cdn.com/ (Favicon Finder)"

: > "$TMPDIR/favicon_hashes.txt"

calc_favicon_hash_py() {
    # $1 = arquivo do favicon. Imprime mmh3(base64(favicon)) no padrao Shodan.
    python3 - "$1" <<'PYEOF'
import sys, base64

def murmur3_32(data, seed=0):
    # implementacao pura p/ nao depender de mmh3 instalado (padrao Shodan)
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h = seed
    n = len(data) // 4
    for i in range(n):
        k = data[i*4:(i+1)*4]
        k = k[0] | (k[1] << 8) | (k[2] << 16) | (k[3] << 24)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[n*4:]
    k = 0
    if len(tail) >= 3: k ^= tail[2] << 16
    if len(tail) >= 2: k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    if h & 0x80000000: h -= 0x100000000
    return h

path = sys.argv[1]
with open(path, 'rb') as f:
    raw = f.read()
b64 = base64.encodebytes(raw).decode().replace('\n', '\n')  # 76 cols + \n (padrao Shodan)
# base64.encodebytes ja quebra a cada 76 chars com \n -- exatamente o que o Shodan hasheia
print(murmur3_32(b64.encode()))
PYEOF
}

while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    fav="$TMPDIR/favicon_${h//[^a-zA-Z0-9]/_}.ico"
    if curl -sk --connect-timeout 5 --max-time 15 "https://${h}/favicon.ico" -o "$fav" 2>/dev/null && [[ -s "$fav" ]]; then
        if have python3; then
            fhash=$(calc_favicon_hash_py "$fav" 2>/dev/null)
            if [[ -n "$fhash" ]]; then
                log "HOST: ${h} | http.favicon.hash:${fhash} | dork: shodan search 'http.favicon.hash:${fhash}'"
                echo "${h} ${fhash}" >> "$TMPDIR/favicon_hashes.txt"
            else
                log "HOST: ${h} | (falha ao calcular hash; jogue o favicon em https://favicon-hash.kmsec.uk/)"
            fi
        else
            md5=$(md5sum "$fav" 2>/dev/null | cut -d' ' -f1 || md5 "$fav" 2>/dev/null)
            log "HOST: ${h} | (sem python3 p/ murmur3; md5=${md5}; calcule o hash Shodan em https://favicon-hash.kmsec.uk/)"
        fi
    else
        # tenta caminho alternativo comum
        if curl -sk --connect-timeout 5 --max-time 15 "https://${h}/" -o "$TMPDIR/root_${h//[^a-zA-Z0-9]/_}.html" 2>/dev/null; then
            iconlink=$(grep -oE '<link[^>]*rel=["'"'"'](shortcut )?icon["'"'"'][^>]*>' "$TMPDIR/root_${h//[^a-zA-Z0-9]/_}.html" | grep -oE 'href=["'"'"'][^"'"'"']+' | head -n1 | sed -E 's/href=["'"'"']//')
            if [[ -n "$iconlink" ]]; then
                [[ "$iconlink" == /* ]] && iconlink="https://${h}${iconlink}"
                [[ "$iconlink" != http* ]] && iconlink="https://${h}/${iconlink}"
                log "HOST: ${h} | sem /favicon.ico, mas achado icon alternativo: ${iconlink} (jogue em https://favicon-hash.kmsec.uk/)"
            fi
        fi
    fi
done < "$TMPDIR/live_hosts.txt"

if [[ -s "$TMPDIR/favicon_hashes.txt" ]]; then
    log "\n[Dorks Shodan prontos (favicon)]:"
    sort -u -k2 "$TMPDIR/favicon_hashes.txt" | while read -r hh fh; do
        log "  shodan search 'http.favicon.hash:${fh}'   # via ${hh}"
    done
fi

log "\n[Dork Shodan por certificado (sem key, rode no site/CLI)]:"
log "  shodan search 'Ssl.cert.subject.CN:\"${DOMAIN}\" 200 --fields ip_str' | httpx-toolkit -sc -title -server -td"
log "  site: https://www.shodan.io/search?query=Ssl.cert.subject.CN%3A%22${DOMAIN}%22"

if [[ -n "$SHODAN_KEY" ]]; then
    log "\n[*] SHODAN_API_KEY detectada -- consultando API..."
    curl -s --max-time 30 "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=Ssl.cert.subject.CN%3A%22${DOMAIN}%22" \
        > "$TMPDIR/shodan.json" || echo -n "" > "$TMPDIR/shodan.json"
    log "[IPs Shodan Ssl.cert.subject.CN:\"${DOMAIN}\"]:"
    grep -oE '"ip_str": *"[^"]*"' "$TMPDIR/shodan.json" | sed -E 's/"ip_str": *"//; s/"$//' | sort -u | tee -a "$OUT" > "$TMPDIR/ips_shodan.txt" || : > "$TMPDIR/ips_shodan.txt"
else
    log "[!] SHODAN_API_KEY nao definida -- consulta via API pulada (dork manual acima)."
    : > "$TMPDIR/ips_shodan.txt"
fi

log "\n[Verificacao SSL: o IP pertence mesmo a empresa? (openssl + nmap ssl-cert)]"
log "    Equivale a: nmap --script ssl-cert -p 443 <IP>"

if ! have nmap; then
    log "(nmap nao instalado -- p/ verificacao completa rode: nmap --script ssl-cert -p 443 <IP>)"
fi
uniq_ips_dns=$(awk '{print $2}' "$TMPDIR/host_ip_map.txt" 2>/dev/null | sort -u | head -n 25)
for ip in $uniq_ips_dns; do
    [[ -z "$ip" ]] && continue
    # Pula IPs privados/loopback/link-local -- nao sao roteaveis da Internet e
    # fazem openssl/nmap pendurar ate o timeout (trava o recon inteiro).
    case "$ip" in
        10.*|127.*|192.168.*|169.254.*|0.*) log "(pulado ${ip} -- IP privado/nao roteavel)"; continue ;;
    esac
    case "$ip" in
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) log "(pulado ${ip} -- IP privado/nao roteavel)"; continue ;;
    esac
    log "\n-- ${ip} --"
    # openssl: CN + SANs do cert apresentado pelo IP (com timeout p/ nao travar em porta filtrada)
    if have timeout; then
        echo | timeout 8 openssl s_client -connect "${ip}:443" -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null \
            | head -n 6 | tee -a "$OUT"
    else
        echo | openssl s_client -connect "${ip}:443" -servername "$DOMAIN" 2>/dev/null \
            | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null \
            | head -n 6 | tee -a "$OUT"
    fi
    if have nmap; then
        if have timeout; then
            timeout 60 nmap -Pn --host-timeout 40s --script ssl-cert -p 443 "$ip" 2>&1 | grep -iE 'Subject|Issuer|CommonName|DNS:|ssl-cert' | head -n 15 | tee -a "$OUT"
        else
            nmap -Pn --host-timeout 40s --script ssl-cert -p 443 "$ip" 2>&1 | grep -iE 'Subject|Issuer|CommonName|DNS:|ssl-cert' | head -n 15 | tee -a "$OUT"
        fi
    fi
done | head -n 150

log "\n[ZoomEye] dork manual: ssl:\"${DOMAIN}\" em https://www.zoomeye.hk/"
if [[ -n "$ZOOMEYE_KEY" ]]; then
    log "[*] ZOOMEYE_KEY detectada (consulta automatica eh via JWT; rode manual se 401):"
    curl -s --max-time 30 -H "API-KEY: ${ZOOMEYE_KEY}" \
        "https://api.zoomeye.ai/host/search?query=ssl%3A%22${DOMAIN}%22" \
        | head -c 800 | tee -a "$OUT"
    echo "" | tee -a "$OUT"
else
    log "[!] ZOOMEYE_KEY nao definida -- https://www.zoomeye.hk/ (crie conta gratis). Dork: ssl:\"${DOMAIN}\""
fi

# ==================================================================
# 12. Analise de JS (feita aqui, sem tool externa)
# ==================================================================
section "12. ARQUIVOS JS ENCONTRADOS + ENDPOINTS EXTRAIDOS"

: > "$TMPDIR/js_files.txt"
: > "$TMPDIR/js_endpoints.txt"

while IFS= read -r h; do
    [[ -z "$h" ]] && continue

    html=$(curl -sk --connect-timeout 3 --max-time 15 "https://${h}")

    # acha <script src="..."> tanto absoluto quanto relativo
    echo "$html" \
        | grep -oE '<script[^>]*src=["'"'"'][^"'"'"']+["'"'"']' \
        | grep -oE '["'"'"'][^"'"'"']+\.js[^"'"'"']*["'"'"']' \
        | tr -d '"'"'"'' \
        | while IFS= read -r src; do

            if [[ "$src" == http* ]]; then
                jsurl="$src"
            elif [[ "$src" == //* ]]; then
                jsurl="https:${src}"
            elif [[ "$src" == /* ]]; then
                jsurl="https://${h}${src}"
            else
                jsurl="https://${h}/${src}"
            fi

            echo "$jsurl" >> "$TMPDIR/js_files.txt"
        done
done < "$TMPDIR/live_hosts.txt"

sort -u "$TMPDIR/js_files.txt" -o "$TMPDIR/js_files.txt"
log "[Arquivos JS encontrados]:"
cat "$TMPDIR/js_files.txt" | tee -a "$OUT"

log "\n[Endpoints/paths extraidos dos JS]:"
while IFS= read -r jsurl; do
    [[ -z "$jsurl" ]] && continue

    curl -sk --connect-timeout 3 --max-time 15 "$jsurl" \
        | grep -oE '"(/[-a-zA-Z0-9_/.]{3,})"|https?://[-a-zA-Z0-9_./?=&%]{5,}' \
        | tr -d '"' \
        | grep -Ev '\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf)([?"]|$)' \
        >> "$TMPDIR/js_endpoints.txt"
done < "$TMPDIR/js_files.txt"

sort -u "$TMPDIR/js_endpoints.txt" -o "$TMPDIR/js_endpoints.txt"
cat "$TMPDIR/js_endpoints.txt" | tee -a "$OUT"

# ==================================================================
# 13. Wayback Machine (url + fl=original + collapse=urlkey, como pedido)
# ==================================================================
section "13. URLS HISTORICAS (Wayback CDX API)"

wayback_url="https://web.archive.org/cdx/search/cdx?url=${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=5000"

wayback_try() {
    local tmp_body tmp_code
    tmp_body=$(mktemp)
    tmp_code=$(curl -s --max-time 40 -o "$tmp_body" -w "%{http_code}" "$wayback_url")
    echo "$tmp_code" > "$TMPDIR/wayback_code"
    cat "$tmp_body"
    rm -f "$tmp_body"
}

wb_out=$(wayback_try)
wb_code=$(cat "$TMPDIR/wayback_code" 2>/dev/null)

if [[ "$wb_code" == "429" ]]; then
    log "[!] Wayback CDX API retornou 429 (rate limit). Aguardando 15s e tentando de novo..."
    sleep 15
    wb_out=$(wayback_try)
    wb_code=$(cat "$TMPDIR/wayback_code" 2>/dev/null)
fi

if [[ "$wb_code" == "429" ]]; then
    log "[!] Ainda em rate limit (429) apos retry. Pulando esta secao -- reexecute o script depois."
elif [[ "$wb_code" != "200" ]]; then
    log "[!] Wayback CDX API retornou HTTP ${wb_code}. Sem dados nesta secao."
    log "    URL usada: ${wayback_url}"
else
    echo "$wb_out" | sort -u | tee -a "$OUT"
    log "\n[Params/URLs interessantes no historico (filao p/ bug bounty)]:"
    echo "$wb_out" | grep -iE '\?|api|admin|login|token|key|password|backup|\.bak|\.zip|\.sql|\.env|\.git' | sort -u | head -n 50 | tee -a "$OUT"
fi

# ==================================================================
# 14. IP ORIGINAL -- consolidacao (NOVO)
#    Ideia: DNS atual quase sempre e CDN/WAF (Cloudflare etc).
#    O IP real vaza em: OTX/urlscan/VT historico, SPF, siblings,
#    favicon/cert em IP direto, RDAP org divergente.
# ==================================================================
section "14. DESCOBERTA DE IP ORIGINAL (consolidado)"

: > "$TMPDIR/all_candidate_ips.txt"
awk '{print $2}' "$TMPDIR/host_ip_map.txt" 2>/dev/null >> "$TMPDIR/all_candidate_ips.txt"
cat "$TMPDIR"/ips_otx.txt "$TMPDIR"/ips_urlscan.txt "$TMPDIR"/ips_vt.txt "$TMPDIR"/ips_spf.txt "$TMPDIR"/ips_shodan.txt 2>/dev/null >> "$TMPDIR/all_candidate_ips.txt"
grep -oE "$IPREGEX" "$TMPDIR/all_candidate_ips.txt" 2>/dev/null | sort -u > "$TMPDIR/ips_unique.txt" || : > "$TMPDIR/ips_unique.txt"

log "[Todos os IPs candidatos (DNS atual + OTX + urlscan + VT + SPF + Shodan)]:"
cat "$TMPDIR/ips_unique.txt" | tee -a "$OUT"

log "\n[Checa quem e CDN/WAF vs origem (via RDAP org + reverse)]:"
while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    org=$(rdap_ip_org "$ip")
    echo "IP: ${ip} | RDAP_ORG: ${org}" | tee -a "$OUT"
done < "$TMPDIR/ips_unique.txt"

log "\n[Como confirmar o IP original (passo a passo)]:"
log "  1. Descarte CDN/WAF (Cloudflare, Akamai, AWS CloudFront, Imperva, etc. no RDAP_ORG acima)."
log "  2. Sobraram IPs de hospedagem propria (ex: Locaweb, Hostinger, AWS EC2, Azure)? Sao os candidatos."
log "  3. Para cada candidato rode:"
log "       curl -sk -H 'Host: ${DOMAIN}' https://<IP_CANDIDATO>/ | head -n 20"
log "       echo | openssl s_client -connect <IP_CANDIDATO>:443 -servername ${DOMAIN} 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName"
log "       nmap --script ssl-cert -p 443 <IP_CANDIDATO>"
log "     Se o certificado responde com CN/SAN=${DOMAIN} (ou o titulo/Server bate com o site), e o IP real."
log "  4. Cruze com siblings do VT (secao 6): sibling que resolve p/ IP fora de CDN = vhost no mesmo servidor."
log "  5. Cruze com favicon hash (secao 11): shodan 'http.favicon.hash:X' revela outros IPs com o mesmo favicon."
log "  6. Historico DNS: https://viewdns.info/iphistory/?domain=${DOMAIN}"

log "\n[Teste rapido Host-header nos candidatos (so os 20 primeiros)]:"
head -n 20 "$TMPDIR/ips_unique.txt" | while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    code=$(curl -sk --connect-timeout 3 --max-time 10 -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN}" "https://${ip}/")
    title=$(curl -sk --connect-timeout 3 --max-time 10 -H "Host: ${DOMAIN}" "https://${ip}/" 2>/dev/null | grep -oiE '<title>[^<]*</title>' | head -n1)
    echo "IP: ${ip} | Host:${DOMAIN} -> HTTP ${code} ${title}" | tee -a "$OUT"
done

# ==================================================================
# 15. DIRSCAN ideal embutido (NOVO)
#    Sem ffuf/gobuster: wordlist curada de alto sinal + curl paralelo.
#    Foco bug-bounty: .git, .env, backup, admin, api, swagger, actuator.
# ==================================================================
section "15. DIRSCAN (wordlist curada -- sem ferramentas externas)"

cat > "$TMPDIR/wordlist.txt" <<'WLEOF'
admin/
administrator/
login/
wp-login.php
wp-admin/
server-status/
server-info/
api/
api/v1/
api/v2/
graphql
graphiql
swagger/
swagger-ui/
swagger.json
openapi.json
.env
.git/HEAD
.git/config
.svn/entries
.DS_Store
backup.zip
backup.tar.gz
db.sql
dump.sql
phpinfo.php
info.php
actuator/
actuator/health
actuator/env
metrics
debug/
console/
jenkins/
.gitlab-ci.yml
Dockerfile
docker-compose.yml
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
security.txt
.well-known/security.txt
WLEOF

log "[*] Wordlist: $(wc -l < "$TMPDIR/wordlist.txt") paths | Hosts vivos: $(wc -l < "$TMPDIR/live_hosts.txt")"
log "    (paralelo xargs -P 10; ajuste DIRSCAN_P=20 p/ mais velocidade)"

DIRSCAN_P="${DIRSCAN_P:-10}"
: > "$TMPDIR/dirscan_hits.txt"

scan_one() {
    host="$1"
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        url="https://${host}/${p}"
        out=$(curl -sk --connect-timeout 2 --max-time 6 -o /dev/null -w "%{http_code} %{size_download}" "$url" 2>/dev/null)
        code=$(echo "$out" | cut -d' ' -f1)
        size=$(echo "$out" | cut -d' ' -f2)
        case "$code" in
            200|201|301|302|307|308|401|403)
                echo "HIT ${code} size=${size} ${url}" ;;
        esac
    done < "$TMPDIR/wordlist.txt"
}

export TMPDIR
export -f scan_one 2>/dev/null || true

if have xargs && [[ -s "$TMPDIR/live_hosts.txt" ]]; then
    # shellcheck disable=SC2016
    tr -d '\r' < "$TMPDIR/live_hosts.txt" | xargs -P "$DIRSCAN_P" -I{} bash -c 'scan_one "$1"' _ {} 2>/dev/null \
        | sort -u | tee -a "$OUT" > "$TMPDIR/dirscan_hits.txt" || true
else
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        scan_one "$h" | sort -u | tee -a "$OUT" >> "$TMPDIR/dirscan_hits.txt"
    done < "$TMPDIR/live_hosts.txt"
fi

if [[ ! -s "$TMPDIR/dirscan_hits.txt" ]]; then
    log "(nenhum path da wordlist retornou 200/30x/401/403 nos hosts vivos)"
else
    log "\n[Destaques criticos (.git/.env/backup/phpinfo)]:"
    grep -iE '\.git|\.env|backup|\.zip|\.sql|phpinfo|actuator/env' "$TMPDIR/dirscan_hits.txt" | tee -a "$OUT" || log "(nenhum critico)"
fi
log "\n[Dica] p/ fuzz completo use ffuf/gobuster com SecLists raft + Content-Length filter:"
log "  ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,403 -fs <tamanho-do-404>"

# ------------------------------------------------------------------
# 16. Aviso final
# ------------------------------------------------------------------
section "16. FERRAMENTAS SEM API PUBLICA (nao incluidas) + REFERENCIAS"

log "- subfinder   -> substituido por crt.sh + crt.name + OTX + urlscan + VT + SecurityTrails"
log "- webanalyze  -> deteccao de tech exige API paga (Wappalyzer/BuiltWith), nao incluido"
log "- subjs/getjs -> substituidos por extracao propria de <script src> (secao 12)"
log "- jshunter    -> substituido por extracao propria de endpoints via regex (secao 12)"
log "- js_snitch   -> sem equivalente via API, nao incluido"
log "- dnsrecon -d ${DOMAIN} -> equivalente na secao 8 (NS/MX/SOA/AXFR)"
log "- httpx-toolkit -> equivalente parcial na secao 10 (status/server por host)"
log ""
log "Referencias usadas neste script:"
log "  crt.name : https://crt.name/v1/search?apex=${DOMAIN}"
log "  favicon  : https://favicon-hash.kmsec.uk/ | https://favicons.teamtailor-cdn.com/"
log "  otx      : https://otx.alienvault.com/api/v1/indicators/hostname/${DOMAIN}/url_list?limit=500&page=1"
log "  urlscan  : https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=${URLSCAN_SIZE}"
log "  wayback  : https://web.archive.org/cdx/search/cdx?url=${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=5000"
log "  vt       : https://www.virustotal.com/vtapi/v2/domain/report?apikey=...&domain=${DOMAIN}"
log "  spf/mx   : https://mxtoolbox.com/ | https://viewdns.info/"
log "  zoomeye  : https://www.zoomeye.hk/ (dork ssl:\"${DOMAIN}\")"
log "  shodan   : Ssl.cert.subject.CN:\"${DOMAIN}\" | http.favicon.hash:<hash>"

log "\n[OK] Concluido. Tudo em: ${OUT}"

exit 0
