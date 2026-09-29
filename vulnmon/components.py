"""组件画像:识别漏洞涉及的是哪类常用系统(CMS/中间件/边界设备/OA/邮件/视频监控等)。

用途:
1. 暴露面加权:边界设备/VPN、中间件、CMS、OA 这类常暴露公网、内网遍地都是的系统,
   同分数下优先推送(见 config 的 focus_categories);
2. 给 AI 判定「是否值得复现」提供资产背景;
3. 日报与 feed.json 里标注组件类型,一眼看出影响的是哪类资产。

匹配基于 CPE 厂商/产品名、KEV 名称、GHSA 包名,均为小写子串匹配;
关键词按长度降序尝试,保证「fortigate」优先于「fortinet」这类宽词。
"""

from __future__ import annotations

# 类别 -> 关键词列表。类别名即最终展示名,config 的 focus_categories 也用这些名字。
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "边界设备/VPN": [
        "fortigate", "fortinet", "fortios", "fortimanager", "fortimail", "fortiweb",
        "palo alto", "pan-os", "globalprotect", "ivanti", "pulse secure", "connect secure",
        "citrix", "netscaler", "sharefile", "sangfor", "深信服", "hillstone", "山石",
        "openvpn", "wireguard", "array networks", "华为 secoway", "usg", "sonicwall",
        "zoho manageengine", "f5", "big-ip", "bigip",
    ],
    "安全设备": [
        "奇安信", "天融信", "topsec", "网御", "leadsec", "venustech", "启明星辰",
        "paloalto", "crowdstrike", "sentinelone", "sophos", "trend micro", "eset",
        "kaspersky", "mcafee", "symantec", "bitdefender", "chkrootkit", "wazuh",
    ],
    "视频监控": [
        "hikvision", "海康威视", "dahua", "大华", "uniview", "宇视", "ezviz", "萤石",
        "axis", "bosch security", "hanwha", "wisenet", "d-link dcs", "vivotek",
    ],
    "邮件系统": [
        "microsoft exchange", "exchange server", "exchange_server",
        "coremail", "hmailserver", "zimbra", "postfix", "dovecot",
        "lotus domino", "domino", "turbo-mail", "turboimail", "winmail", "u-mail",
        "magicmail", "cmail",
    ],
    "OA/协同办公": [
        "用友", "yonyou", "金蝶", "kingdee", "泛微", "weaver", "e-cology", "致远",
        "seeyon", "万户", "wanhu", "蓝凌", "landray", "通达", "tongda", "oa ",
        "ruoyi", "若依", "jeecg", "springblade", "柠檬", "hiprint",
        "dzzoffice", "x2openoffice", "libreoffice", "wps office", "wps", "onlyoffice",
        "confluence", "jira", "bitbucket", "dingtalk", "yida", "明道云",
    ],
    "ERP/业务系统": [
        "sap ", "oracle e-business", "servicenow", "salesforce", "dynamics 365",
        "odoo", "erpnext", "infor", "用友 nc", "金蝶云", "管家婆", "kinggrid",
        "金格", "iwebshop", "crmeb", "locatory", "cookieauth",
    ],
    "Web中间件": [
        "weblogic", "websphere", "jboss", "wildfly", "tomcat", "jetty", "undertow",
        "resin", "iis", "haproxy", "traefik", "kong", "apisix", "envoy", "lighttpd",
        "httpd", "nginx unit", "openresty", "caddy", "coldfusion", "webtop",
    ],
    "Web框架": [
        "spring framework", "spring security", "springboot", "spring boot", "spring cloud",
        "struts", "thinkphp", "laravel", "django", "flask", "rails", "sinatra",
        "gin-gonic", "beego", "yii", "codeigniter", "symfony", "cakephp", "fuelphp",
        "vite", "nuxt", "next.js", "nextjs",
    ],
    "CMS": [
        "wordpress", "joomla", "drupal", "dedecms", "织梦", "typecho", "pbootcms",
        "emlog", "zblog", "halo", "ghost", "magento", "shopware", "opencart",
        "prestashop", "craft cms", "strapi", "directus", "umbraco", "sitecore",
        "liferay", "plone", "concrete5", "phpmywind", "五指", "小猪", "eyoucms",
        "迅睿", "thinkcmf", "fastadmin", "hyperf", "limeurvey",
    ],
    "开发运维/CI": [
        "jenkins", "gitlab", "gitea", "gogs", "nexus", "artifactory", "harbor",
        "sonarqube", "argocd", "drone", "teamcity", "bamboo", "circleci",
        "ansible", "terraform", "chef", "puppet", "saltstack", "gitee", "coding.net",
    ],
    "容器/虚拟化": [
        "vmware", "esxi", "vcenter", "vrealize", "docker", "kubernetes", " k8s",
        "rancher", "proxmox", "ovirt", "xen", "hyper-v", "containerd", "podman",
        "istio", "cilium", "harmony",
    ],
    "数据库": [
        "mysql", "mariadb", "postgres", "oracle database", "sql server", "mssql",
        "mongodb", "redis", "elasticsearch", "couchdb", "cassandra", "influxdb",
        "达梦", "dameng", "人大金仓", "kingbase", "tidb", "oceanbase", " polardb",
    ],
    "监控运维": [
        "zabbix", "grafana", "prometheus", "nagios", "cacti", "observium", "librenms",
        "prtg", "solarwinds", "datadog", "splunk", "kibana", "logstash", "graylog",
        "夜莺", "n9e", "blueking", "蓝鲸",
    ],
    "NAS/存储": [
        "synology", "群晖", "qnap", "威联通", "truenas", "freenas", "western digital",
        "netgear readynas", "asustor", "terrastation", "minio", "ceph", "gluster",
        "smartdns",
    ],
    "网络设备": [
        "cisco", "juniper", "h3c", "huawei", "华为", "ruijie", "锐捷", "tp-link",
        "mikrotik", "ubiquiti", "aruba", "zyxel", "netgear", "d-link", "tplink",
        " 华三", "openwrt", "padavan", "iosa", "nx-os",
    ],
    "操作系统": [
        "windows", "linux kernel", "ubuntu", "debian", "centos", "rhel", "red hat",
        "fedora", "suse", "alpine", "android", "ios ", "macos", "chrome os",
        "统信", "uos", "麒麟", "kylin", "openeuler", "openeharmony",
    ],
    "开发库/依赖": [
        "log4j", "logback", "jackson", "fastjson", "xstream", "commons-", "guava",
        "openssl", "openssl", "zlib", "curl", "libcurl", "libssh", "openvpn3",
        "numpy", "pillow", "requests", "urllib3", "axios", "lodash", "left-pad",
        "minio-go", "golang.org", "pypi", "npm ", "maven ", "composer",
    ],
}

# 知名开源产品的上游源码仓库(CPE 厂商/产品 -> GitHub 仓库),
# 详情页「源码与资料」区用于给出门源码直达地址;未收录的走仓库搜索链接
SOURCE_REPOS = {
    "nginx": "nginx/nginx", "httpd": "apache/httpd", "apache": "apache/httpd",
    "tomcat": "apache/tomcat", "jboss": "wildfly/wildfly", "wildfly": "wildfly/wildfly",
    "struts": "apache/struts", "spring": "spring-projects/spring-framework",
    "spring_framework": "spring-projects/spring-framework",
    "spring_security": "spring-projects/spring-security",
    "log4j": "apache/logging-log4j2", "jackson": "FasterXML/jackson-databind",
    "fastjson": "alibaba/fastjson", "openssl": "openssl/openssl",
    "openssh": "openssh/openssh-portable", "curl": "curl/curl", "libcurl": "curl/curl",
    "zlib": "madler/zlib", "libpng": "pnggroup/libpng", "linux": "torvalds/linux",
    "kernel": "torvalds/linux", "sudo": "sudo-project/sudo", "systemd": "systemd/systemd",
    "docker": "moby/moby", "containerd": "containerd/containerd",
    "kubernetes": "kubernetes/kubernetes", "k8s": "kubernetes/kubernetes",
    "rancher": "rancher/rancher", "qemu": "qemu/qemu", "xen": "xen-project/xen",
    "proxmox": "proxmox/pve-manager", "lxd": "canonical/lxd",
    "cloud-init": "canonical/cloud-init", "kyverno": "kyverno/kyverno",
    "gitlab": "gitlabhq/gitlabhq", "gitea": "go-gitea/gitea", "gogs": "gogs/gogs",
    "jenkins": "jenkinsci/jenkins", "nexus": "sonatype/nexus-public",
    "harbor": "goharbor/harbor", "sonarqube": "SonarSource/sonarqube",
    "argocd": "argocd/argo-cd", "grafana": "grafana/grafana",
    "zabbix": "zabbix/zabbix", "prometheus": "prometheus/prometheus",
    "nagios": "NagiosEnterprises/nagioscore", "cacti": "Cacti/cacti",
    "graylog": "Graylog2/graylog2-server", "wordpress": "WordPress/WordPress",
    "joomla": "joomla/joomla-cms", "drupal": "drupal/drupal",
    "magento": "magento/magento2", "ghost": "TryGhost/Ghost", "halo": "halo-dev/halo",
    "django": "django/django", "flask": "pallets/flask", "fastapi": "fastapi/fastapi",
    "requests": "psf/requests", "python": "python/cpython", "php": "php/php-src",
    "rails": "rails/rails", "laravel": "laravel/laravel", "thinkphp": "top-think/framework",
    "redis": "redis/redis", "memcached": "memcached/memcached",
    "mongodb": "mongodb/mongo", "elasticsearch": "elastic/elasticsearch",
    "clickhouse": "ClickHouse/ClickHouse", "mysql": "mysql/mysql-server",
    "mariadb": "mariadb/server", "postgresql": "postgres/postgres",
    "sqlite": "sqlite/sqlite", "couchdb": "apache/couchdb",
    "influxdb": "influxdata/influxdb", "imagemagick": "ImageMagick/ImageMagick",
    "ffmpeg": "FFmpeg/FFmpeg", "keycloak": "keycloak/keycloak", "minio": "minio/minio",
    "ceph": "ceph/ceph", "gluster": "gluster/glusterfs",
    "haproxy": "haproxy/haproxy", "envoy": "envoyproxy/envoy",
    "traefik": "traefik/traefik", "caddy": "caddyserver/caddy",
    "lighttpd": "lighttpd/lighttpd", "varnish": "varnishcache/varnish-cache",
    "squid": "squid-cache/squid", "openvpn": "OpenVPN/openvpn",
    "wireguard": "WireGuard/wireguard", "strongswan": "strongswan/strongswan",
    "vm2": "patriksimek/vm2", "pyjwt": "jpadilla/pyjwt",
    "froxlor": "froxlor/Froxlor", "roundcube": "roundcube/roundcubemail",
    "chromium": "chromium/chromium", "chrome": "chromium/chromium",
    "firefox": "mozilla/gecko-dev", "webkit": "WebKit/WebKit",
}

# GHSA 包生态 -> 包注册页(源码入口)
PACKAGE_PAGES = {
    "pip": "https://pypi.org/project/{pkg}/",
    "npm": "https://www.npmjs.com/package/{pkg}",
    "go": "https://pkg.go.dev/{pkg}",
    "maven": "https://central.sonatype.com/artifact/{pkg}",
    "composer": "https://packagist.org/packages/{pkg}",
    "gem": "https://rubygems.org/gems/{pkg}",
    "nuget": "https://www.nuget.org/packages/{pkg}",
    "cargo": "https://crates.io/crates/{pkg}",
    "pub": "https://pub.dev/packages/{pkg}",
}


def source_repo_url(item: dict) -> tuple[str, str] | None:
    """返回 (显示名, URL):上游源码仓库或包注册页;识别不出返回 None。"""
    for r in item.get("ghsa_ranges") or []:
        head = (r.split(":", 1)[0] or "").lower()
        rest = r.split(":", 1)[1] if ":" in r else ""
        pkg = rest.split()[0] if rest.split() else ""
        tpl = PACKAGE_PAGES.get(head)
        if tpl and pkg:
            return f"{head}:{pkg}", tpl.format(pkg=pkg)
    for p in item.get("products") or []:
        vendor, _, prod = p.partition(" ")
        for key in (vendor, prod, prod.replace("_", "")):
            if key in SOURCE_REPOS:
                repo = SOURCE_REPOS[key]
                return repo, f"https://github.com/{repo}"
    return None


# 展开为按关键词长度降序的匹配表,避免宽词抢先命中
_FLAT: list[tuple[str, str]] = sorted(
    ((kw, cat) for cat, kws in CATEGORY_KEYWORDS.items() for kw in kws),
    key=lambda t: len(t[0]), reverse=True)


def classify(item: dict) -> str | None:
    """判断漏洞涉及的组件类别;识别不出返回 None。"""
    hay = " ".join([
        " ".join(item.get("products", [])),
        item.get("kev_name") or "",
        " ".join(item.get("ghsa_ranges", [])),
        " ".join(item.get("desc", "")[:220].split()),
    ]).lower()
    if not hay.strip():
        return None
    for kw, cat in _FLAT:
        if kw in hay:
            return cat
    return None
