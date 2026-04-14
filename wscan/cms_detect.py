"""
CMS Detector
============
HTML・HTTPヘッダ・URL パターンから CMS を特定する。

対応 CMS: WordPress, Drupal, Django, Laravel, EC-CUBE, Joomla, Magento
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CmsInfo:
    """検出された CMS の情報。"""
    name: str            # "wordpress" | "drupal" | "django" | "laravel" | "ec_cube" | "joomla" | "magento" | "unknown"
    version: str = ""    # 検出できた場合のバージョン
    confidence: str = "low"           # "high" | "medium" | "low"
    indicators: list[str] = field(default_factory=list)

    @property
    def is_known(self) -> bool:
        return self.name != "unknown"


def detect_cms(html: str, headers: dict, url: str) -> CmsInfo:
    """
    HTML・HTTP ヘッダ・URL パターンから CMS を特定する。

    Parameters
    ----------
    html    : ページの HTML 文字列
    headers : HTTP レスポンスヘッダ (dict, lowercase keys preferred)
    url     : ページの URL

    Returns
    -------
    CmsInfo
    """
    # ヘッダキーを小文字に正規化
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    html_lower = html.lower() if html else ""

    # ── WordPress ──────────────────────────────────────────────────────────────
    wp_indicators: list[str] = []
    if "wp-content/" in html_lower or "wp-includes/" in html_lower:
        wp_indicators.append("wp-content/wp-includes in HTML")
    if re.search(r'<meta[^>]+name="generator"[^>]+content="wordpress', html_lower):
        wp_indicators.append("generator meta tag")
    if "wp-login.php" in html_lower or "/wp-admin" in html_lower:
        wp_indicators.append("wp-admin/wp-login.php in HTML")
    if "wordpress" in hdrs.get("x-powered-by", "").lower():
        wp_indicators.append("X-Powered-By header")
    # WordPress Generator version
    wp_version = ""
    m = re.search(r'wordpress\s+([\d.]+)', html_lower)
    if m:
        wp_version = m.group(1)
    if wp_indicators:
        conf = "high" if len(wp_indicators) >= 2 else "medium"
        return CmsInfo("wordpress", wp_version, conf, wp_indicators)

    # ── Drupal ─────────────────────────────────────────────────────────────────
    drupal_indicators: list[str] = []
    if "/sites/default/" in html_lower or "drupal.settings" in html_lower:
        drupal_indicators.append("Drupal path patterns")
    if "drupal" in hdrs.get("x-generator", "").lower():
        drupal_indicators.append("X-Generator header")
    if re.search(r'<meta[^>]+name="generator"[^>]+content="drupal', html_lower):
        drupal_indicators.append("generator meta tag")
    if "Drupal" in hdrs.get("x-drupal-cache", "") or "drupal" in hdrs.get("x-drupal-dynamic-cache", "").lower():
        drupal_indicators.append("X-Drupal-Cache header")
    drupal_ver = ""
    m = re.search(r'drupal\s+([\d.]+)', html_lower)
    if m:
        drupal_ver = m.group(1)
    if drupal_indicators:
        conf = "high" if len(drupal_indicators) >= 2 else "medium"
        return CmsInfo("drupal", drupal_ver, conf, drupal_indicators)

    # ── Django ─────────────────────────────────────────────────────────────────
    django_indicators: list[str] = []
    if "csrfmiddlewaretoken" in html_lower:
        django_indicators.append("csrfmiddlewaretoken in HTML")
    if "django" in hdrs.get("x-powered-by", "").lower() or "django" in hdrs.get("server", "").lower():
        django_indicators.append("Server/X-Powered-By header")
    if re.search(r'/admin/login\?next=', html_lower) or "django administration" in html_lower:
        django_indicators.append("Django admin page detected")
    if django_indicators:
        conf = "high" if len(django_indicators) >= 2 else "medium"
        return CmsInfo("django", "", conf, django_indicators)

    # ── Laravel ────────────────────────────────────────────────────────────────
    laravel_indicators: list[str] = []
    if "laravel_session" in hdrs.get("set-cookie", "") or "laravel_session" in html_lower:
        laravel_indicators.append("laravel_session cookie")
    if "laravel" in hdrs.get("x-powered-by", "").lower():
        laravel_indicators.append("X-Powered-By header")
    if re.search(r'laravel', html_lower):
        laravel_indicators.append("Laravel in HTML")
    if laravel_indicators:
        conf = "high" if len(laravel_indicators) >= 2 else "medium"
        return CmsInfo("laravel", "", conf, laravel_indicators)

    # ── EC-CUBE ────────────────────────────────────────────────────────────────
    eccube_indicators: list[str] = []
    if "/html/user_data/" in html_lower or "ec-cube" in html_lower:
        eccube_indicators.append("EC-CUBE path/keyword in HTML")
    if re.search(r'<meta[^>]+content="ec-cube', html_lower):
        eccube_indicators.append("EC-CUBE generator meta tag")
    if eccube_indicators:
        return CmsInfo("ec_cube", "", "medium", eccube_indicators)

    # ── Joomla ─────────────────────────────────────────────────────────────────
    joomla_indicators: list[str] = []
    if "/administrator/" in html_lower or "joomla" in html_lower:
        joomla_indicators.append("Joomla path/keyword in HTML")
    if re.search(r'<meta[^>]+name="generator"[^>]+content="joomla', html_lower):
        joomla_indicators.append("Joomla generator meta tag")
    joomla_ver = ""
    m = re.search(r'joomla!\s*([\d.]+)', html_lower)
    if m:
        joomla_ver = m.group(1)
    if joomla_indicators:
        conf = "high" if len(joomla_indicators) >= 2 else "medium"
        return CmsInfo("joomla", joomla_ver, conf, joomla_indicators)

    # ── Magento ────────────────────────────────────────────────────────────────
    magento_indicators: list[str] = []
    if "mage" in html_lower and ("magento" in html_lower or "/static/version" in html_lower):
        magento_indicators.append("Mage/Magento keyword in HTML")
    if "X-Magento" in str(hdrs):
        magento_indicators.append("X-Magento header")
    if magento_indicators:
        return CmsInfo("magento", "", "medium", magento_indicators)

    return CmsInfo("unknown", "", "low", [])
