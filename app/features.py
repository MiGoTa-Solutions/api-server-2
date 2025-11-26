from __future__ import annotations

import re
import socket
from typing import Dict
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}
REQUEST_TIMEOUT = 5
SOCIAL_KEYWORDS = ("facebook", "instagram", "linkedin", "twitter", "whatsapp")


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _normalize_domain(netloc: str) -> str:
    if netloc.startswith("www."):
        return netloc[4:]
    return netloc


def _split_domain(domain: str) -> tuple[str, str]:
    clean_domain = domain.split(":", 1)[0]
    parts = clean_domain.split(".")
    if len(parts) < 2:
        return clean_domain, ""
    return clean_domain, parts[-1]


def _count_self_redirects(domain: str, history: list[requests.Response]) -> int:
    total = 0
    for item in history:
        parsed = urlparse(item.headers.get("Location", item.url))
        redirect_domain = _normalize_domain(parsed.netloc.lower())
        if redirect_domain == domain:
            total += 1
    return total


def _compute_match_score(text: str, token: str) -> float:
    if not text or not token:
        return 0.0
    text_lower = text.lower()
    token_lower = token.lower()
    if token_lower in text_lower:
        return 1.0
    return 0.0


def extract_url_features(url: str) -> Dict[str, float | int | str]:
    parsed = urlparse(url)
    domain = _normalize_domain(parsed.netloc.lower())
    domain, tld = _split_domain(domain)

    features: Dict[str, float | int | str] = {}

    # --- Basic URL structure ---
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)
    try:
        socket_inet = domain if domain else "0.0.0.0"
        socket.inet_aton(socket_inet)  # type: ignore[attr-defined]
        features["IsDomainIP"] = 1
    except Exception:
        features["IsDomainIP"] = 0
    features["TLD"] = tld
    features["TLDLength"] = len(tld)
    subdomain_parts = domain.split(".") if domain else []
    features["NoOfSubDomain"] = max(len(subdomain_parts) - 2, 0)

    # --- Character counts ---
    features["NoOfLettersInURL"] = sum(char.isalpha() for char in url)
    features["NoOfDegitsInURL"] = sum(char.isdigit() for char in url)
    features["LetterRatioInURL"] = _safe_ratio(features["NoOfLettersInURL"], len(url))
    features["DegitRatioInURL"] = _safe_ratio(features["NoOfDegitsInURL"], len(url))

    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")
    total_special = sum(not char.isalnum() for char in url)
    other_special = total_special - (
        features["NoOfEqualsInURL"]
        + features["NoOfQMarkInURL"]
        + features["NoOfAmpersandInURL"]
    )
    features["NoOfOtherSpecialCharsInURL"] = max(other_special, 0)
    features["SpacialCharRatioInURL"] = _safe_ratio(
        features["NoOfOtherSpecialCharsInURL"], len(url)
    )

    obfuscated_count = url.count("@") + url.count("-")
    features["HasObfuscation"] = 1 if obfuscated_count else 0
    features["NoOfObfuscatedChar"] = obfuscated_count
    features["ObfuscationRatio"] = _safe_ratio(obfuscated_count, len(url))

    # --- Placeholder statistical scores ---
    features["URLSimilarityIndex"] = 100.0
    features["CharContinuationRate"] = 1.0
    features["URLCharProb"] = 0.5
    features["TLDLegitimateProb"] = 0.5

    features["IsHTTPS"] = 1 if parsed.scheme == "https" else 0

    features["NoOfSelfRedirect"] = 0
    features["NoOfURLRedirect"] = 0
    features["HasDescription"] = 0

    html = ""
    soup: BeautifulSoup | None = None

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=DEFAULT_HEADERS)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        features["NoOfURLRedirect"] = len(response.history)
        features["NoOfSelfRedirect"] = _count_self_redirects(domain, response.history)
    except Exception:
        soup = None

    if html:
        lines = html.splitlines()
        features["LineOfCode"] = len(lines)
        features["LargestLineLength"] = max((len(line) for line in lines), default=0)
    else:
        features["LineOfCode"] = 0
        features["LargestLineLength"] = 0

    title_text = ""
    if soup and soup.title and soup.title.string:
        title_text = soup.title.string.strip()
        features["HasTitle"] = 1
    else:
        features["HasTitle"] = 0

    features["DomainTitleMatchScore"] = _compute_match_score(title_text, domain)
    features["URLTitleMatchScore"] = _compute_match_score(title_text, url)

    if soup:
        favicon = soup.find("link", rel=re.compile("icon", re.IGNORECASE))
        features["HasFavicon"] = 1 if favicon else 0
        robots_meta = soup.find("meta", attrs={"name": "robots"})
        features["Robots"] = 1 if robots_meta else 0
        viewport = soup.find("meta", attrs={"name": "viewport"})
        features["IsResponsive"] = 1 if viewport else 0
        description = soup.find("meta", attrs={"name": "description"})
        features["HasDescription"] = 1 if description else 0

        images = soup.find_all("img")
        stylesheets = [
            link
            for link in soup.find_all("link")
            if any(str(rel).lower() == "stylesheet" for rel in link.get("rel", []))
        ]
        scripts = soup.find_all("script")
        anchors = soup.find_all("a", href=True)

        features["NoOfImage"] = len(images)
        features["NoOfCSS"] = len(stylesheets)
        features["NoOfJS"] = len(scripts)

        self_refs = 0
        empty_refs = 0
        external_refs = 0
        for anchor in anchors:
            href = anchor["href"].strip()
            if not href or href == "#":
                empty_refs += 1
                continue
            anchor_parsed = urlparse(href)
            href_domain = anchor_parsed.netloc.lower()
            href_domain = _normalize_domain(href_domain)
            if href.startswith("/") or href_domain == domain:
                self_refs += 1
            else:
                external_refs += 1
        features["NoOfSelfRef"] = self_refs
        features["NoOfEmptyRef"] = empty_refs
        features["NoOfExternalRef"] = external_refs

        features["NoOfPopup"] = len(soup.find_all("popup"))
        features["NoOfiFrame"] = len(soup.find_all("iframe"))

        forms = soup.find_all("form")
        features["HasExternalFormSubmit"] = 0
        features["HasSubmitButton"] = 0
        features["HasHiddenFields"] = 0
        features["HasPasswordField"] = 0
        for form in forms:
            action = (form.get("action") or "").strip()
            if action:
                action_domain = _normalize_domain(urlparse(action).netloc.lower())
                if action_domain and action_domain != domain:
                    features["HasExternalFormSubmit"] = 1
            if form.find("button", {"type": "submit"}) or form.find("input", {"type": "submit"}):
                features["HasSubmitButton"] = 1
            if form.find("input", {"type": "hidden"}):
                features["HasHiddenFields"] = 1
            if form.find("input", {"type": "password"}):
                features["HasPasswordField"] = 1

        lower_html = html.lower()
        features["HasSocialNet"] = 1 if any(keyword in lower_html for keyword in SOCIAL_KEYWORDS) else 0
        features["Bank"] = 1 if "bank" in lower_html else 0
        features["Pay"] = 1 if "pay" in lower_html else 0
        features["Crypto"] = 1 if "crypto" in lower_html else 0
        features["HasCopyrightInfo"] = 1 if ("copyright" in lower_html or "\u00a9" in html) else 0
    else:
        zero_columns = [
            "HasFavicon",
            "Robots",
            "IsResponsive",
            "NoOfImage",
            "NoOfCSS",
            "NoOfJS",
            "NoOfSelfRef",
            "NoOfEmptyRef",
            "NoOfExternalRef",
            "NoOfPopup",
            "NoOfiFrame",
            "HasExternalFormSubmit",
            "HasSocialNet",
            "HasSubmitButton",
            "HasHiddenFields",
            "HasPasswordField",
            "Bank",
            "Pay",
            "Crypto",
            "HasCopyrightInfo",
        ]
        for column in zero_columns:
            features[column] = 0

    return features
