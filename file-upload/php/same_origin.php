<?php

// Cross-site request forgery guard for the upload endpoints. config.php loads
// this file, so both submit.php and the vendored FilePond index.php enforce it.
//
// A browser that attaches a logged-in user's credentials (basic/LDAP auth, or a
// session cookie) to a request also tells us where that request came from:
// Sec-Fetch-Site on every current browser, and Origin on any browser that makes
// a non-GET request. A request carrying neither header did not come from a web
// page in a browser (e.g. curl), so it cannot be a forgery on someone else's
// behalf. This is the same policy as Go's net/http CrossOriginProtection.

function same_origin_strip_port($host) {
    $host = strtolower(trim($host));
    if (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $host, $m)) {
        return $m[1];
    }
    $colon = strrpos($host, ':');
    if (($colon !== false) && (strpos($host, ':') === $colon)) {
        $host = substr($host, 0, $colon);
    }
    return $host;
}

// Hostnames this deployment answers to, as seen by the browser. Malcolm's nginx
// proxy forwards the client's Host as both Host and X-Forwarded-Host. Ports are
// ignored on purpose: the published port (e.g. 443 or 8443) is not reliably
// visible from inside the container, and the hostname alone is what a
// third-party page cannot forge.
function same_origin_expected_hosts() {
    $hosts = array();
    foreach (array('HTTP_X_FORWARDED_HOST', 'HTTP_HOST', 'SERVER_NAME') as $key) {
        if (!isset($_SERVER[$key])) continue;
        foreach (explode(',', $_SERVER[$key]) as $candidate) {
            $candidate = same_origin_strip_port($candidate);
            if (strlen($candidate) > 0) $hosts[] = $candidate;
        }
    }
    return $hosts;
}

function same_origin_origin_matches($origin) {
    $parts = @parse_url(trim($origin));
    if (!is_array($parts) || !isset($parts['host']) || (strlen($parts['host']) === 0)) {
        return false;
    }
    return in_array(same_origin_strip_port($parts['host']), same_origin_expected_hosts(), true);
}

function same_origin_reject($reason) {
    $client = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    error_log(sprintf('Rejected cross-site %s %s from %s (%s)',
        $_SERVER['REQUEST_METHOD'] ?? '?', $_SERVER['SCRIPT_NAME'] ?? '?', $client, $reason));
    http_response_code(403);
    header('Content-Type: text/plain');
    header('Cache-Control: no-store');
    echo "Forbidden: cross-site requests are not accepted by this endpoint\n";
    exit;
}

function same_origin_enforce() {
    // this endpoint is same-origin only, so never advertise cross-origin access
    header_remove('Access-Control-Allow-Origin');
    header_remove('Access-Control-Allow-Methods');
    header_remove('Access-Control-Allow-Headers');

    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if (in_array($method, array('GET', 'HEAD', 'OPTIONS'), true)) return;

    if (isset($_SERVER['HTTP_SEC_FETCH_SITE'])) {
        $site = strtolower(trim($_SERVER['HTTP_SEC_FETCH_SITE']));
        if (($site === 'same-origin') || ($site === 'none')) return;
        same_origin_reject('Sec-Fetch-Site: ' . $site);
    }

    if (isset($_SERVER['HTTP_ORIGIN'])) {
        if (same_origin_origin_matches($_SERVER['HTTP_ORIGIN'])) return;
        same_origin_reject('Origin: ' . $_SERVER['HTTP_ORIGIN']);
    }
}

same_origin_enforce();
