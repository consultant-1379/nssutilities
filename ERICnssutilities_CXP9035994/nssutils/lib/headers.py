SECURITY_REQUEST_HEADERS = {"X-Requested-With": "XMLHttpRequest"}
DELETE_SECURITY_REQUEST = {"X-Requested-With": "XMLHttpRequest", "If-Match": "*"}
JSON_SECURITY_REQUEST = {"X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json", "Accept": "application/json"}
FLS_HEADERS = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"}
SHM_LONG_HEADER = {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json; charset=UTF-8',
    'Accept': 'application/json, text/javascript, */*; q=0.01'
}
