// Логін і пароль прибрано з коду сторінки (CWE-319/798)
function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
    xhttp.send(JSON.stringify({username: "", password: ""}));
}
