// Копія файлу за тим самим шляхом; логін і пароль так само прибрано (CWE-319/798)
function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', '#attack/307/100', true);
    xhttp.send(JSON.stringify({username: "", password: ""}));
}
