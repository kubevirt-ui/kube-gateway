package proxy

import (
	"html/template"
	"log"
	"net/http"
)

type logoutTemplateData struct {
	BaseAddress    string
	IssuerEndpoint string
}

// logoutHTMLTemplate is a page tempalte that sends a POST request to the logout endpoint.
const logoutHTMLTemplate = `
<html>
<script type="module" crossorigin="anonymous">
	function load() {
		document.getElementById("then").value = "{{.BaseAddress}}/";
		document.forms["logout"].submit();
	}
	window.addEventListener("load", load, false);

	setTimeout(function(){ window.location.href = '/auth/login'; }, 5000);
</script>
</meta>

<body id="body">
	<p>looging out...</p>
	<div style="visibility: hidden">
		<form name="logout" action="{{.IssuerEndpoint}}/logout" target="iframe" method="POST">
			<label for="then">then</label><input id="then" name="then" />
		</form>
		<iframe name="iframe" src=""></iframe>
	</div>
</body>

</html>`

// Logout handle redirection to openshifts logout endpoint.
func (s Server) Logout(w http.ResponseWriter, r *http.Request) {
	// Log request
	log.Printf("%s %v: %+v", r.RemoteAddr, r.Method, r.URL)

	t, err := template.New("page").Parse(logoutHTMLTemplate)
	if err != nil {
		log.Printf("error parsing logout html template: %v", err)
		return
	}

	data := &logoutTemplateData{BaseAddress: s.BaseAddress, IssuerEndpoint: s.IssuerEndpoint}
	err = t.Execute(w, data)
	if err != nil {
		log.Printf("error executing logout html template: %v", err)
		return
	}
}
