package dcedirectory

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func TestListEchoesNonceUnderTheSignature(t *testing.T) {
	h := newHarness(t, nil)
	nonce := strings.Repeat("ab", 16)
	for _, query := range []string{"?nonce=" + nonce, "?limit=1&nonce=" + nonce, "?nonce=" + nonce + "&limit=1"} {
		w := httptest.NewRecorder()
		h.s.ServeHTTP(w, httptest.NewRequest("GET", ListPath+query, nil))
		if w.Code != 200 {
			t.Fatal(query, w.Code, w.Body)
		}
		if !sign.VerifyBody(h.master.Public().(ed25519.PublicKey), w.Header().Get("Signature"), w.Body.Bytes()) {
			t.Fatal("signature")
		}
		var list List
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || list.Nonce != nonce {
			t.Fatal(query, list.Nonce, err)
		}
	}
}

func TestListWithoutNonceKeepsItsBytes(t *testing.T) {
	h := newHarness(t, nil)
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, httptest.NewRequest("GET", ListPath+"?limit=1", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "nonce") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestListRefusesBadNonces(t *testing.T) {
	h := newHarness(t, nil)
	for _, query := range []string{"?nonce=short", "?nonce=" + strings.Repeat("AB", 16), "?nonce=" + strings.Repeat("ab", 16) + "&nonce=" + strings.Repeat("cd", 16), "?nonce=" + strings.Repeat("ab", 16) + "&other=1"} {
		w := httptest.NewRecorder()
		h.s.ServeHTTP(w, httptest.NewRequest("GET", ListPath+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
}
