package gate

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// janeImages is a scoped decision whose images are quire-sites/jane/, the others' protected.
func janeImages() *scoped {
	return &scoped{scope: &scope.Scope{Name: "jane", Images: []string{"quire-sites/jane/"}}, policy: config.Containers{ProtectedImages: []string{"quire-sites/"}}}
}

// imageList is Docker's answer to an image list of n images, every step-th of them jane's, written as
// it's read (never held whole), with a hook at its end.
type imageList struct {
	n, step, i int
	pending    []byte
	done       bool
	atEnd      func()
	read       int64
}

func (l *imageList) Read(p []byte) (int, error) {
	for len(l.pending) == 0 {
		switch {
		case l.done:
			if l.atEnd != nil {
				l.atEnd()
				l.atEnd = nil
			}

			return 0, io.EOF
		case l.i == 0:
			l.pending = []byte("[")
		case l.i > l.n:
			l.pending, l.done = []byte("]"), true

			continue
		}

		if l.i > 0 {
			owner := "other"
			if l.i%l.step == 0 {
				owner = "jane"
			}

			sep := ","
			if l.i == 1 {
				sep = ""
			}

			l.pending = fmt.Appendf(l.pending, `%s{"Id":"sha256:%064d","RepoTags":["quire-sites/%s/app:%d"],"RepoDigests":[],"Labels":{"com.example.padding":"%s"},"Size":123456}`, sep, l.i, owner, l.i, strings.Repeat("p", 300))
		}

		l.i++
	}

	n := copy(p, l.pending)
	l.pending = l.pending[n:]
	l.read += int64(n)

	return n, nil
}

// An image list is read one image at a time: of a host's 100,000 images, the gate holds the scope's
// 10, not the host's list (about 50 MiB), when Docker's answer has been read to its end.
func TestAnImageListHoldsOnlyTheScopesImages(t *testing.T) {
	var before, atEnd runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	list := &imageList{n: 100000, step: 10000, atEnd: func() {
		runtime.GC()
		runtime.ReadMemStats(&atEnd)
	}}

	kept, err := janeImages().imagesFrom(list)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Count(string(kept), `"Id"`); got != 10 {
		t.Fatalf("kept %d images, want jane's 10", got)
	}

	if list.read < 40<<20 {
		t.Fatalf("the list read was only %d bytes", list.read)
	}

	held := int64(atEnd.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("read %d MiB of Docker's answer, %d KiB held at its end", list.read>>20, held>>10)

	if held > 4<<20 {
		t.Fatalf("%d KiB held once Docker's list of %d MiB was read: it was held whole", held>>10, list.read>>20)
	}
}

// One image of Docker's list over 1 MiB is refused once about 1 MiB of it is read, not once it's
// all been decoded.
func TestAnImageListsElementIsBoundedAsItsRead(t *testing.T) {
	huge := &countedReader{r: io.MultiReader(strings.NewReader(`[{"RepoTags":["quire-sites/jane/app:1"],"Pad":"`), strings.NewReader(strings.Repeat("a", 2<<20)), strings.NewReader(`"}]`))}

	_, err := janeImages().imagesFrom(huge)

	var refused *refusal
	if !errors.As(err, &refused) || refused.code != CodeAnswerTooLarge || refused.status != http.StatusBadGateway {
		t.Fatalf("%v", err)
	}

	if huge.n > maxListElement+64<<10 {
		t.Fatalf("read %d bytes of a 2 MiB image before refusing it", huge.n)
	}
}

// The scope's list is bounded too, as the client would get it.
func TestAnImageListsKeptListIsBounded(t *testing.T) {
	old := maxListKept
	maxListKept = 4096

	defer func() { maxListKept = old }()

	_, err := janeImages().imagesFrom(&imageList{n: 100, step: 1})

	var refused *refusal
	if !errors.As(err, &refused) || refused.code != CodeAnswerTooLarge {
		t.Fatalf("%v", err)
	}
}

// What isn't a list, or is cut short, is an error, never a list of what was read.
func TestAnImageListThatIsntOne(t *testing.T) {
	for _, answer := range []string{`{}`, `[{"RepoTags":["quire-sites/jane/a:1"]}`, `[{"RepoTags":`, `nope`, ``} {
		if kept, err := janeImages().imagesFrom(strings.NewReader(answer)); err == nil {
			t.Errorf("%q: kept %s", answer, kept)
		}
	}

	kept, err := janeImages().imagesFrom(strings.NewReader(`[]`))
	if err != nil || string(kept) != "[]" {
		t.Errorf("an empty list: %s %v", kept, err)
	}
}

type countedReader struct {
	r io.Reader
	n int64
}

func (c *countedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)

	return n, err
}

// Through the gate: an answer larger than YorvoGate passes on is refused as that, never as Docker
// not answering.
func TestAnAnswerTooLargeIsRefusedAsThat(t *testing.T) {
	old := maxAnswer
	maxAnswer = 64

	defer func() { maxAnswer = old }()

	d := startDocker(t)
	server := gate(t, d, "sites")

	status, answer := send(t, server, "GET", "/v1.56/info", "", asJane)
	if status != http.StatusBadGateway || !strings.Contains(answer, string(CodeAnswerTooLarge)) {
		t.Fatalf("%d %s", status, answer)
	}
}
