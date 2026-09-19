package service

// The service's identity on Windows, in one place.
//
// THREE THINGS HAVE TO AGREE ABOUT THESE STRINGS: the binary, which registers
// and answers to the service; the MSI, which installs it; and the
// documentation, which tells a member what to type. They are declared here and
// the packaging is checked against them by TestPackagingMatchesTheServiceSpec,
// because a disagreement does not break a build — it produces an installer that
// registers `DTPAgent` and a `sc start` line in the README that names something
// else, and the member concludes the agent does not work.
const (
	// Name is the service key: what `sc.exe start` and `net start` take. No
	// spaces, because half the tooling that consumes it does not quote.
	Name = "DTPAgent"

	// DisplayName is what services.msc shows. This is the name an
	// administrator sees months later while deciding whether the thing is safe
	// to stop, so it says what it is rather than who wrote it.
	DisplayName = "DTP Certificate Discovery Agent"

	// Description is the sentence beside it in the same list. It leads with
	// read-only: an unexplained agent from a certificate vendor running as
	// LocalSystem is exactly the thing a security review kills, and the answer
	// to that review should be on the screen where the question is asked.
	Description = "Inventories the certificates installed on this host and reports them to the " +
		"Digital Trust Platform. Read-only: it never reads a private key, installs nothing, " +
		"and modifies no file."

	// Arg is the single argument the service manager starts the binary with.
	// Not a flag, because the Service Control Manager stores it in the
	// registry as part of the image path and an operator reads it there.
	Arg = "service"
)
