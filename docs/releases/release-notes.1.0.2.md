v1.0.2 — Documentation fixes

README-only release, no code changes:

- Fix README: NSS and NSPR are vendored as Git submodules (nss, nspr),
 not used from the operating system packages
- Add the submodules to the repository directory structure and a
 `git clone --recursive` hint for cloning them along with the repo
- Remove an incorrect comparison with BoringSslStream
- Drop the reference to a local capture file
 from the README