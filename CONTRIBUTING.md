# Contributing to Kokos

Thank you for looking at the code. Please read this before opening anything.

## What is welcome

Issues are open to anyone with a GitHub account. Pick a template when you open
one; it asks for what is needed.

- **Bug reports.** Say which version and platform, and how to reproduce it.
  Never paste the contents of a vault, a password, or a recovery hint into an
  issue.
- **Feature requests.** Describe the problem you want solved, not only the
  feature. There is no promise that a request gets built, but every one is read.
- **Questions about the design.** The source is published so it can be checked;
  a question about why something is done a certain way is a fair issue.
- **Security reports.** Do not open a public issue. Use a private vulnerability
  report, as SECURITY.md describes.

## Pull requests

Kokos is free software under the MIT License, but it is maintained as a
single-author project: pull requests are not accepted, and unsolicited
patches will be closed unread.

This is not a judgement about the code offered. A merged patch stays the
copyright of its author. Every outside author would
then have to agree before the project could be relicensed or its rights
transferred, and the project wants to keep both options open. There is no
contributor agreement in place to cover that yet. If that changes, this file
will change with it.

If you have found a fix, describe it in an issue. A clear description of the
defect and of the correct behaviour is genuinely useful and costs you less than
a patch.

## Building

Two things to expect:

- A local build is **not byte-identical** to a released binary. The build is not
  reproducible, so a hash comparison against a release will not match.
- **Google Drive sync will not work in a self-build.** The OAuth client secret
  is not in the repository. Exercising that code path takes a Google OAuth
  client of your own: register a Desktop-app client, supply its secret through
  the `KOKOS_GDRIVE_CLIENT_SECRET` environment variable, and change the
  `GOOGLE_CLIENT_ID` constant in `src-tauri/src/gdrive/oauth.rs` to that
  client's id. Changing only the secret does not work — Google's token endpoint
  rejects a secret that does not belong to the client id sent with it.
