# OIDC Module - FAQ

A few common questions gathered from prior discussions.

## Set JSON type for claims

You can set the type of claim by prefixing the claim name with `int:`,
`bool:` or `string:`. If no prefix is present, `string` is assumed.

If a custom claim name starts with a prefix (example: `int:mycustomclaim`)
you can add one of the type prefixes (example: `string:int:mycustomclaim`)
to force the module to release a claim with the original prefix in it
(example: claim `int:mycustomclaim` of type `string`).

## Release photo

The OIDC `picture` claim is a URL, while the LDAP attribute `jpegPhoto`
is often a base64 string. To use `jpegPhoto`, try an authproc filter to
turn it into a data URL by adding the `data:image/jpeg;base64,` prefix.
Support for data URLs varies by OIDC client, so test your clients.
