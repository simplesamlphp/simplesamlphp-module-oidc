# Set JSON type for claims

You can set the type of claim by prefixing the name with `int:`, `bool:` or `string:`. If no prefix is set then `string`
is assumed. In the rare event that your custom claim name starts with a prefix (example: `int:mycustomclaim`) you can
add one of the type prefixes (example: `string:int:mycustomclaim`) to force the module to release a claim with the
original prefix in it (example: claim `int:mycustomclaim` of type `string`)

# Release photo

The OIDC `picture` claim is an URL, while the `jpegPhoto` LDAP attribute is often a b64 string. To use `jpegPhoto` you
can try using an authproc filter to turn it into a data url by adding `data:image/jpeg;base64,` prefix. The support
for data URLs amongst OIDC client is unknown. 