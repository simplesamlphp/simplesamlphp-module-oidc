<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * How a configuration overview row value should be rendered.
 *
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\Row
 */
enum ConfigOverviewValueTypeEnum: string
{
    /** Translatable UI literal, for example, 'Yes' or 'None configured'. */
    case Text = 'text';

    /**
     * Value which must be shown exactly as configured, for example, an issuer, an auth source ID or
     * a cache adapter class. Never passed through the translator, both because it is data rather
     * than UI text, and so that a configured value which happens to match a message ID can not be
     * rewritten.
     */
    case RawText = 'rawText';

    /** String to be rendered as a hyperlink. */
    case Url = 'url';

    /** List of strings, rendered as an unordered list. */
    case StringList = 'stringList';

    /** Map with string keys and string list values, for example, auth source to ACR values. */
    case StringMap = 'stringMap';

    /** Arbitrary array, rendered as a pretty-printed JSON code box. */
    case Json = 'json';

    /** \SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag instance. */
    case SignatureKeyPairs = 'signatureKeyPairs';

    /** Scope definitions, as prepared by the overview builder. */
    case Scopes = 'scopes';

    /** Trust Anchor definitions (entity ID and optional JWKS), as prepared by the overview builder. */
    case TrustAnchors = 'trustAnchors';

    /** Resolved Trust Marks (type and payload), as prepared by the overview builder. */
    case TrustMarks = 'trustMarks';

    /** Supported Verifiable Credential configurations, as prepared by the overview builder. */
    case CredentialConfigurations = 'credentialConfigurations';

    /** Administration UI permissions (inspected attribute and entitlements), as prepared by the overview builder. */
    case AdminUiPermissions = 'adminUiPermissions';
}
