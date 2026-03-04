<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Utils\EMail;

class EmailFactory
{
    /**
     * @throws \PHPMailer\PHPMailer\Exception
     */
    public function build(
        string $subject,
        string $from = null,
        string $to = null,
        string $textTemplate = 'mailtxt.twig',
        string $htmlTemplate = 'mailhtml.twig',
    ): EMail {
        return new EMail(
            $subject,
            $from,
            $to,
            $textTemplate,
            $htmlTemplate,
        );
    }
}
