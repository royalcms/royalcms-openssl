<?php namespace Royalcms\Component\Openssl\Certificate;

use Royalcms\Component\Openssl\Certificate;

/**
 * X509 Certificate Validator
 */

/**
 * Utility class dealing with certificates.
 */
class Utility
{
    /**
     * Look for PEM encoded certs in text (like Mozillas CA bundle).
     *
     * @static
     * @param  string $text
     * @return array  Certificates found (array of \Royalcms\Component\Openssl\Certificate objects)
     */
    public static function getCertificatesFromText($text)
    {
        $inputLines = explode(PHP_EOL, $text);
        $certificatesFound = array();
        $recording = false;
        $certificate = "";
        foreach ($inputLines as $inputLine) {
            if (trim($inputLine) === "-----BEGIN CERTIFICATE-----") {
                $certificate = "";

                $recording = true;
            }

            if ($recording) {
                $certificate .= $inputLine . PHP_EOL;
            }

            if (trim($inputLine) === "-----END CERTIFICATE-----") {
                $certificate = new Certificate($certificate);
                $certificatesFound[$certificate->getSubjectDN()] = $certificate;
                $recording = false;
            }
        }

        return $certificatesFound;
    }
}
