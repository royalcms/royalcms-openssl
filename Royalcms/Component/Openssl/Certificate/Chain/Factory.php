<?php namespace Royalcms\Component\Openssl\Certificate\Chain;

use Exception;
use Royalcms\Component\Openssl\Certificate\Utility;
use Royalcms\Component\Openssl\Certificate\Chain;
use Royalcms\Component\Openssl\Certificate;
use Royalcms\Component\Openssl\Command\X509;

/**
 * X509 Certificate Validator
 */

/**
 * Build a certificate chain
 */
class Factory
{
    protected static $s_rootCertificates;

    public static function loadRootCertificatesFromFile($filePath)
    {
        if (!file_exists($filePath)) {
            throw new Exception("Unable to load Root certificates, file '$filePath' does not exist");
        }

        $fileContents = file_get_contents($filePath);
        $certificatesFound = Utility::getCertificatesFromText($fileContents);

        self::setRootCertificates($certificatesFound);
    }

    public static function setRootCertificates(array $list)
    {
        self::$s_rootCertificates = $list;
    }

    public static function createFromCertificates(array $certificates)
    {
        $chain = new Chain();
        foreach ($certificates as $certificate) {
            // Root CA?
            if (isset(self::$s_rootCertificates[$certificate->getIssuerDn()])) {
                $certificate->setTrustedRootCertificateAuthority(true);
            }

            $chain->addCertificate($certificate);
        }

        return $chain;
    }

    public static function createFromPems(array $pems)
    {
        $chain = new Chain();
        foreach ($pems as $pem) {
            $certificate = new Certificate($pem);

            // Root CA?
            if (isset(self::$s_rootCertificates[$certificate->getIssuerDn()])) {
                $certificate->setTrustedRootCertificateAuthority(true);
            }

            $chain->addCertificate($certificate);
        }

        return $chain;
    }

    public static function createFromCertificateIssuerUrl(Certificate $certificate, Chain $chain = null)
    {
        if (!$chain) {
            $chain = new Chain();
        }

        $chain->addCertificate($certificate);

        // Self signed?
        if ($certificate->isSelfSigned()) {
            return $chain;
        }

        // Root CA, add it and stop building
        if (isset(self::$s_rootCertificates[$certificate->getIssuerDn()])) {
            $chain->addCertificate(self::$s_rootCertificates[$certificate->getIssuerDn()]);

            return $chain;
        }

        /**
         * Get the certificate for the issuer of this certificate
         */
        $issuerUrls = $certificate->getCertificateAuthorityIssuerUrls();
        if (empty($issuerUrls)) {
            // Can't get the issuer certificate... return the chain as is...
            return $chain;
        }

        foreach ($issuerUrls as $issuerUrl) {
            $issuerCertificate = file_get_contents($issuerUrl);
            if (!$issuerCertificate || trim($issuerCertificate) === "") {
                // @todo Unable to get the issuer certificate... log this somewhere?
                //       For now we silently just use the next issuer url
                continue;
            }

            // Not a PEM certificate? Probably a DER certificate, transform
            if (strpos($issuerCertificate, '-----BEGIN CERTIFICATE-----') === false) {
                $x509Command = new X509();
                $x509Command->setInForm(X509::FORM_DER);
                $x509Command->execute($issuerCertificate)->getOutput();
                $issuerCertificate = $x509Command->getOutput();
            }

            $issuerCertificate = new Certificate($issuerCertificate);

            return self::createFromCertificateIssuerUrl($issuerCertificate, $chain);
        }
        // Can't get the issuer certificate... return the chain as is...
        return $chain;
    }
}
