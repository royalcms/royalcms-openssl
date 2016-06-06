<?php namespace Royalcms\Component\Openssl\Certificate;

use Royalcms\Component\Openssl\Certificate;

/**
 * X509 Certificate Validator
 */

/**
 * Certificate chain.
 */
class Chain
{
    protected $_certificates;

    /**
     * Create a new certificate chain.
     *
     * @param array $certificates
     */
    public function __construct(array $certificates = array())
    {
        $this->_certificates = $certificates;
    }

    /**
     * Add a parent certificate.
     *
     * Note that this does not do any checking! 
     *
     * @param  \Royalcms\Component\Openssl\Certificate       $certificate
     * @return \Royalcms\Component\Openssl\Certificate\Chain
     */
    public function addCertificate(Certificate $certificate)
    {
        array_push($this->_certificates, $certificate);

        return $this;
    }

    /**
     * Get a stack of certificates, top most CA is the last certificate.
     *
     * @return array
     */
    public function getCertificates()
    {
        return $this->_certificates;
    }
}
