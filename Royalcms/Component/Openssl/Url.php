<?php namespace Royalcms\Component\Openssl;

use Royalcms\Component\Openssl\Url\UnparsableUrlException;
use Royalcms\Component\Openssl\Command\SClient;
use Royalcms\Component\Openssl\Command\X509;
use Royalcms\Component\Openssl\Certificate;
use Royalcms\Component\Openssl\Certificate\Utility;
use Royalcms\Component\Openssl\Certificate\Chain\Factory;

/**
 * X509 Certificate Validator
 */

/**
 *
 */
class Url
{
    protected $_url;
    protected $_parsed;
    protected $_trustedRootCertificateAuthorityFile;

    protected $_serverCertificatePem;
    protected $_serverCertificateChainPem;

    /**
     * @var \Royalcms\Component\Openssl\Command\SClient
     */
    protected $_connection;

    public function __construct($url)
    {
        $this->_url     = $url;
        $this->_parsed  = parse_url($url);
        if (!$this->_parsed) {
            throw new UnparsableUrlException("Url '$url' is not a valid URL");
        }
    }

    public function setTrustedRootCertificateAuthorityFile($file)
    {
        $this->_trustedRootCertificateAuthorityFile = $file;

        return $this;
    }

    public function getHostName()
    {
        return $this->_parsed['host'];
    }

    public function getUrl()
    {
        return $this->_url;
    }

    public function isHttps()
    {
        return ($this->_parsed && isset($this->_parsed['scheme']) && strtolower($this->_parsed['scheme']) === 'https');
    }

    public function connect()
    {
        $command = new SClient();
        $command->setConnectTo($this->_parsed['host']);
        $command->setShowCerts(true);
        if (isset($this->_trustedRootCertificateAuthorityFile)) {
            $command->setCertificateAuthorityFile($this->_trustedRootCertificateAuthorityFile);
        }
        $command->execute();
        $this->_connection = $command;

        return ($command->getExitStatus() === 0);
    }

    public function getServerCertificate()
    {
        if (!$this->_connection) {
            $this->connect();
        }

        $x509Command = new X509();
        $x509Command->execute($this->_connection->getOutput());
        $pem = $x509Command->getOutput();

        return new Certificate($pem);
    }

    public function getServerCertificateChain()
    {
        $blocks = explode("\n---\n", $this->_connection->getOutput());
        $certificateOutput = $blocks[1];

        $certificatesFound = Utility::getCertificatesFromText($certificateOutput);

        return Factory::createFromCertificates($certificatesFound);
    }

    public function isCertificateValidForUrlHostname()
    {
        $urlCertificate = $this->getServerCertificate();

        $urlHost = $this->getHostName();
        $validHostNames = $urlCertificate->getValidHostNames();

        foreach ($validHostNames as $hostName) {
            if ($this->_doesHostnameMatchPattern($urlHost, $hostName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Match patterns from certificates like:
     * test.example.com
     * or
     * *.test.example.com
     *
     * @param  string $hostname
     * @param  string $pattern
     * @return bool
     */
    protected function _doesHostnameMatchPattern($hostname, $pattern)
    {
        if ($hostname === $pattern) {
            return true; // Exact match
        }

        if (!substr($pattern, 0, 2)==='*.') {
            return false; // Not an exact match, not a wildcard pattern, so no match...
        }

        $pattern = substr($pattern, 2);

        if ($hostname === $pattern) {
            return true; // Exact match for pattern root, eg *.example.com also matches example.com
        }

        // Remove sub-domain
        $hostname = substr($hostname, strpos($hostname, '.') + 1);
        if ($hostname === $pattern) {
            return true;
        }

        return false;
    }
}
