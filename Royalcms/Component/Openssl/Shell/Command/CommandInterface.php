<?php namespace Royalcms\Component\Openssl\Shell\Command;
/**
 * X509 Certificate Validator
 */

/**
 * Interface for a shell command.
 */
interface CommandInterface
{
    /**
     * @abstract
     * @param  string                  $stdIn
     * @return \Royalcms\Component\Openssl\Shell\Command\CommandInterface
     */
    public function execute($stdIn = "");
    public function getExitStatus();
    public function getOutput();
    public function getErrors();
}
