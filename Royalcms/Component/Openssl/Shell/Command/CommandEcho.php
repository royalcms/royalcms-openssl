<?php namespace Royalcms\Component\Openssl\Shell\Command;
/**
 * X509 Certificate Validator
 */

/**
 * Demo implementation of shell command pattern.
 */
class CommandEcho extends CommandAbstract
{
    const COMMAND = 'echo';

    public function _buildCommand($arguments = array())
    {
        return self::COMMAND . ' ' . escapeshellarg($arguments[0]);
    }
}
