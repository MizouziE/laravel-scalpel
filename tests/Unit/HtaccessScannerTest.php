<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\HtaccessScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class HtaccessScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.htaccess_dangerous_handlers' => [
                'cgi-script',
                'python-program',
                'perl-script',
                'ruby-script',
                'application/x-httpd-python',
            ],
        ]);
    }

    public function test_flags_dangerous_add_handler(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddHandler cgi-script .py');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('cgi-script', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_handler_python(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddHandler application/x-httpd-python .php');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-python', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_type(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddType application/x-httpd-php .jpg');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-php', $findings->all()[0]->description);
    }

    public function test_flags_security_disabling_php_flags(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', '
            php_flag allow_url_include on
            php_value disable_functions none
        ');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertEquals('CRITICAL', $findings->all()[1]->severity->value);
    }

    public function test_flags_auto_prepend_file_in_htaccess(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'php_value auto_prepend_file /tmp/shell.txt');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('auto_prepend_file', $findings->all()[0]->description);
    }

    public function test_reports_error_for_unreadable_htaccess(): void
    {
        $htaccessPath = $this->tempDir.'/.htaccess';
        file_put_contents($htaccessPath, 'AddHandler cgi-script .py');
        @chmod($htaccessPath, 0000);

        if (@fopen($htaccessPath, 'r') !== false) {
            @chmod($htaccessPath, 0644);
            $this->markTestSkipped('Cannot make file unreadable in this environment.');
        }

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        @chmod($htaccessPath, 0644);

        $this->assertTrue($findings->hasErrors());
        $this->assertEquals('partial', $findings->status());
        $this->assertEquals(1, $findings->skippedFilesCount());
    }

    public function test_flags_external_redirects(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'RewriteRule ^(.*)$ http://attacker.com/$1 [R=301,L]');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_force_https_self_redirect_is_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule (.*) https://%{HTTP_HOST}/\$1 [R=301,L]",
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_server_name_self_redirect_is_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,R=301]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_http_host_header_variable_self_redirect_is_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://%{HTTP:Host}/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_external_host_carrying_the_request_host_as_a_parameter_is_still_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://attacker.com/?from=%{HTTP_HOST} [R=302,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString("host 'attacker.com'", $findings->all()[0]->description);
    }

    public function test_external_host_prefixed_with_the_request_host_is_still_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://%{HTTP_HOST}.evil.com/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString("host '%{HTTP_HOST}.evil.com'", $findings->all()[0]->description);
    }

    public function test_external_host_hidden_behind_userinfo_is_still_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://%{HTTP_HOST}@evil.com/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString("host 'evil.com'", $findings->all()[0]->description);
    }

    public function test_self_redirect_with_an_explicit_port_is_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://%{HTTP_HOST}:8443/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_self_redirect_with_the_server_port_variable_is_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^ https://%{HTTP_HOST}:%{SERVER_PORT}%{REQUEST_URI} [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_allowlisted_redirect_host_is_not_flagged(): void
    {
        config(['scalpel.htaccess_allowed_redirect_hosts' => ['example.com']]);
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://example.com/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_allowlisted_redirect_host_ignores_port_and_case(): void
    {
        config(['scalpel.htaccess_allowed_redirect_hosts' => ['Example.COM']]);
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://example.com:8443/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_host_outside_the_allowlist_is_still_flagged(): void
    {
        config(['scalpel.htaccess_allowed_redirect_hosts' => ['example.com']]);
        file_put_contents(
            $this->tempDir.'/.htaccess',
            'RewriteRule ^(.*)$ https://not-example.com/$1 [R=301,L]',
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_relative_rewrite_targets_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/.htaccess',
            "RewriteRule ^ index.php [L]\nRewriteRule ^admin - [F]",
        );

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_flags_exec_cgi_options(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'Options +ExecCGI');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        // Create a broken symlink named .htaccess
        @symlink($this->tempDir.'/non_existent_file.htaccess', $this->tempDir.'/.htaccess');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/.htaccess');
    }
}
