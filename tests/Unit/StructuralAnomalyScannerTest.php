<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\StructuralAnomalyScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class StructuralAnomalyScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Setup mock configurations
        config(['scalpel.non_php_zones' => ['public', 'storage', 'bootstrap/cache']]);
        config(['scalpel.structural_allowed_files' => ['public/index.php']]);
        config(['scalpel.structural_allowed_directories' => ['public/legacy-plugin']]);
        config(['scalpel.excluded_paths' => ['vendor', 'node_modules', '.git']]);
    }

    public function test_flags_php_files_in_non_php_zones(): void
    {
        // Create temp directories
        @mkdir($this->tempDir.'/public', 0777, true);
        @mkdir($this->tempDir.'/storage/app', 0777, true);
        @mkdir($this->tempDir.'/bootstrap/cache', 0777, true);

        // Put legitimate/allowed file
        file_put_contents($this->tempDir.'/public/index.php', '<?php echo "Hello";');

        // Put anomalous PHP files
        file_put_contents($this->tempDir.'/public/malicious.php', '<?php eval($_GET["cmd"]);');
        file_put_contents($this->tempDir.'/storage/app/backdoor.php', '<?php phpinfo();');
        file_put_contents($this->tempDir.'/bootstrap/cache/evil.php', '<?php system("whoami");');

        // Put non-PHP files in non-PHP zones (should not be flagged)
        file_put_contents($this->tempDir.'/public/styles.css', 'body {}');
        file_put_contents($this->tempDir.'/storage/app/data.txt', 'some text');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(3, $findings);

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/malicious.php', $files);
        $this->assertContains('storage/app/backdoor.php', $files);
        $this->assertContains('bootstrap/cache/evil.php', $files);
        $this->assertNotContains('public/index.php', $files);
    }

    public function test_flags_non_standard_php_extensions(): void
    {
        @mkdir($this->tempDir.'/public/icons', 0777, true);
        @mkdir($this->tempDir.'/storage/app', 0777, true);

        file_put_contents($this->tempDir.'/public/icons/shell.phtml', '<?php eval($_POST["c"]);');
        file_put_contents($this->tempDir.'/public/icons/x.pht', '<?php system("id");');
        file_put_contents($this->tempDir.'/storage/app/y.phar', '<?php phpinfo();');
        file_put_contents($this->tempDir.'/public/normal.css', 'body {}');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(3, $findings);

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/icons/shell.phtml', $files);
        $this->assertContains('public/icons/x.pht', $files);
        $this->assertContains('storage/app/y.phar', $files);
    }

    public function test_flags_double_extension_webshells(): void
    {
        @mkdir($this->tempDir.'/public/uploads', 0777, true);

        file_put_contents($this->tempDir.'/public/uploads/shell.php.jpg', 'GIF89a<?php eval($_POST["c"]); ?>');
        file_put_contents($this->tempDir.'/public/uploads/photo.png', 'binary-image-data');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);

        $finding = $findings->all()[0];
        $this->assertEquals('HIGH', $finding->severity->value);
        $this->assertEquals('public/uploads/shell.php.jpg', $finding->file);
        $this->assertStringContainsString('embeds a PHP extension', $finding->description);
    }

    public function test_respects_allowed_directories(): void
    {
        @mkdir($this->tempDir.'/public/legacy-plugin/package', 0777, true);
        file_put_contents($this->tempDir.'/public/legacy-plugin/package/asset.php', '<?php return [];');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_shipped_config_does_not_allow_public_vendor(): void
    {
        /** @var array{structural_allowed_directories: string[]} $shipped */
        $shipped = require __DIR__.'/../../config/scalpel.php';

        $this->assertNotContains('public/vendor', $shipped['structural_allowed_directories']);
    }

    public function test_flags_php_files_in_public_vendor_with_shipped_config(): void
    {
        /** @var array{structural_allowed_directories: string[]} $shipped */
        $shipped = require __DIR__.'/../../config/scalpel.php';
        config(['scalpel.structural_allowed_directories' => $shipped['structural_allowed_directories']]);

        // Published assets (JS/CSS) are fine; a PHP file here is a web shell indicator.
        @mkdir($this->tempDir.'/public/vendor/horizon', 0777, true);
        file_put_contents($this->tempDir.'/public/vendor/horizon/app.js', 'console.log(1);');
        file_put_contents($this->tempDir.'/public/vendor/horizon/shell.php', '<?php eval($_POST["c"]);');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertSame('public/vendor/horizon/shell.php', $findings->all()[0]->file);
    }

    public function test_always_excludes_laravel_framework_directories(): void
    {
        // storage/framework/views contains compiled Blade templates (legitimate PHP files)
        // storage/framework/cache contains real-time facade cache files (legitimate PHP files)
        // These should NEVER be flagged, even if user config doesn't list them
        @mkdir($this->tempDir.'/storage/framework/views', 0777, true);
        @mkdir($this->tempDir.'/storage/framework/cache', 0777, true);

        // Create compiled Blade view files (empty and non-empty)
        file_put_contents($this->tempDir.'/storage/framework/views/abc123.php', '');
        file_put_contents($this->tempDir.'/storage/framework/views/def456.php', '<?php echo "compiled blade";');

        // Create real-time facade cache files
        file_put_contents($this->tempDir.'/storage/framework/cache/facade-1e06026dbe325cba543b.php', '<?php

namespace Facades\App\Services;

use Illuminate\Support\Facades\Facade;

class MyService extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \'App\Services\MyService\';
    }
}
');

        // Also create a real anomaly elsewhere in storage to make sure scanning still works
        @mkdir($this->tempDir.'/storage/app', 0777, true);
        file_put_contents($this->tempDir.'/storage/app/backdoor.php', '<?php eval("bad");');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        // Compiled Blade views should NOT be flagged
        $this->assertNotContains('storage/framework/views/abc123.php', $files);
        $this->assertNotContains('storage/framework/views/def456.php', $files);

        // Real-time facade caches should NOT be flagged
        $this->assertNotContains('storage/framework/cache/facade-1e06026dbe325cba543b.php', $files);

        // But real anomalies in storage should still be flagged
        $this->assertContains('storage/app/backdoor.php', $files);
        $this->assertCount(1, $findings);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        @symlink($this->tempDir.'/non_existent_file.php', $this->tempDir.'/public/test.php');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/public/test.php');
    }
}
