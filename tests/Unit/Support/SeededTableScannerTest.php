<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\SeededTableScanner;
use ShieldCI\Tests\AnalyzerTestCase;

class SeededTableScannerTest extends AnalyzerTestCase
{
    protected function createAnalyzer(): AnalyzerInterface
    {
        throw new \LogicException('No analyzer under test.');
    }

    private function scanner(): SeededTableScanner
    {
        return new SeededTableScanner(new AstParser);
    }

    public function test_returns_null_when_no_seeders_directory(): void
    {
        $basePath = $this->createTempDirectory(['composer.json' => '{}']);

        $this->assertNull($this->scanner()->catalogueTables($basePath));
    }

    public function test_detects_table_seeded_via_model_update_or_create(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Plan;

class PlanSeeder
{
    public function run(): void
    {
        Plan::updateOrCreate(['tier' => 'free'], ['amount' => 0]);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/PlanSeeder.php' => $seeder,
        ]);

        $this->assertContains('plans', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_detects_table_seeded_via_db_table_insert(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Support\Facades\DB;

class PillarSeeder
{
    public function run(): void
    {
        DB::table('pillars')->insert([
            ['name' => 'Strategy'],
            ['name' => 'Finance'],
        ]);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/PillarSeeder.php' => $seeder,
        ]);

        $this->assertContains('pillars', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_factory_seeded_table_is_not_a_catalogue(): void
    {
        // Factories generate volume, not a fixed catalogue — must not be treated as one.
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\User;

class UserSeeder
{
    public function run(): void
    {
        User::factory()->count(50)->create();
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/UserSeeder.php' => $seeder,
        ]);

        $this->assertNotContains('users', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_table_seeded_both_literally_and_via_factory_is_excluded(): void
    {
        // A table that is also factory-seeded somewhere grows with volume → not a catalogue.
        $literal = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Tag;

class TagSeeder
{
    public function run(): void
    {
        Tag::create(['name' => 'urgent']);
    }
}
PHP;

        $factory = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Tag;

class TagVolumeSeeder
{
    public function run(): void
    {
        Tag::factory()->count(1000)->create();
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/TagSeeder.php' => $literal,
            'database/seeders/TagVolumeSeeder.php' => $factory,
        ]);

        $this->assertNotContains('tags', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_respects_explicit_table_override_when_resolving_model(): void
    {
        $model = <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BusinessStage extends Model
{
    protected $table = 'business_stages';
}
PHP;

        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\BusinessStage;

class BusinessStageSeeder
{
    public function run(): void
    {
        BusinessStage::firstOrCreate(['name' => 'Seed']);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'app/Models/BusinessStage.php' => $model,
            'database/seeders/BusinessStageSeeder.php' => $seeder,
        ]);

        $this->assertContains('business_stages', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_caches_catalogue_per_base_path(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Plan;

class PlanSeeder
{
    public function run(): void
    {
        Plan::create(['tier' => 'free']);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/PlanSeeder.php' => $seeder,
        ]);

        $scanner = $this->scanner();
        $first = $scanner->catalogueTables($basePath);

        // A second call for the same base path returns the cached result.
        $this->assertSame($first, $scanner->catalogueTables($basePath));
    }

    public function test_skips_non_php_files_in_seeders_directory(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use App\Models\Plan;

class PlanSeeder
{
    public function run(): void
    {
        Plan::create(['tier' => 'free']);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/PlanSeeder.php' => $seeder,
            'database/seeders/notes.txt' => 'not php',
        ]);

        // The .txt file is skipped; the real seeder is still scanned.
        $this->assertContains('plans', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_empty_seeder_file_is_skipped(): void
    {
        $basePath = $this->createTempDirectory([
            'database/seeders/EmptySeeder.php' => '<?php',
        ]);

        // A file that parses to an empty AST contributes nothing; the directory still
        // exists, so the result is an empty catalogue rather than null.
        $this->assertSame([], $this->scanner()->catalogueTables($basePath));
    }

    public function test_resolves_db_table_through_a_chained_builder_write(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

use Illuminate\Support\Facades\DB;

class WidgetSeeder
{
    public function run(): void
    {
        DB::table('widgets')->where('active', true)->insert([
            ['name' => 'A'],
        ]);
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/WidgetSeeder.php' => $seeder,
        ]);

        // The DB::table root is reached by walking past the intermediate ->where() call.
        $this->assertContains('widgets', $this->scanner()->catalogueTables($basePath) ?? []);
    }

    public function test_builder_write_not_rooted_in_db_table_is_ignored(): void
    {
        $seeder = <<<'PHP'
<?php

namespace Database\Seeders;

class CustomSeeder
{
    public function run(): void
    {
        $builder = $this->builder();
        $builder->insert([['name' => 'A']]);
    }

    private function builder()
    {
        return null;
    }
}
PHP;

        $basePath = $this->createTempDirectory([
            'database/seeders/CustomSeeder.php' => $seeder,
        ]);

        // $builder->insert(...) has no statically-resolvable DB::table('x') root, so it
        // registers no catalogue table.
        $this->assertSame([], $this->scanner()->catalogueTables($basePath));
    }
}
