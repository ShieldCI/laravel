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
}
